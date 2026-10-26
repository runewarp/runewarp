//! Production **Retiring** / reconnect-vs-exit policy for one **Server address** worker.
//!
//! The **Address controller** owns worker slots and maintenance intent. This module owns
//! the Connected-tunnel policy every production factory must follow: Retire cancels
//! Establishing / Reconnecting work immediately, leaves a live Connected tunnel until
//! remote close or process **Infrastructure drain**, re-adopts without a duplicate dial,
//! and observes connect/disconnect for **Assignment convergence**.
//!
//! While a primary connection is live, the worker also owns at most one **Candidate Tunnel
//! connection** for its address. A replacement hint on the primary starts a candidate after a
//! jittered delay; the candidate must reach the hinted generation before it offers credit. Once
//! it does, it becomes the primary and the old connection retires through placement withdrawal.
//! Candidates never count toward convergence or readiness and never carry Visitors before
//! promotion.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;

use super::address_controller::{AddressWorkerControl, MaintenanceIntent};
use super::tunnel_attempt::{
    TunnelAttemptFailure, TunnelAttemptOutcome, TunnelConnectionControl, TunnelConnectionEnd,
    TunnelConnectionRun,
};
use crate::ServerAddress;
use crate::reconnect_policy::ReconnectPolicy;
use crate::tunnel::{ReplacementHint, ServerRuntimeGeneration};
use rand::{RngCore, SeedableRng};

/// Dial / connect adapter for [`run_address_worker`].
///
/// Production wires DNS + QUIC connect; tests supply in-memory Connected sessions so
/// Retiring correctness exercises the same policy path as production.
pub trait AddressWorkerDial: Send + Sync {
    fn establish(&self, address: ServerAddress) -> BoxFuture<'static, TunnelAttemptOutcome>;

    /// Open a candidate connection on a fresh socket that must reach `expected_generation`
    /// before it offers Visitor credit.
    ///
    /// A wrong generation is a retryable failure. Dials without candidate support fail every
    /// candidate, which leaves the primary untouched.
    fn establish_candidate(
        &self,
        _address: ServerAddress,
        _expected_generation: ServerRuntimeGeneration,
    ) -> BoxFuture<'static, TunnelAttemptOutcome> {
        Box::pin(async {
            TunnelAttemptOutcome::Retryable(TunnelAttemptFailure::unclassified(
                "candidate attempts are unsupported",
            ))
        })
    }
}

/// Backoff between dial / reconnect attempts.
pub trait AddressWorkerBackoff: Send {
    fn next_delay(&mut self) -> Duration;
    fn reset_after_connected(&mut self);
    /// A fresh, independent sequence of the same kind, used for candidate retries.
    fn fresh(&self) -> Self
    where
        Self: Sized;
}

impl<R: RngCore + SeedableRng + Send> AddressWorkerBackoff for ReconnectPolicy<R> {
    fn next_delay(&mut self) -> Duration {
        self.next_retry().delay
    }

    fn reset_after_connected(&mut self) {
        self.reset();
    }

    fn fresh(&self) -> Self {
        Self::new_with_rng(R::from_os_rng())
    }
}

/// Fixed delay for deterministic Retiring / cancel tests.
#[derive(Clone, Copy, Debug)]
pub struct FixedBackoff(pub Duration);

impl AddressWorkerBackoff for FixedBackoff {
    fn next_delay(&mut self) -> Duration {
        self.0
    }

    fn reset_after_connected(&mut self) {}

    fn fresh(&self) -> Self {
        *self
    }
}

/// Optional hooks for runtime logging around lifecycle transitions.
pub trait AddressWorkerHooks: Send + Sync {
    fn on_client_ready(&self, _configured_server_addr: &str) {}
    fn on_retryable_failure(&self, _message: &str, _retry_delay_secs: u64) {}
    fn on_session_ended(&self, _error: Option<&str>, _retry_delay_secs: u64) {}
}

/// No-op hooks for tests and callers that log inside their dial adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SilentAddressWorkerHooks;

impl AddressWorkerHooks for SilentAddressWorkerHooks {}

/// Drive one address worker with production Retiring / reconnect-vs-exit policy.
///
/// Returns only after every connection it retired has finished its withdrawal, so process
/// shutdown waits for them like any other connection.
pub async fn run_address_worker<D, H, B>(
    address: ServerAddress,
    control: AddressWorkerControl,
    dial: Arc<D>,
    hooks: Arc<H>,
    backoff: B,
) -> Result<(), String>
where
    D: AddressWorkerDial + ?Sized,
    H: AddressWorkerHooks + ?Sized,
    B: AddressWorkerBackoff,
{
    let mut retiring = JoinSet::new();
    let result = maintain_address(address, &control, dial, hooks, backoff, &mut retiring).await;
    // Each retired connection ends by its own deadline, shutdown, or remote close.
    while retiring.join_next().await.is_some() {}
    result
}

async fn maintain_address<D, H, B>(
    address: ServerAddress,
    control: &AddressWorkerControl,
    dial: Arc<D>,
    hooks: Arc<H>,
    mut backoff: B,
    retiring: &mut JoinSet<()>,
) -> Result<(), String>
where
    D: AddressWorkerDial + ?Sized,
    H: AddressWorkerHooks + ?Sized,
    B: AddressWorkerBackoff,
{
    let mut connected_once = false;
    let mut maintenance = control.subscribe_maintenance();
    let mut candidate_backoff = backoff.fresh();
    loop {
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            // Establishing / reconnecting work stops on remove. Connected workers reach
            // this check only after their tunnel run ends (Retire does not locally close).
            return Ok(());
        }

        let outcome = tokio::select! {
            _ = wait_for_shutdown(control) => return Ok(()),
            changed = maintenance.changed() => {
                if changed.is_err()
                    || control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    return Ok(());
                }
                continue;
            }
            outcome = dial.establish(address.clone()) => outcome,
        };

        if control.maintenance_intent() == MaintenanceIntent::Retire {
            return Ok(());
        }

        let (configured_server_addr, run, hints) = match outcome {
            TunnelAttemptOutcome::Connected {
                configured_server_addr,
                run,
                hints,
            } => (configured_server_addr, run, hints),
            TunnelAttemptOutcome::Retryable(failure) => {
                let delay = backoff.next_delay();
                let delay_secs = display_delay_secs(delay);
                if let Some(message) = failure.unclassified_message() {
                    hooks.on_retryable_failure(message, delay_secs);
                } else {
                    failure.report_after_retry_delay(delay_secs);
                }
                if wait_for_retry_delay(delay, control).await {
                    continue;
                }
                return Ok(());
            }
            TunnelAttemptOutcome::FatalLocalMaterial(message) => return Err(message),
        };

        let first_connection = !connected_once;
        let retiring_intent = control.maintenance_intent() == MaintenanceIntent::Retire;
        if !retiring_intent {
            backoff.reset_after_connected();
        }
        connected_once = true;
        if first_connection && control.claim_client_ready_log() {
            hooks.on_client_ready(&configured_server_addr);
        }
        if let Some(status) = control.observe_connected(&address) {
            crate::runtime_log::client_assignment_convergence(status);
        }

        // The run observes process shutdown through the shared Client-instance mode and
        // deadline. Candidates and Retire logging continue alongside it until it ends.
        let run_result = ConnectedAddress {
            address: &address,
            configured_server_addr: &configured_server_addr,
            control,
            dial: dial.as_ref(),
            candidate_backoff: &mut candidate_backoff,
            retiring,
        }
        .run(run, hints)
        .await;

        if let Some(status) = control.observe_disconnected(&address) {
            crate::runtime_log::client_assignment_convergence(status);
        }

        // A withdrawal protocol failure fails the process after every worker finishes draining.
        if let Err(end) = &run_result
            && let Some(message) = end.withdrawal_protocol_failure_message()
        {
            return Err(message.to_owned());
        }

        // Retiring connections stay live until remote close or process shutdown, then exit
        // without reconnecting. Maintained connections reconnect after unexpected closes.
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            return Ok(());
        }

        match run_result {
            Ok(()) => return Ok(()),
            Err(end) => {
                let delay = backoff.next_delay();
                let delay_secs = display_delay_secs(delay);
                if let Some(message) = end.unclassified_message() {
                    hooks.on_session_ended(Some(message), delay_secs);
                } else {
                    end.report_after_retry_delay(delay_secs);
                }
                if wait_for_retry_delay(delay, control).await {
                    continue;
                }
                return Ok(());
            }
        }
    }
}

type ConnectionRunFuture = Pin<Box<dyn Future<Output = Result<(), TunnelConnectionEnd>> + Send>>;

/// The primary connection of a Connected address: its run, retirement trigger and hints.
struct Primary {
    run: ConnectionRunFuture,
    retire: Option<oneshot::Sender<tokio::time::Instant>>,
    hints: watch::Receiver<ReplacementHint>,
    /// False once the hint sender dropped, as after GOAWAY: the last hint stands.
    hints_live: bool,
    interruptions: u64,
}

impl Primary {
    fn start(
        run: TunnelConnectionRun,
        hints: watch::Receiver<ReplacementHint>,
        shutdown: crate::OrderlyShutdown,
    ) -> Self {
        let (retire, retirement) = oneshot::channel();
        let interruptions = hints.borrow().interruptions;
        Self {
            run: run(TunnelConnectionControl::new(shutdown, retirement)),
            retire: Some(retire),
            hints,
            hints_live: true,
            interruptions,
        }
    }

    fn hinted_generation(&self) -> Option<ServerRuntimeGeneration> {
        self.hints.borrow().generation
    }
}

/// Candidate lifecycle for one address: at most one candidate at a time.
enum Candidate {
    Idle,
    /// Waiting out the jittered delay before the next attempt toward `target`.
    Waiting {
        target: ServerRuntimeGeneration,
        delay: Pin<Box<tokio::time::Sleep>>,
        /// Whether an attempt toward `target` has already started and been logged.
        started: bool,
    },
    /// An attempt toward `target` is in flight.
    Warming {
        target: ServerRuntimeGeneration,
        attempt: BoxFuture<'static, TunnelAttemptOutcome>,
    },
}

enum CandidateEvent {
    DelayElapsed,
    Attempted(TunnelAttemptOutcome),
}

impl Candidate {
    /// Wait for the pending delay or attempt; pending forever while idle.
    async fn progress(&mut self) -> CandidateEvent {
        match self {
            Self::Idle => std::future::pending().await,
            Self::Waiting { delay, .. } => {
                delay.as_mut().await;
                CandidateEvent::DelayElapsed
            }
            Self::Warming { attempt, .. } => CandidateEvent::Attempted(attempt.await),
        }
    }

    fn target(&self) -> Option<ServerRuntimeGeneration> {
        match self {
            Self::Idle => None,
            Self::Waiting { target, .. } | Self::Warming { target, .. } => Some(*target),
        }
    }

    /// Drop any candidate work. An unpromoted candidate holds no credit and carried no Visitor,
    /// so closing it affects no traffic.
    fn abort(&mut self, configured_server_addr: &str, reason: &str) {
        let started = match self {
            Self::Idle => false,
            Self::Waiting { started, .. } => *started,
            Self::Warming { .. } => true,
        };
        *self = Self::Idle;
        if started {
            crate::runtime_log::client_tunnel_candidate_aborted(configured_server_addr, reason);
        }
    }
}

/// One Connected stretch of an address worker: the primary run plus candidate work.
struct ConnectedAddress<'a, D: ?Sized, B> {
    address: &'a ServerAddress,
    configured_server_addr: &'a str,
    control: &'a AddressWorkerControl,
    dial: &'a D,
    candidate_backoff: &'a mut B,
    retiring: &'a mut JoinSet<()>,
}

impl<D, B> ConnectedAddress<'_, D, B>
where
    D: AddressWorkerDial + ?Sized,
    B: AddressWorkerBackoff,
{
    /// Run until the current primary ends, returning how it ended. Promotions replace the
    /// primary without ending the stretch; retired connections continue on `retiring`.
    async fn run(
        mut self,
        run: TunnelConnectionRun,
        hints: watch::Receiver<ReplacementHint>,
    ) -> Result<(), TunnelConnectionEnd> {
        let shutdown = self.control.orderly_shutdown();
        let mut primary = Primary::start(run, hints, shutdown.clone());
        let mut candidate = Candidate::Idle;
        let mut maintenance = self.control.subscribe_maintenance();
        let mut maintenance_live = true;
        let mut shutdown_started = shutdown.mode().is_some();
        let mut logged_retiring = false;
        if self.control.maintenance_intent() == MaintenanceIntent::Retire {
            crate::runtime_log::client_tunnel_retiring(self.configured_server_addr);
            logged_retiring = true;
        }
        self.reconcile(
            &mut candidate,
            primary.hinted_generation(),
            shutdown_started,
        );

        loop {
            let is_active = !matches!(candidate, Candidate::Idle);
            tokio::select! {
                result = &mut primary.run => {
                    // Primary loss has one recovery path: the ordinary reconnect.
                    candidate.abort(self.configured_server_addr, "primary-lost");
                    return result;
                }
                _ = shutdown.wait_started(), if !shutdown_started => {
                    shutdown_started = true;
                    candidate.abort(self.configured_server_addr, "shutdown");
                }
                changed = maintenance.changed(), if maintenance_live => {
                    if changed.is_err() {
                        maintenance_live = false;
                        continue;
                    }
                    if self.control.maintenance_intent() == MaintenanceIntent::Retire {
                        if !logged_retiring {
                            crate::runtime_log::client_tunnel_retiring(self.configured_server_addr);
                            logged_retiring = true;
                        }
                        candidate.abort(self.configured_server_addr, "retiring");
                    } else {
                        // Re-adopted: the standing hint may start a candidate again.
                        logged_retiring = false;
                        self.reconcile(&mut candidate, primary.hinted_generation(), shutdown_started);
                    }
                }
                changed = primary.hints.changed(), if primary.hints_live => {
                    if changed.is_err() {
                        primary.hints_live = false;
                        continue;
                    }
                    let hint = *primary.hints.borrow_and_update();
                    if hint.interruptions != primary.interruptions {
                        // Pause replacement; the resubscribed snapshot decides whether it restarts.
                        primary.interruptions = hint.interruptions;
                        candidate.abort(self.configured_server_addr, "subscription-interrupted");
                    }
                    self.reconcile(&mut candidate, hint.generation, shutdown_started);
                }
                event = candidate.progress(), if is_active => match event {
                    CandidateEvent::DelayElapsed => {
                        if let Some(target) = candidate.target() {
                            crate::runtime_log::client_tunnel_candidate_starting(
                                self.configured_server_addr,
                                &target.to_string(),
                            );
                            candidate = Candidate::Warming {
                                target,
                                attempt: self.dial.establish_candidate(self.address.clone(), target),
                            };
                        }
                    }
                    CandidateEvent::Attempted(outcome) => {
                        self.settle(&mut primary, &mut candidate, outcome, &shutdown, shutdown_started);
                    }
                },
            }
        }
    }

    /// Promote a validated candidate, or schedule its retry after a failure.
    fn settle(
        &mut self,
        primary: &mut Primary,
        candidate: &mut Candidate,
        outcome: TunnelAttemptOutcome,
        shutdown: &crate::OrderlyShutdown,
        shutdown_started: bool,
    ) {
        let Some(target) = candidate.target() else {
            return;
        };
        *candidate = Candidate::Idle;
        let message = match outcome {
            TunnelAttemptOutcome::Connected { run, hints, .. } => {
                // Retire or shutdown may race the attempt's completion; then the candidate is
                // dropped unpromoted, which closes it and returns any credit it reserved.
                if self.allows_candidates(shutdown_started) {
                    self.promote(primary, run, hints, shutdown, target);
                    self.reconcile(candidate, primary.hinted_generation(), shutdown_started);
                }
                return;
            }
            TunnelAttemptOutcome::Retryable(failure) => {
                let delay = self.candidate_backoff.next_delay();
                let delay_secs = display_delay_secs(delay);
                match failure.unclassified_message() {
                    Some(message) => crate::runtime_log::client_tunnel_candidate_failed(
                        self.configured_server_addr,
                        delay_secs,
                        message,
                    ),
                    None => failure.report_candidate_after_retry_delay(
                        self.configured_server_addr,
                        delay_secs,
                    ),
                }
                *candidate = waiting(target, delay, true);
                return;
            }
            // Local material also fails the next primary reconnect, which owns the fatal exit.
            // A candidate only retries.
            TunnelAttemptOutcome::FatalLocalMaterial(message) => message,
        };
        let delay = self.candidate_backoff.next_delay();
        crate::runtime_log::client_tunnel_candidate_failed(
            self.configured_server_addr,
            display_delay_secs(delay),
            &message,
        );
        *candidate = waiting(target, delay, true);
    }

    fn allows_candidates(&self, shutdown_started: bool) -> bool {
        !shutdown_started
            && !self.control.shutdown_requested()
            && self.control.maintenance_intent() == MaintenanceIntent::Maintain
    }

    /// Make the candidate follow `hint`: none, the same target (a no-op), or a new target.
    fn reconcile(
        &mut self,
        candidate: &mut Candidate,
        hint: Option<ServerRuntimeGeneration>,
        shutdown_started: bool,
    ) {
        let allowed = self.allows_candidates(shutdown_started);
        match (candidate.target(), hint.filter(|_| allowed)) {
            (None, None) => {}
            (Some(_), None) => candidate.abort(self.configured_server_addr, "hint-withdrawn"),
            (Some(current), Some(hint)) if current == hint => {}
            (current, Some(hint)) => {
                if current.is_some() {
                    candidate.abort(self.configured_server_addr, "hint-changed");
                }
                // A new hint restarts the retry sequence from its first jittered window.
                self.candidate_backoff.reset_after_connected();
                *candidate = waiting(hint, self.candidate_backoff.next_delay(), false);
            }
        }
    }

    /// Make the validated candidate the primary, then retire the old connection.
    fn promote(
        &mut self,
        primary: &mut Primary,
        run: TunnelConnectionRun,
        hints: watch::Receiver<ReplacementHint>,
        shutdown: &crate::OrderlyShutdown,
        generation: ServerRuntimeGeneration,
    ) {
        crate::runtime_log::client_tunnel_candidate_promoted(
            self.configured_server_addr,
            &generation.to_string(),
        );
        let old = std::mem::replace(primary, Primary::start(run, hints, shutdown.clone()));
        self.candidate_backoff.reset_after_connected();
        let deadline = tokio::time::Instant::now() + shutdown.graceful_shutdown_duration();
        if let Some(retire) = old.retire {
            let _ = retire.send(deadline);
        }
        let old_run = old.run;
        self.retiring.spawn(async move {
            // The run reports its own retirement outcome; none of them ends the process.
            let _ = old_run.await;
        });
    }
}

fn waiting(target: ServerRuntimeGeneration, delay: Duration, started: bool) -> Candidate {
    Candidate::Waiting {
        target,
        delay: Box::pin(tokio::time::sleep(delay)),
        started,
    }
}

/// Production helper: [`run_address_worker`] with [`ReconnectPolicy`] backoff.
pub async fn run_address_worker_with_reconnect_policy<D, H>(
    address: ServerAddress,
    control: AddressWorkerControl,
    dial: Arc<D>,
    hooks: Arc<H>,
) -> Result<(), String>
where
    D: AddressWorkerDial + ?Sized,
    H: AddressWorkerHooks + ?Sized,
{
    run_address_worker(address, control, dial, hooks, ReconnectPolicy::new()).await
}

/// Returns true when the worker should continue retrying after the delay.
pub async fn wait_for_retry_delay(delay: Duration, control: &AddressWorkerControl) -> bool {
    let mut maintenance = control.subscribe_maintenance();
    tokio::select! {
        _ = wait_for_shutdown(control) => false,
        changed = maintenance.changed() => {
            if changed.is_err() {
                return false;
            }
            !control.shutdown_requested()
                && control.maintenance_intent() != MaintenanceIntent::Retire
        }
        _ = tokio::time::sleep(delay) => {
            !control.shutdown_requested()
                && control.maintenance_intent() != MaintenanceIntent::Retire
        }
    }
}

pub async fn wait_for_shutdown(control: &AddressWorkerControl) {
    let mut shutdown = control.subscribe_shutdown();
    if control.shutdown_requested() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Build an [`AddressWorkerFactory`] that runs the production lifecycle with `dial`.
#[cfg(test)]
pub fn production_address_worker_factory<D, H>(
    dial: Arc<D>,
    hooks: Arc<H>,
) -> super::address_controller::AddressWorkerFactory
where
    D: AddressWorkerDial + 'static,
    H: AddressWorkerHooks + 'static,
{
    Arc::new(move |server_address, control| {
        let dial = Arc::clone(&dial);
        let hooks = Arc::clone(&hooks);
        Box::pin(async move {
            run_address_worker_with_reconnect_policy(server_address, control, dial, hooks).await
        })
    })
}

/// Test helper: Connected session that stays open until `remote_close` or process shutdown.
#[cfg(test)]
pub fn connected_session_until(
    configured_server_addr: String,
    remote_close: Pin<Box<dyn Future<Output = ()> + Send>>,
) -> TunnelAttemptOutcome {
    TunnelAttemptOutcome::Connected {
        configured_server_addr,
        hints: watch::channel(ReplacementHint::default()).1,
        run: Box::new(move |control| {
            Box::pin(async move {
                tokio::select! {
                    _ = control.shutdown().wait_started() => Ok(()),
                    _ = remote_close => Ok(()),
                }
            })
        }),
    }
}

fn display_delay_secs(delay: Duration) -> u64 {
    let rounded = delay.as_nanos().div_ceil(1_000_000_000);
    u64::try_from(rounded.max(1)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod candidate_tests;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;
    use crate::AddressController;
    use crate::AssignmentConvergence;
    use crate::ServerAddress;
    use crate::managed_session::{ClientManagedInput, RoleAdapter};

    #[tokio::test(start_paused = true)]
    async fn connected_session_reports_the_delay_it_actually_awaits() {
        struct DisconnectingDial {
            attempts: Arc<AtomicUsize>,
        }

        impl AddressWorkerDial for DisconnectingDial {
            fn establish(
                &self,
                _address: ServerAddress,
            ) -> BoxFuture<'static, TunnelAttemptOutcome> {
                let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if attempt > 0 {
                        return std::future::pending::<TunnelAttemptOutcome>().await;
                    }
                    TunnelAttemptOutcome::Connected {
                        configured_server_addr: "a.example.test:443".to_owned(),
                        hints: no_hints(),
                        run: Box::new(move |_control| {
                            Box::pin(async move {
                                Err(TunnelConnectionEnd::unclassified("connection ended"))
                            })
                        }),
                    }
                })
            }
        }

        struct DelayHooks(Arc<AtomicUsize>);

        impl AddressWorkerHooks for DelayHooks {
            fn on_session_ended(&self, _error: Option<&str>, retry_delay_secs: u64) {
                self.0.store(retry_delay_secs as usize, Ordering::SeqCst);
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let reported_delay_secs = Arc::new(AtomicUsize::new(0));
        let dial = Arc::new(DisconnectingDial {
            attempts: Arc::clone(&attempts),
        });
        let hook_delay = Arc::clone(&reported_delay_secs);
        let factory: crate::AddressWorkerFactory = Arc::new(move |address, control| {
            let dial = Arc::clone(&dial);
            let reported_delay_secs = Arc::clone(&hook_delay);
            Box::pin(async move {
                run_address_worker(
                    address,
                    control,
                    dial,
                    Arc::new(DelayHooks(Arc::clone(&reported_delay_secs))),
                    FixedBackoff(Duration::from_secs(2)),
                )
                .await
            })
        });
        let mut controller = AddressController::for_static(factory);
        controller.seed_configured([ServerAddress::parse("a.example.test").unwrap()]);
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });

        while reported_delay_secs.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(reported_delay_secs.load(Ordering::SeqCst), 2);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(1_999)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(1)).await;
        while attempts.load(Ordering::SeqCst) == 1 {
            tokio::task::yield_now().await;
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        shutdown.request();
        runtime.await.expect("runtime join").expect("shutdown");
    }

    struct ScriptedDial {
        dial_count: Arc<AtomicUsize>,
        connected_hold: Arc<AtomicBool>,
        remote_close_rx: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl AddressWorkerDial for ScriptedDial {
        fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, TunnelAttemptOutcome> {
            let dial_count = Arc::clone(&self.dial_count);
            let connected_hold = Arc::clone(&self.connected_hold);
            let remote_close = self
                .remote_close_rx
                .lock()
                .expect("remote close mutex")
                .take();
            Box::pin(async move {
                dial_count.fetch_add(1, Ordering::SeqCst);
                let Some(remote_close) = remote_close else {
                    // Subsequent dials after the first Connected session hang until cancelled.
                    std::future::pending::<()>().await;
                    unreachable!()
                };
                connected_hold.store(true, Ordering::SeqCst);
                connected_session_until(
                    "tunnel.example.test:443".to_owned(),
                    Box::pin(async move {
                        let _ = remote_close.await;
                    }),
                )
            })
        }
    }

    async fn apply_addresses(
        adapter: &mut crate::ClientAssignmentAdapter,
        addresses: Vec<ServerAddress>,
    ) {
        adapter
            .apply(ClientManagedInput {
                server_addresses: addresses,
            })
            .await
            .expect("apply ok");
    }

    #[tokio::test]
    async fn retire_while_connected_leaves_tunnel_open_until_remote_close() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let connected_hold = Arc::new(AtomicBool::new(false));
        let (remote_close_tx, remote_close_rx) = oneshot::channel();
        let dial = Arc::new(ScriptedDial {
            dial_count: Arc::clone(&dial_count),
            connected_hold: Arc::clone(&connected_hold),
            remote_close_rx: std::sync::Mutex::new(Some(remote_close_rx)),
        });
        let factory = production_address_worker_factory(dial, Arc::new(SilentAddressWorkerHooks));
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let address = ServerAddress::parse("tunnel.example.test").unwrap();

        let runtime = tokio::spawn(async move { controller.run().await });

        apply_addresses(&mut adapter, vec![address.clone()]).await;
        wait_until(|| connected_hold.load(Ordering::SeqCst)).await;
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Converged
        );
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        // Remove → Retire. Tunnel must stay Connected (no second dial).
        apply_addresses(&mut adapter, Vec::new()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            connected_hold.load(Ordering::SeqCst),
            "Retire must not locally close a Connected tunnel"
        );
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Converged
        );
        assert_eq!(view.worker_count(), 1);

        // Remote close ends the Retiring worker.
        let _ = remote_close_tx.send(());
        wait_until(|| view.worker_count() == 0).await;

        runtime.abort();
    }

    #[tokio::test]
    async fn re_adopt_while_connected_does_not_dial_duplicate() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let connected_hold = Arc::new(AtomicBool::new(false));
        let (_remote_close_tx, remote_close_rx) = oneshot::channel();
        let dial = Arc::new(ScriptedDial {
            dial_count: Arc::clone(&dial_count),
            connected_hold: Arc::clone(&connected_hold),
            remote_close_rx: std::sync::Mutex::new(Some(remote_close_rx)),
        });
        let factory = production_address_worker_factory(dial, Arc::new(SilentAddressWorkerHooks));
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let address = ServerAddress::parse("tunnel.example.test").unwrap();
        let runtime = tokio::spawn(async move { controller.run().await });

        apply_addresses(&mut adapter, vec![address.clone()]).await;
        wait_until(|| connected_hold.load(Ordering::SeqCst)).await;
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        apply_addresses(&mut adapter, Vec::new()).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        apply_addresses(&mut adapter, vec![address.clone()]).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            dial_count.load(Ordering::SeqCst),
            1,
            "re-adopt must not dial a duplicate while Connected"
        );
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Converged
        );
        assert_eq!(view.worker_count(), 1);

        runtime.abort();
    }

    #[tokio::test]
    async fn remove_while_establishing_cancels_unresolved_dial() {
        struct HangingDial {
            started: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }

        struct HangGuard {
            dropped: Arc<AtomicBool>,
        }

        impl Drop for HangGuard {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }

        impl AddressWorkerDial for HangingDial {
            fn establish(
                &self,
                _address: ServerAddress,
            ) -> BoxFuture<'static, TunnelAttemptOutcome> {
                let started = Arc::clone(&self.started);
                let dropped = Arc::clone(&self.dropped);
                Box::pin(async move {
                    started.store(true, Ordering::SeqCst);
                    let _guard = HangGuard { dropped };
                    std::future::pending::<()>().await;
                    unreachable!()
                })
            }
        }

        let started = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let dial = Arc::new(HangingDial {
            started: Arc::clone(&started),
            dropped: Arc::clone(&dropped),
        });
        let factory = production_address_worker_factory(dial, Arc::new(SilentAddressWorkerHooks));
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let address = ServerAddress::parse("tunnel.example.test").unwrap();
        let runtime = tokio::spawn(async move { controller.run().await });

        apply_addresses(&mut adapter, vec![address.clone()]).await;
        wait_until(|| started.load(Ordering::SeqCst)).await;

        apply_addresses(&mut adapter, Vec::new()).await;
        wait_until(|| view.worker_count() == 0).await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "Establishing dial must be cancelled on Retire"
        );

        runtime.abort();
    }

    #[tokio::test]
    async fn static_client_ready_fires_once_through_production_policy() {
        let ready_count = Arc::new(AtomicUsize::new(0));

        struct ReadyHooks {
            ready_count: Arc<AtomicUsize>,
        }

        impl AddressWorkerHooks for ReadyHooks {
            fn on_client_ready(&self, _configured_server_addr: &str) {
                self.ready_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct ImmediateDial;

        impl AddressWorkerDial for ImmediateDial {
            fn establish(
                &self,
                _address: ServerAddress,
            ) -> BoxFuture<'static, TunnelAttemptOutcome> {
                Box::pin(async {
                    connected_session_until(
                        "a.example.test:443".to_owned(),
                        Box::pin(std::future::pending()),
                    )
                })
            }
        }

        let factory = production_address_worker_factory(
            Arc::new(ImmediateDial),
            Arc::new(ReadyHooks {
                ready_count: Arc::clone(&ready_count),
            }),
        );
        let mut controller = AddressController::for_static(factory);
        controller.seed_configured([ServerAddress::parse("a.example.test").unwrap()]);
        wait_until(|| ready_count.load(Ordering::SeqCst) == 1).await;
        assert_eq!(ready_count.load(Ordering::SeqCst), 1);
        controller.request_shutdown();
        controller.run_until_idle().await.unwrap();
    }

    #[tokio::test]
    async fn managed_mode_does_not_emit_static_client_ready() {
        let ready_count = Arc::new(AtomicUsize::new(0));

        struct ReadyHooks {
            ready_count: Arc<AtomicUsize>,
        }

        impl AddressWorkerHooks for ReadyHooks {
            fn on_client_ready(&self, _configured_server_addr: &str) {
                self.ready_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct ImmediateDial {
            connected: Arc<AtomicBool>,
        }

        impl AddressWorkerDial for ImmediateDial {
            fn establish(
                &self,
                _address: ServerAddress,
            ) -> BoxFuture<'static, TunnelAttemptOutcome> {
                let connected = Arc::clone(&self.connected);
                Box::pin(async move {
                    connected.store(true, Ordering::SeqCst);
                    connected_session_until(
                        "a.example.test:443".to_owned(),
                        Box::pin(std::future::pending()),
                    )
                })
            }
        }

        let connected = Arc::new(AtomicBool::new(false));
        let factory = production_address_worker_factory(
            Arc::new(ImmediateDial {
                connected: Arc::clone(&connected),
            }),
            Arc::new(ReadyHooks {
                ready_count: Arc::clone(&ready_count),
            }),
        );
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let runtime = tokio::spawn(async move { controller.run().await });
        apply_addresses(
            &mut adapter,
            vec![ServerAddress::parse("a.example.test").unwrap()],
        )
        .await;
        wait_until(|| connected.load(Ordering::SeqCst)).await;
        assert_eq!(ready_count.load(Ordering::SeqCst), 0);
        runtime.abort();
    }

    #[tokio::test]
    async fn process_shutdown_drains_retiring_connected_tunnel() {
        let dial_count = Arc::new(AtomicUsize::new(0));
        let connected_hold = Arc::new(AtomicBool::new(false));
        let (_remote_close_tx, remote_close_rx) = oneshot::channel();
        let dial = Arc::new(ScriptedDial {
            dial_count: Arc::clone(&dial_count),
            connected_hold: Arc::clone(&connected_hold),
            remote_close_rx: std::sync::Mutex::new(Some(remote_close_rx)),
        });
        let factory = production_address_worker_factory(dial, Arc::new(SilentAddressWorkerHooks));
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let shutdown = controller.shutdown_handle();
        let address = ServerAddress::parse("tunnel.example.test").unwrap();
        let runtime = tokio::spawn(async move { controller.run().await });

        apply_addresses(&mut adapter, vec![address.clone()]).await;
        wait_until(|| connected_hold.load(Ordering::SeqCst)).await;
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);

        // Retire without remote close — tunnel stays Connected.
        apply_addresses(&mut adapter, Vec::new()).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(view.worker_count(), 1);
        assert!(connected_hold.load(Ordering::SeqCst));

        // Infrastructure drain (process shutdown) closes Retiring tunnels; Retire alone does not.
        shutdown.request();
        wait_until(|| view.worker_count() == 0).await;
        runtime
            .await
            .expect("runtime join")
            .expect("shutdown drain");
        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn graceful_shutdown_reaches_every_connection_and_a_protocol_failure_fails_last() {
        use crate::ShutdownMode;

        struct WithdrawingDial {
            connected: Arc<AtomicUsize>,
            /// Whether the sibling's drain was still Graceful after the failure was reported.
            sibling_stayed_graceful: Arc<AtomicBool>,
        }

        impl AddressWorkerDial for WithdrawingDial {
            fn establish(
                &self,
                address: ServerAddress,
            ) -> BoxFuture<'static, TunnelAttemptOutcome> {
                let connected = Arc::clone(&self.connected);
                let sibling_stayed_graceful = Arc::clone(&self.sibling_stayed_graceful);
                let fails = address.hostname().as_str() == "a.example.test";
                Box::pin(async move {
                    connected.fetch_add(1, Ordering::SeqCst);
                    TunnelAttemptOutcome::Connected {
                        configured_server_addr: address.hostname().to_string(),
                        hints: no_hints(),
                        run: Box::new(move |control| {
                            Box::pin(async move {
                                let shutdown = control.shutdown();
                                assert_eq!(shutdown.wait_started().await, ShutdownMode::Graceful);
                                assert!(shutdown.graceful_deadline().is_some());
                                if fails {
                                    return Err(TunnelConnectionEnd::withdrawal_protocol_failure(
                                        "withdrawal failed for a",
                                    ));
                                }
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                sibling_stayed_graceful.store(
                                    shutdown.mode() == Some(ShutdownMode::Graceful),
                                    Ordering::SeqCst,
                                );
                                Ok(())
                            })
                        }),
                    }
                })
            }
        }

        let connected = Arc::new(AtomicUsize::new(0));
        let sibling_stayed_graceful = Arc::new(AtomicBool::new(false));
        let dial = Arc::new(WithdrawingDial {
            connected: Arc::clone(&connected),
            sibling_stayed_graceful: Arc::clone(&sibling_stayed_graceful),
        });
        let factory = production_address_worker_factory(dial, Arc::new(SilentAddressWorkerHooks));
        let mut controller = AddressController::for_static(factory)
            .with_graceful_shutdown_duration(Duration::from_secs(60));
        controller.seed_configured([
            ServerAddress::parse("a.example.test").unwrap(),
            ServerAddress::parse("b.example.test").unwrap(),
        ]);
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });
        wait_until(|| connected.load(Ordering::SeqCst) == 2).await;

        shutdown.begin(ShutdownMode::Graceful);
        let result = tokio::time::timeout(Duration::from_secs(2), runtime)
            .await
            .expect("runtime finishes")
            .expect("runtime join");
        assert_eq!(result, Err("withdrawal failed for a".to_owned()));
        assert!(
            sibling_stayed_graceful.load(Ordering::SeqCst),
            "a failed sibling must not escalate another drain to Fast"
        );
    }

    fn no_hints() -> watch::Receiver<ReplacementHint> {
        watch::channel(ReplacementHint::default()).1
    }

    async fn wait_until(predicate: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not met before timeout");
    }
}
