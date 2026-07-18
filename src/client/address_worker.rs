//! Production **Retiring** / reconnect-vs-exit policy for one **Server address** worker.
//!
//! The **Address controller** owns worker slots and maintenance intent. This module owns
//! the Connected-tunnel policy every production factory must follow: Retire cancels
//! Establishing / Reconnecting work immediately, leaves a live Connected tunnel until
//! remote close or process **Infrastructure drain**, re-adopts without a duplicate dial,
//! and observes connect/disconnect for **Assignment convergence**.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;

use super::address_controller::{AddressWorkerControl, MaintenanceIntent};
use crate::ServerAddress;
use crate::reconnect_policy::ReconnectPolicy;
use crate::shutdown::ShutdownMode;
use rand::RngCore;

/// Runs a Connected tunnel until process shutdown or remote close.
pub type ConnectedTunnelRun = Box<
    dyn FnOnce(BoxFuture<'static, ShutdownMode>) -> BoxFuture<'static, Result<(), String>> + Send,
>;

/// Runs a Connected tunnel and preserves its typed operator-reporting context until the
/// Address worker chooses the retry delay.
pub type ReportedConnectedTunnelRun = Box<
    dyn FnOnce(
            BoxFuture<'static, ShutdownMode>,
        ) -> BoxFuture<'static, Result<(), ConnectedTunnelFailure>>
        + Send,
>;

/// A retryable failure plus optional operator reporting that needs the chosen delay.
pub struct ConnectedTunnelFailure {
    message: String,
    delay_reporter: Box<dyn FnOnce(u64) + Send>,
}

impl ConnectedTunnelFailure {
    pub fn with_delay_reporter(
        message: String,
        delay_reporter: impl FnOnce(u64) + Send + 'static,
    ) -> Self {
        Self {
            message,
            delay_reporter: Box::new(delay_reporter),
        }
    }
}

/// Result of one establish attempt under the production address-worker policy.
pub enum EstablishOutcome {
    /// Tunnel is Connected. `run` must stay live until remote close or the provided
    /// process-shutdown future completes — never solely because maintenance became Retire.
    Connected {
        configured_server_addr: String,
        run: ConnectedTunnelRun,
    },
    /// Tunnel is Connected and needs classified operator reporting if its session ends.
    ConnectedWithRetryReporter {
        configured_server_addr: String,
        run: ReportedConnectedTunnelRun,
    },
    /// Transient failure; lifecycle backs off and retries unless Retire/shutdown.
    ///
    /// `log_with_delay` receives the lifecycle's chosen backoff display seconds so dial
    /// adapters can emit operator logs with the real retry delay.
    Retryable {
        message: String,
        log_with_delay: Option<Box<dyn FnOnce(u64) + Send>>,
    },
    /// Fatal failure; lifecycle returns `Err`.
    Fatal { message: String },
}

/// Dial / connect adapter for [`run_address_worker`].
///
/// Production wires DNS + QUIC connect; tests supply in-memory Connected sessions so
/// Retiring correctness exercises the same policy path as production.
pub trait AddressWorkerDial: Send + Sync {
    fn establish(&self, address: ServerAddress) -> BoxFuture<'static, EstablishOutcome>;
}

/// Backoff between dial / reconnect attempts.
pub trait AddressWorkerBackoff: Send {
    fn next_delay(&mut self) -> Duration;
    fn reset_after_connected(&mut self);
}

impl<R: RngCore + Send> AddressWorkerBackoff for ReconnectPolicy<R> {
    fn next_delay(&mut self) -> Duration {
        self.next_retry().delay
    }

    fn reset_after_connected(&mut self) {
        self.reset();
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
pub async fn run_address_worker<D, H, B>(
    address: ServerAddress,
    control: AddressWorkerControl,
    dial: Arc<D>,
    hooks: Arc<H>,
    mut backoff: B,
) -> Result<(), String>
where
    D: AddressWorkerDial + ?Sized,
    H: AddressWorkerHooks + ?Sized,
    B: AddressWorkerBackoff,
{
    let mut connected_once = false;
    let mut maintenance = control.subscribe_maintenance();
    loop {
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            // Establishing / reconnecting work stops on remove. Connected workers reach
            // this check only after their tunnel run ends (Retire does not locally close).
            return Ok(());
        }

        let outcome = tokio::select! {
            _ = wait_for_shutdown(&control) => return Ok(()),
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

        let (configured_server_addr, run, reported_run) = match outcome {
            EstablishOutcome::Connected {
                configured_server_addr,
                run,
            } => (configured_server_addr, Some(run), None),
            EstablishOutcome::ConnectedWithRetryReporter {
                configured_server_addr,
                run,
            } => (configured_server_addr, None, Some(run)),
            EstablishOutcome::Retryable {
                message,
                log_with_delay,
            } => {
                let delay = backoff.next_delay();
                let delay_secs = display_delay_secs(delay);
                if let Some(log) = log_with_delay {
                    log(delay_secs);
                } else {
                    hooks.on_retryable_failure(&message, delay_secs);
                }
                if wait_for_retry_delay(delay, &control).await {
                    continue;
                }
                return Ok(());
            }
            EstablishOutcome::Fatal { message } => return Err(message),
        };

        let first_connection = !connected_once;
        let retiring = control.maintenance_intent() == MaintenanceIntent::Retire;
        if !retiring {
            backoff.reset_after_connected();
        }
        connected_once = true;
        if first_connection && control.claim_client_ready_log() {
            hooks.on_client_ready(&configured_server_addr);
        }
        if let Some(status) = control.observe_connected(&address) {
            crate::runtime_log::client_assignment_convergence(status);
        }

        let process_shutdown = Box::pin({
            let control = control.clone();
            let configured_server_addr = configured_server_addr.clone();
            async move {
                wait_for_process_shutdown_observing_retire(&control, &configured_server_addr).await;
                ShutdownMode::Graceful
            }
        });
        let (run_result, retry_reporter) = if let Some(run) = run {
            (run(process_shutdown).await, None)
        } else if let Some(run) = reported_run {
            match run(process_shutdown).await {
                Ok(()) => (Ok(()), None),
                Err(failure) => (Err(failure.message), Some(failure.delay_reporter)),
            }
        } else {
            unreachable!("Connected outcome always has one run adapter")
        };

        if let Some(status) = control.observe_disconnected(&address) {
            crate::runtime_log::client_assignment_convergence(status);
        }

        // Retiring connections stay live until remote close or process shutdown, then exit
        // without reconnecting. Maintained connections reconnect after unexpected closes.
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            return Ok(());
        }

        match run_result {
            Ok(()) => return Ok(()),
            Err(error) => {
                let delay = backoff.next_delay();
                let delay_secs = display_delay_secs(delay);
                if let Some(report) = retry_reporter {
                    report(delay_secs);
                } else {
                    hooks.on_session_ended(Some(&error), delay_secs);
                }
                if wait_for_retry_delay(delay, &control).await {
                    continue;
                }
                return Ok(());
            }
        }
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

/// Wait for process shutdown while observing Retire without closing the live tunnel.
pub(crate) async fn wait_for_process_shutdown_observing_retire(
    control: &AddressWorkerControl,
    configured_server_addr: &str,
) {
    let mut maintenance = control.subscribe_maintenance();
    let mut shutdown = control.subscribe_shutdown();
    let mut logged_retiring = false;
    if control.maintenance_intent() == MaintenanceIntent::Retire {
        crate::runtime_log::client_tunnel_retiring(configured_server_addr);
        logged_retiring = true;
    }
    if control.shutdown_requested() {
        return;
    }
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || control.shutdown_requested() {
                    return;
                }
            }
            changed = maintenance.changed() => {
                if changed.is_err() {
                    return;
                }
                if !logged_retiring
                    && control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    crate::runtime_log::client_tunnel_retiring(configured_server_addr);
                    logged_retiring = true;
                }
            }
        }
    }
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
pub fn connected_session_until(
    configured_server_addr: String,
    remote_close: Pin<Box<dyn Future<Output = ()> + Send>>,
) -> EstablishOutcome {
    EstablishOutcome::Connected {
        configured_server_addr,
        run: Box::new(move |process_shutdown| {
            Box::pin(async move {
                tokio::select! {
                    _ = process_shutdown => Ok(()),
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
            reported_delay_secs: Arc<AtomicUsize>,
        }

        impl AddressWorkerDial for DisconnectingDial {
            fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, EstablishOutcome> {
                let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
                let reported_delay_secs = Arc::clone(&self.reported_delay_secs);
                Box::pin(async move {
                    if attempt > 0 {
                        return std::future::pending::<EstablishOutcome>().await;
                    }
                    EstablishOutcome::ConnectedWithRetryReporter {
                        configured_server_addr: "a.example.test:443".to_owned(),
                        run: Box::new(move |_process_shutdown| {
                            Box::pin(async move {
                                Err(ConnectedTunnelFailure::with_delay_reporter(
                                    "connection ended".to_owned(),
                                    move |delay_secs| {
                                        reported_delay_secs
                                            .store(delay_secs as usize, Ordering::SeqCst);
                                    },
                                ))
                            })
                        }),
                    }
                })
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let reported_delay_secs = Arc::new(AtomicUsize::new(0));
        let dial = Arc::new(DisconnectingDial {
            attempts: Arc::clone(&attempts),
            reported_delay_secs: Arc::clone(&reported_delay_secs),
        });
        let factory: crate::AddressWorkerFactory = Arc::new(move |address, control| {
            let dial = Arc::clone(&dial);
            Box::pin(async move {
                run_address_worker(
                    address,
                    control,
                    dial,
                    Arc::new(SilentAddressWorkerHooks),
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
        fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, EstablishOutcome> {
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
            fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, EstablishOutcome> {
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
            fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, EstablishOutcome> {
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
            fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, EstablishOutcome> {
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
