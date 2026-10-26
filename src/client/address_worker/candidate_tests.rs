//! Candidate lifecycle of one address worker against a scripted dial.
//!
//! Time is paused, so the fixed candidate delay is observable from attempt timestamps.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::Notify;
use tokio::time::Instant;

use super::*;
use crate::managed_session::{ClientManagedInput, RoleAdapter};
use crate::{AddressController, AssignmentConvergence, ShutdownMode};

const CANDIDATE_DELAY: Duration = Duration::from_secs(1);
const GRACEFUL: Duration = Duration::from_secs(30);

fn generation() -> ServerRuntimeGeneration {
    ServerRuntimeGeneration::generate()
}

fn hint(generation: Option<ServerRuntimeGeneration>, interruptions: u64) -> ReplacementHint {
    ReplacementHint {
        generation,
        interruptions,
        paused: false,
    }
}

/// One scripted Tunnel connection: tests drive its hints and remote close and observe how the
/// worker treated it.
struct FakeConnection {
    hints: Mutex<Option<watch::Sender<ReplacementHint>>>,
    remote_close: Notify,
    /// Whether the worker started the run, which is when a real candidate offers credit.
    started: AtomicBool,
    shutdown_seen: AtomicBool,
    ended: AtomicBool,
    /// Report a withdrawal protocol failure when shutdown withdraws this connection.
    fail_withdrawal: AtomicBool,
}

impl FakeConnection {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            hints: Mutex::new(Some(watch::Sender::new(ReplacementHint::default()))),
            remote_close: Notify::new(),
            started: AtomicBool::new(false),
            shutdown_seen: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            fail_withdrawal: AtomicBool::new(false),
        })
    }

    fn set_hint(&self, hint: ReplacementHint) {
        if let Some(sender) = self.hints.lock().unwrap().as_ref() {
            sender.send_replace(hint);
        }
    }

    /// Drop the hint sender, as the Client does after GOAWAY.
    fn stop_hints(&self) {
        self.hints.lock().unwrap().take();
    }

    fn close(&self) {
        self.remote_close.notify_one();
    }

    fn started(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }

    fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    fn shutdown_seen(&self) -> bool {
        self.shutdown_seen.load(Ordering::SeqCst)
    }

    /// Running and not ended: an active connection carrying Visitors.
    fn active(&self) -> bool {
        self.started() && !self.ended()
    }

    fn outcome(self: &Arc<Self>) -> TunnelAttemptOutcome {
        let hints = self
            .hints
            .lock()
            .unwrap()
            .as_ref()
            .expect("hints live")
            .subscribe();
        let connection = Arc::clone(self);
        TunnelAttemptOutcome::Connected {
            configured_server_addr: "tunnel.example.test:443".to_owned(),
            hints,
            run: Box::new(move |shutdown| {
                Box::pin(async move {
                    connection.started.store(true, Ordering::SeqCst);
                    let result = tokio::select! {
                        _ = shutdown.wait_started() => {
                            connection.shutdown_seen.store(true, Ordering::SeqCst);
                            if connection.fail_withdrawal.load(Ordering::SeqCst) {
                                Err(TunnelConnectionEnd::withdrawal_protocol_failure(
                                    "withdrawal failed",
                                ))
                            } else {
                                Ok(())
                            }
                        }
                        _ = connection.remote_close.notified() => {
                            Err(TunnelConnectionEnd::unclassified("connection closed"))
                        }
                    };
                    connection.ended.store(true, Ordering::SeqCst);
                    result
                })
            }),
        }
    }
}

enum CandidateScript {
    Connect(Arc<FakeConnection>),
    /// Connect once the test releases the gate, so completion can coincide with other events.
    ConnectWhen(Arc<FakeConnection>, Arc<Notify>),
    Fail(&'static str),
}

/// Records that a candidate attempt future was dropped, by abort or after it completed.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct FakeDial {
    primaries: Arc<Mutex<VecDeque<Arc<FakeConnection>>>>,
    candidates: Mutex<VecDeque<CandidateScript>>,
    primary_dials: Arc<AtomicUsize>,
    /// Every candidate attempt: when it started, its target, and whether it was dropped.
    attempts: Mutex<Vec<(Instant, ServerRuntimeGeneration, Arc<AtomicBool>)>>,
}

impl FakeDial {
    fn with_primary(primary: &Arc<FakeConnection>) -> Arc<Self> {
        let dial = Self::default();
        dial.primaries
            .lock()
            .unwrap()
            .push_back(Arc::clone(primary));
        Arc::new(dial)
    }

    fn script(&self, script: CandidateScript) {
        self.candidates.lock().unwrap().push_back(script);
    }

    fn add_primary(&self, primary: &Arc<FakeConnection>) {
        self.primaries
            .lock()
            .unwrap()
            .push_back(Arc::clone(primary));
    }

    fn attempts(&self) -> Vec<(Instant, ServerRuntimeGeneration, bool)> {
        self.attempts
            .lock()
            .unwrap()
            .iter()
            .map(|(at, target, dropped)| (*at, *target, dropped.load(Ordering::SeqCst)))
            .collect()
    }

    fn primary_dials(&self) -> usize {
        self.primary_dials.load(Ordering::SeqCst)
    }
}

impl AddressWorkerDial for FakeDial {
    fn establish(&self, _address: ServerAddress) -> BoxFuture<'static, TunnelAttemptOutcome> {
        // Count and consume only once polled, so a dial the worker drops unpolled loses nothing.
        let dials = Arc::clone(&self.primary_dials);
        let primaries = Arc::clone(&self.primaries);
        Box::pin(async move {
            dials.fetch_add(1, Ordering::SeqCst);
            let next = primaries.lock().unwrap().pop_front();
            match next {
                Some(connection) => connection.outcome(),
                None => std::future::pending().await,
            }
        })
    }

    fn establish_candidate(
        &self,
        _address: ServerAddress,
        expected_generation: ServerRuntimeGeneration,
    ) -> BoxFuture<'static, TunnelAttemptOutcome> {
        let dropped = Arc::new(AtomicBool::new(false));
        self.attempts.lock().unwrap().push((
            Instant::now(),
            expected_generation,
            Arc::clone(&dropped),
        ));
        let script = self.candidates.lock().unwrap().pop_front();
        Box::pin(async move {
            let _flag = DropFlag(dropped);
            match script {
                Some(CandidateScript::Connect(connection)) => connection.outcome(),
                Some(CandidateScript::ConnectWhen(connection, gate)) => {
                    gate.notified().await;
                    connection.outcome()
                }
                Some(CandidateScript::Fail(message)) => {
                    TunnelAttemptOutcome::Retryable(TunnelAttemptFailure::unclassified(message))
                }
                None => std::future::pending().await,
            }
        })
    }
}

fn factory(
    dial: &Arc<FakeDial>,
    hooks: Arc<dyn AddressWorkerHooks>,
) -> crate::AddressWorkerFactory {
    let dial = Arc::clone(dial);
    Arc::new(move |address, control| {
        let dial = Arc::clone(&dial);
        let hooks = Arc::clone(&hooks);
        Box::pin(async move {
            run_address_worker(address, control, dial, hooks, FixedBackoff(CANDIDATE_DELAY)).await
        })
    })
}

fn address() -> ServerAddress {
    ServerAddress::parse("tunnel.example.test").unwrap()
}

/// A static controller running one worker for [`address`].
struct Harness {
    dial: Arc<FakeDial>,
    shutdown: crate::AddressControllerShutdown,
    runtime: tokio::task::JoinHandle<Result<(), String>>,
}

impl Harness {
    async fn start(primary: &Arc<FakeConnection>) -> Self {
        Self::start_with_hooks(primary, Arc::new(SilentAddressWorkerHooks)).await
    }

    async fn start_with_hooks(
        primary: &Arc<FakeConnection>,
        hooks: Arc<dyn AddressWorkerHooks>,
    ) -> Self {
        let dial = FakeDial::with_primary(primary);
        let mut controller = AddressController::for_static(factory(&dial, hooks))
            .with_graceful_shutdown_duration(GRACEFUL);
        controller.seed_configured([address()]);
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });
        wait_until(|| dial.primary_dials() == 1).await;
        settle().await;
        Self {
            dial,
            shutdown,
            runtime,
        }
    }

    async fn wait_for_attempts(&self, count: usize) {
        wait_until(|| self.dial.attempts().len() >= count).await;
    }

    async fn finish(self, mode: ShutdownMode) {
        self.shutdown.begin(mode);
        tokio::time::timeout(Duration::from_secs(5), self.runtime)
            .await
            .expect("runtime finishes")
            .expect("runtime join")
            .expect("clean shutdown");
    }
}

/// Let spawned tasks observe the latest changes without advancing time.
async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}

async fn wait_until(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "condition not met before timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_validated_candidate_joins_beside_the_primary_and_takes_over_without_reconnecting() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let harness = Harness::start(&old).await;
    let target = generation();
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&new)));

    let hinted_at = Instant::now();
    old.set_hint(hint(Some(target), 0));
    wait_until(|| new.started()).await;

    let attempts = harness.dial.attempts();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].1, target);
    assert_eq!(attempts[0].0 - hinted_at, CANDIDATE_DELAY);
    assert!(
        old.active() && new.active(),
        "both connections carry Visitors"
    );

    // An abrupt loss of the old connection during the overlap hands over without a reconnect.
    old.close();
    wait_until(|| old.ended()).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(new.active());
    assert_eq!(harness.dial.primary_dials(), 1);
    assert_eq!(harness.dial.attempts().len(), 1);

    // The joined connection now owns reconnect.
    let next = FakeConnection::new();
    harness.dial.add_primary(&next);
    new.close();
    wait_until(|| harness.dial.primary_dials() == 2).await;
    harness.finish(ShutdownMode::Graceful).await;
    assert!(next.shutdown_seen());
}

#[tokio::test(start_paused = true)]
async fn losing_the_joined_connection_keeps_the_primary_and_rejoins_while_the_hint_stands() {
    let old = FakeConnection::new();
    let first = FakeConnection::new();
    let second = FakeConnection::new();
    let harness = Harness::start(&old).await;
    let target = generation();
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&first)));
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&second)));

    old.set_hint(hint(Some(target), 0));
    wait_until(|| first.started()).await;
    first.close();
    wait_until(|| second.started()).await;

    assert!(old.active() && second.active());
    assert_eq!(harness.dial.primary_dials(), 1);
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn no_further_candidate_starts_while_a_second_connection_is_active() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let harness = Harness::start(&old).await;
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&new)));
    old.set_hint(hint(Some(generation()), 0));
    wait_until(|| new.started()).await;

    old.set_hint(hint(Some(generation()), 0));
    old.set_hint(hint(None, 0));
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert_eq!(harness.dial.attempts().len(), 1);
    assert!(
        new.active(),
        "a hint change never touches a joined connection"
    );
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn a_duplicate_hint_keeps_the_warming_candidate() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;
    let target = generation();

    primary.set_hint(hint(Some(target), 0));
    harness.wait_for_attempts(1).await;
    primary.set_hint(hint(Some(target), 0));
    tokio::time::sleep(Duration::from_secs(5)).await;

    let attempts = harness.dial.attempts();
    assert_eq!(attempts.len(), 1);
    assert!(!attempts[0].2, "the duplicate is a no-op");
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn a_changed_hint_aborts_the_candidate_and_starts_one_for_the_new_generation() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;
    let first = generation();
    let second = generation();

    primary.set_hint(hint(Some(first), 0));
    harness.wait_for_attempts(1).await;
    let changed_at = Instant::now();
    primary.set_hint(hint(Some(second), 0));
    harness.wait_for_attempts(2).await;

    let attempts = harness.dial.attempts();
    assert!(attempts[0].2, "the old candidate was aborted");
    assert_eq!(attempts[1].1, second);
    assert_eq!(attempts[1].0 - changed_at, CANDIDATE_DELAY);
    assert!(primary.active());
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn a_withdrawn_hint_aborts_an_unvalidated_candidate() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;

    primary.set_hint(hint(Some(generation()), 0));
    harness.wait_for_attempts(1).await;
    primary.set_hint(hint(None, 0));
    settle().await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    let attempts = harness.dial.attempts();
    assert_eq!(attempts.len(), 1);
    assert!(attempts[0].2);
    assert!(primary.active());
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn failed_candidates_retry_while_the_hint_stands_and_keep_the_primary() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;
    let target = generation();
    // A wrong generation and an admission-limit close are both ordinary candidate failures.
    harness.dial.script(CandidateScript::Fail(
        "candidate reached the old generation",
    ));
    harness
        .dial
        .script(CandidateScript::Fail("tunnel connection limit reached"));

    primary.set_hint(hint(Some(target), 0));
    harness.wait_for_attempts(3).await;

    let attempts = harness.dial.attempts();
    assert!(
        attempts
            .iter()
            .all(|(_, attempted, _)| *attempted == target)
    );
    assert_eq!(attempts[1].0 - attempts[0].0, CANDIDATE_DELAY);
    assert_eq!(attempts[2].0 - attempts[1].0, CANDIDATE_DELAY);
    assert!(primary.active());
    assert_eq!(harness.dial.primary_dials(), 1);
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn a_subscription_interruption_aborts_the_candidate_until_the_resubscribed_hint() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;
    let target = generation();

    primary.set_hint(hint(Some(target), 0));
    harness.wait_for_attempts(1).await;
    primary.set_hint(hint(None, 1));
    settle().await;
    assert!(
        harness.dial.attempts()[0].2,
        "interruption aborts the candidate"
    );
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(harness.dial.attempts().len(), 1, "replacement pauses");

    primary.set_hint(hint(Some(target), 1));
    harness.wait_for_attempts(2).await;
    assert!(primary.active(), "the primary stays up");

    // A resubscription the worker observes only after its new snapshot still restarts.
    primary.set_hint(hint(Some(target), 2));
    harness.wait_for_attempts(3).await;
    assert!(harness.dial.attempts()[1].2);
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn losing_the_primary_without_a_second_connection_aborts_the_candidate_and_reconnects() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;

    primary.set_hint(hint(Some(generation()), 0));
    harness.wait_for_attempts(1).await;
    primary.close();
    wait_until(|| harness.dial.primary_dials() == 2).await;

    assert!(harness.dial.attempts()[0].2);
    assert_eq!(harness.dial.attempts().len(), 1);
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn after_goaway_the_last_hint_stands_and_the_candidate_still_joins() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let harness = Harness::start(&old).await;

    old.set_hint(hint(Some(generation()), 0));
    old.stop_hints();
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&new)));
    wait_until(|| new.started()).await;

    // The draining connection finishes; the joined one serves on without a reconnect.
    old.close();
    wait_until(|| old.ended()).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(new.active());
    assert_eq!(harness.dial.primary_dials(), 1);
    harness.finish(ShutdownMode::Graceful).await;
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_aborts_a_warming_candidate_at_once() {
    let primary = FakeConnection::new();
    let harness = Harness::start(&primary).await;

    primary.set_hint(hint(Some(generation()), 0));
    harness.wait_for_attempts(1).await;
    harness.shutdown.begin(ShutdownMode::Graceful);
    settle().await;

    assert!(harness.dial.attempts()[0].2);
    wait_until(|| primary.ended()).await;
    harness.finish(ShutdownMode::Graceful).await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_reaches_both_active_connections_and_waits_for_them() {
    for mode in [ShutdownMode::Graceful, ShutdownMode::Fast] {
        let old = FakeConnection::new();
        let new = FakeConnection::new();
        let harness = Harness::start(&old).await;
        harness
            .dial
            .script(CandidateScript::Connect(Arc::clone(&new)));
        old.set_hint(hint(Some(generation()), 0));
        wait_until(|| new.started()).await;

        harness.finish(mode).await;
        assert!(old.shutdown_seen() && new.shutdown_seen(), "{mode:?}");
        assert!(old.ended() && new.ended(), "{mode:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_joined_connections_withdrawal_protocol_failure_fails_the_process() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    new.fail_withdrawal.store(true, Ordering::SeqCst);
    let harness = Harness::start(&old).await;
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&new)));
    old.set_hint(hint(Some(generation()), 0));
    wait_until(|| new.started()).await;

    harness.shutdown.begin(ShutdownMode::Graceful);
    let result = tokio::time::timeout(Duration::from_secs(5), harness.runtime)
        .await
        .expect("runtime finishes")
        .expect("runtime join");
    assert_eq!(result, Err("withdrawal failed".to_owned()));
    assert!(old.shutdown_seen());
}

#[tokio::test(start_paused = true)]
async fn static_readiness_fires_once_across_a_join_and_handover() {
    struct ReadyHooks(Arc<AtomicUsize>);

    impl AddressWorkerHooks for ReadyHooks {
        fn on_client_ready(&self, _configured_server_addr: &str) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let ready = Arc::new(AtomicUsize::new(0));
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let harness = Harness::start_with_hooks(&old, Arc::new(ReadyHooks(Arc::clone(&ready)))).await;
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&new)));
    old.set_hint(hint(Some(generation()), 0));
    wait_until(|| new.started()).await;
    old.close();
    wait_until(|| old.ended()).await;
    settle().await;

    assert_eq!(ready.load(Ordering::SeqCst), 1);
    harness.finish(ShutdownMode::Fast).await;
}

async fn apply(adapter: &mut crate::ClientAssignmentAdapter, addresses: Vec<ServerAddress>) {
    adapter
        .apply(ClientManagedInput {
            server_addresses: addresses,
        })
        .await
        .expect("apply ok");
}

#[tokio::test(start_paused = true)]
async fn convergence_ignores_candidates_and_survives_a_join_and_handover() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let dial = FakeDial::with_primary(&old);
    let (mut controller, mut adapter) =
        AddressController::for_managed(factory(&dial, Arc::new(SilentAddressWorkerHooks)));
    let view = controller.view();
    let runtime = tokio::spawn(async move { controller.run().await });
    apply(&mut adapter, vec![address()]).await;
    wait_until(|| view.assignment_convergence() == AssignmentConvergence::Converged).await;

    dial.script(CandidateScript::Connect(Arc::clone(&new)));
    old.set_hint(hint(Some(generation()), 0));
    wait_until(|| !dial.attempts().is_empty()).await;
    assert_eq!(
        view.assignment_convergence(),
        AssignmentConvergence::Converged
    );
    wait_until(|| new.started()).await;
    old.close();
    wait_until(|| old.ended()).await;
    settle().await;

    assert_eq!(
        view.assignment_convergence(),
        AssignmentConvergence::Converged
    );
    assert_eq!(view.worker_count(), 1);
    assert_eq!(dial.primary_dials(), 1);
    runtime.abort();
}

#[tokio::test(start_paused = true)]
async fn removal_aborts_a_warming_candidate_and_re_adding_restarts_it() {
    let primary = FakeConnection::new();
    let dial = FakeDial::with_primary(&primary);
    let (mut controller, mut adapter) =
        AddressController::for_managed(factory(&dial, Arc::new(SilentAddressWorkerHooks)));
    let view = controller.view();
    let runtime = tokio::spawn(async move { controller.run().await });
    apply(&mut adapter, vec![address()]).await;
    wait_until(|| view.assignment_convergence() == AssignmentConvergence::Converged).await;
    let target = generation();

    primary.set_hint(hint(Some(target), 0));
    wait_until(|| dial.attempts().len() == 1).await;
    apply(&mut adapter, Vec::new()).await;
    settle().await;
    assert!(dial.attempts()[0].2, "Retiring aborts the candidate");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        dial.attempts().len(),
        1,
        "a Retiring address starts no candidates"
    );
    assert!(primary.active(), "Retiring keeps the primary");

    apply(&mut adapter, vec![address()]).await;
    wait_until(|| dial.attempts().len() == 2).await;
    assert_eq!(dial.attempts()[1].1, target);
    assert_eq!(dial.primary_dials(), 1, "re-adoption does not dial");
    runtime.abort();
}

fn paused(generation: Option<ServerRuntimeGeneration>, interruptions: u64) -> ReplacementHint {
    ReplacementHint {
        paused: true,
        ..hint(generation, interruptions)
    }
}

/// Start a primary, hint `target`, and leave one gated candidate attempt in flight.
async fn gated_candidate(
    old: &Arc<FakeConnection>,
    new: &Arc<FakeConnection>,
    target: ServerRuntimeGeneration,
) -> (Harness, Arc<Notify>) {
    let harness = Harness::start(old).await;
    let gate = Arc::new(Notify::new());
    harness.dial.script(CandidateScript::ConnectWhen(
        Arc::clone(new),
        Arc::clone(&gate),
    ));
    old.set_hint(hint(Some(target), 0));
    harness.wait_for_attempts(1).await;
    settle().await;
    (harness, gate)
}

#[tokio::test(start_paused = true)]
async fn a_hint_withdrawn_as_the_candidate_completes_prevents_the_join() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let (harness, gate) = gated_candidate(&old, &new, generation()).await;

    // Both become ready before the worker runs again.
    old.set_hint(hint(None, 0));
    gate.notify_one();
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert!(
        !new.started(),
        "the candidate never ran, so it never offered credit"
    );
    assert!(old.active());
    assert_eq!(harness.dial.attempts().len(), 1);
    harness.finish(ShutdownMode::Fast).await;
}

#[tokio::test(start_paused = true)]
async fn losing_the_primary_as_the_candidate_completes_takes_the_ordinary_reconnect() {
    let old = FakeConnection::new();
    let new = FakeConnection::new();
    let (harness, gate) = gated_candidate(&old, &new, generation()).await;
    let next = FakeConnection::new();
    harness.dial.add_primary(&next);

    old.close();
    gate.notify_one();
    wait_until(|| harness.dial.primary_dials() == 2).await;

    assert!(!new.started(), "no join after primary loss");
    harness.finish(ShutdownMode::Fast).await;
    assert!(next.shutdown_seen());
}

#[tokio::test(start_paused = true)]
async fn a_paused_hint_blocks_the_join_until_goaway_restores_it() {
    let old = FakeConnection::new();
    let first = FakeConnection::new();
    let target = generation();
    let (harness, gate) = gated_candidate(&old, &first, target).await;

    // The subscription ended; the Client does not know yet whether GOAWAY caused it.
    old.set_hint(paused(Some(target), 0));
    gate.notify_one();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!first.started(), "no join while paused");

    // GOAWAY refused the resubscription: the hint stands and the candidate joins on retry.
    let second = FakeConnection::new();
    harness
        .dial
        .script(CandidateScript::Connect(Arc::clone(&second)));
    old.set_hint(hint(Some(target), 0));
    old.stop_hints();
    wait_until(|| second.started()).await;
    assert_eq!(harness.dial.attempts().len(), 2);
    harness.finish(ShutdownMode::Fast).await;
}
