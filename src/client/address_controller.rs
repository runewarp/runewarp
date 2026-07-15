//! Client **Address controller** owning the complete assigned **Server address**
//! lifecycle: maintenance intent, address workers, **Retiring**, **Assignment
//! convergence**, managed apply acknowledgment, fatal worker completion, static
//! **Client-ready** policy, and shutdown draining.
//!
//! Static Client startup seeds the controller from configured **Server addresses**
//! via [`AddressController::for_static`] and [`AddressController::seed_configured`].
//! Managed-session reconciliation drives the same seam through
//! [`AddressController::for_managed`], which returns a
//! [`crate::ClientAssignmentAdapter`] wired to the controller's internal apply loop.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc, watch};

use super::assignment_convergence::{AssignmentConvergence, AssignmentConvergenceTracker};
use super::managed_adapter::ClientAssignmentApply;
use crate::ServerAddress;

/// Spawns one address worker for a normalized **Server address**.
pub type AddressWorkerFactory = Arc<
    dyn Fn(ServerAddress, AddressWorkerControl) -> BoxFuture<'static, Result<(), String>>
        + Send
        + Sync,
>;

/// Whether the controller should keep maintaining a Tunnel connection for an address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceIntent {
    /// Dial and reconnect as needed.
    Maintain,
    /// Stop dialing and reconnecting; leave any live connection until remote close
    /// or process shutdown.
    Retire,
}

/// Per-worker control channels observed by an address worker.
#[derive(Clone, Debug)]
pub struct AddressWorkerControl {
    maintenance: watch::Receiver<MaintenanceIntent>,
    shutdown: watch::Receiver<bool>,
    ready_logged: Arc<AtomicBool>,
    client_ready_enabled: bool,
    convergence: Option<AssignmentConvergenceTracker>,
}

impl AddressWorkerControl {
    pub fn maintenance_intent(&self) -> MaintenanceIntent {
        *self.maintenance.borrow()
    }

    pub fn subscribe_maintenance(&self) -> watch::Receiver<MaintenanceIntent> {
        self.maintenance.clone()
    }

    pub fn shutdown_requested(&self) -> bool {
        *self.shutdown.borrow()
    }

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.clone()
    }

    /// Returns true exactly once across all workers for the one-shot Client-ready log.
    ///
    /// Managed mode disables this so **Assignment convergence** replaces the static
    /// one-shot Client-ready event.
    pub fn claim_client_ready_log(&self) -> bool {
        self.client_ready_enabled && !self.ready_logged.swap(true, Ordering::SeqCst)
    }

    /// Record that this worker reached Connected. Returns the new **Assignment
    /// convergence** when it changed. No-op in static mode (no tracker).
    pub fn observe_connected(&self, address: &ServerAddress) -> Option<AssignmentConvergence> {
        self.convergence
            .as_ref()
            .and_then(|tracker| tracker.mark_connected(address))
    }

    /// Record that this worker lost Connected. Returns the new **Assignment
    /// convergence** when it changed. No-op in static mode (no tracker).
    pub fn observe_disconnected(&self, address: &ServerAddress) -> Option<AssignmentConvergence> {
        self.convergence
            .as_ref()
            .and_then(|tracker| tracker.mark_disconnected(address))
    }
}

struct WorkerSlot {
    maintenance_tx: watch::Sender<MaintenanceIntent>,
    generation: u64,
}

type RunningWorker = BoxFuture<'static, (ServerAddress, u64, Result<(), String>)>;

/// How the controller was constructed and which subsystems are active.
enum ControllerMode {
    /// Lightweight intent/slot tests via [`AddressController::new`] + [`AddressController::add`]
    /// / [`AddressController::seed_static`].
    Manual {
        client_ready_enabled: bool,
        convergence: Option<AssignmentConvergenceTracker>,
    },
    /// Static Client startup via [`AddressController::for_static`]: factory-driven seeding,
    /// **Client-ready** enabled, no managed apply loop.
    Static { factory: AddressWorkerFactory },
    /// Managed-session reconciliation via [`AddressController::for_managed`]: factory,
    /// apply channel, and **Assignment convergence**; **Client-ready** disabled.
    Managed {
        factory: AddressWorkerFactory,
        apply_rx: Option<mpsc::UnboundedReceiver<ClientAssignmentApply>>,
        convergence: AssignmentConvergenceTracker,
    },
}

/// Owns address-worker lifecycle keyed by normalized **Server address**.
pub struct AddressController {
    workers: HashMap<ServerAddress, WorkerSlot>,
    running: FuturesUnordered<RunningWorker>,
    ready_logged: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    next_generation: u64,
    mode: ControllerMode,
    shared_worker_count: Arc<AtomicUsize>,
}

/// Read-only observation handle for integration tests and harnesses.
#[derive(Clone, Debug)]
pub struct AddressControllerView {
    convergence: Option<AssignmentConvergenceTracker>,
    worker_count: Arc<AtomicUsize>,
}

impl AddressControllerView {
    /// Current **Assignment convergence**. Static mode without a tracker is always
    /// [`AssignmentConvergence::Converged`].
    pub fn assignment_convergence(&self) -> AssignmentConvergence {
        self.convergence
            .as_ref()
            .map(AssignmentConvergenceTracker::current)
            .unwrap_or(AssignmentConvergence::Converged)
    }

    /// Number of live address-worker slots.
    pub fn worker_count(&self) -> usize {
        self.worker_count.load(Ordering::SeqCst)
    }
}

/// Signals process shutdown to every address worker without borrowing the controller mutably.
#[derive(Clone, Debug)]
pub struct AddressControllerShutdown {
    shutdown_tx: watch::Sender<bool>,
}

impl AddressControllerShutdown {
    pub fn request(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Default for AddressController {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressController {
    fn new_with_mode(mode: ControllerMode) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            workers: HashMap::new(),
            running: FuturesUnordered::new(),
            ready_logged: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            shutdown_rx,
            next_generation: 1,
            mode,
            shared_worker_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn new() -> Self {
        Self::new_with_mode(ControllerMode::Manual {
            client_ready_enabled: true,
            convergence: None,
        })
    }

    /// Static Client controller with **Client-ready** enabled and no managed apply loop.
    pub fn for_static(factory: AddressWorkerFactory) -> Self {
        Self::new_with_mode(ControllerMode::Static { factory })
    }

    /// Managed Client controller with **Assignment convergence** tracking and an apply
    /// channel owned by [`Self::run`]. Disables the static one-shot **Client-ready** log.
    ///
    /// Production obtains [`crate::ClientAssignmentAdapter`] only through this constructor.
    pub fn for_managed(factory: AddressWorkerFactory) -> (Self, crate::ClientAssignmentAdapter) {
        let (apply_tx, apply_rx) = mpsc::unbounded_channel();
        let adapter = crate::ClientAssignmentAdapter::new(apply_tx);
        let controller = Self::new_with_mode(ControllerMode::Managed {
            factory,
            apply_rx: Some(apply_rx),
            convergence: AssignmentConvergenceTracker::new(),
        });
        (controller, adapter)
    }

    fn factory(&self) -> Option<&AddressWorkerFactory> {
        match &self.mode {
            ControllerMode::Manual { .. } => None,
            ControllerMode::Static { factory } | ControllerMode::Managed { factory, .. } => {
                Some(factory)
            }
        }
    }

    fn convergence_tracker(&self) -> Option<&AssignmentConvergenceTracker> {
        match &self.mode {
            ControllerMode::Manual { convergence, .. } => convergence.as_ref(),
            ControllerMode::Static { .. } => None,
            ControllerMode::Managed { convergence, .. } => Some(convergence),
        }
    }

    fn client_ready_enabled(&self) -> bool {
        match &self.mode {
            ControllerMode::Manual {
                client_ready_enabled,
                ..
            } => *client_ready_enabled,
            ControllerMode::Static { .. } => true,
            ControllerMode::Managed { .. } => false,
        }
    }

    /// Clone a read-only view for observing worker count and **Assignment convergence**
    /// from another task (for example integration-test harnesses).
    pub fn view(&self) -> AddressControllerView {
        AddressControllerView {
            convergence: self.convergence_tracker().cloned(),
            worker_count: Arc::clone(&self.shared_worker_count),
        }
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Current **Assignment convergence**. Static mode without a tracker is always
    /// [`AssignmentConvergence::Converged`].
    pub fn assignment_convergence(&self) -> AssignmentConvergence {
        self.convergence_tracker()
            .map(AssignmentConvergenceTracker::current)
            .unwrap_or(AssignmentConvergence::Converged)
    }

    /// True while at least one address-worker future is still outstanding.
    pub fn has_inflight_workers(&self) -> bool {
        !self.running.is_empty()
    }

    pub fn contains(&self, address: &ServerAddress) -> bool {
        self.workers.contains_key(address)
    }

    pub fn maintenance_intent(&self, address: &ServerAddress) -> Option<MaintenanceIntent> {
        self.workers
            .get(address)
            .map(|slot| *slot.maintenance_tx.borrow())
    }

    /// Seed workers from the configured **Server address** set using the stored factory.
    ///
    /// No-op when no factory was configured (for example outside [`Self::for_static`]).
    pub fn seed_configured(&mut self, addresses: impl IntoIterator<Item = ServerAddress>) {
        let Some(factory) = self.factory() else {
            return;
        };
        let factory = factory.clone();
        for address in addresses {
            let _ = self.add_with_factory(address, &factory);
        }
    }

    /// Seed workers from the static configured Server address set.
    pub fn seed_static<F, Fut>(
        &mut self,
        addresses: impl IntoIterator<Item = ServerAddress>,
        mut spawn: F,
    ) where
        F: FnMut(ServerAddress, AddressWorkerControl) -> Fut,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        for address in addresses {
            let _ = self.add(address, &mut spawn);
        }
    }

    /// Start maintaining `address`, or re-adopt a live Retiring worker for it.
    ///
    /// Returns `false` when a live Maintain worker already exists (duplicate prevention).
    /// If a previous worker has already exited but has not been reaped yet, the stale
    /// slot is replaced by a newly spawned worker.
    pub fn add<F, Fut>(&mut self, address: ServerAddress, spawn: F) -> bool
    where
        F: FnOnce(ServerAddress, AddressWorkerControl) -> Fut,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        if let Some(slot) = self.workers.get(&address) {
            if slot.is_live() {
                let current = *slot.maintenance_tx.borrow();
                if current == MaintenanceIntent::Maintain {
                    return false;
                }
                let _ = slot.maintenance_tx.send(MaintenanceIntent::Maintain);
                return true;
            }
            self.workers.remove(&address);
            self.decrement_shared_worker_count();
        }

        self.spawn_worker(address, spawn);
        true
    }

    fn add_with_factory(&mut self, address: ServerAddress, factory: &AddressWorkerFactory) -> bool {
        let factory = factory.clone();
        self.add(address, move |addr, control| factory(addr, control))
    }

    /// Stop maintaining `address`.
    ///
    /// Establishing / reconnecting workers should exit after observing
    /// [`MaintenanceIntent::Retire`]. Connected workers stay Retiring until remote
    /// closure or process shutdown. Returns `false` when no live worker exists.
    pub fn remove(&self, address: &ServerAddress) -> bool {
        let Some(slot) = self.workers.get(address) else {
            return false;
        };
        if !slot.is_live() {
            return false;
        }
        let _ = slot.maintenance_tx.send(MaintenanceIntent::Retire);
        true
    }

    /// Restore maintenance for a live Retiring address without starting a second dial loop.
    ///
    /// Returns `false` when no live Retiring worker exists for `address`.
    pub fn re_adopt(&self, address: &ServerAddress) -> bool {
        let Some(slot) = self.workers.get(address) else {
            return false;
        };
        if !slot.is_live() || *slot.maintenance_tx.borrow() != MaintenanceIntent::Retire {
            return false;
        }
        let _ = slot.maintenance_tx.send(MaintenanceIntent::Maintain);
        true
    }

    /// Replace maintenance intent with `desired` using the stored factory.
    fn replace_intent_with_factory(
        &mut self,
        desired: &[ServerAddress],
        factory: &AddressWorkerFactory,
    ) {
        let factory = factory.clone();
        self.replace_intent(desired, move |addr, control| factory(addr, control));
    }

    /// Replace maintenance intent with `desired`.
    ///
    /// Dispatches removals, re-adoptions, and additions without waiting for network
    /// convergence. Addresses already Retiring and absent from `desired` stay Retiring.
    pub fn replace_intent<F, Fut>(&mut self, desired: &[ServerAddress], mut spawn: F)
    where
        F: FnMut(ServerAddress, AddressWorkerControl) -> Fut,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let desired_set: HashSet<ServerAddress> = desired.iter().cloned().collect();
        let existing: Vec<ServerAddress> = self.workers.keys().cloned().collect();
        for address in existing {
            if desired_set.contains(&address) {
                if self.maintenance_intent(&address) == Some(MaintenanceIntent::Retire)
                    && !self.re_adopt(&address)
                {
                    self.workers.remove(&address);
                    self.decrement_shared_worker_count();
                }
            } else if self.maintenance_intent(&address) == Some(MaintenanceIntent::Maintain) {
                let _ = self.remove(&address);
            }
        }
        for address in desired {
            if !self.contains(address) || !self.worker_is_live(address) {
                let _ = self.add(address.clone(), &mut spawn);
            }
        }
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Cloneable handle for signaling process shutdown without borrowing the controller mutably.
    pub fn shutdown_handle(&self) -> AddressControllerShutdown {
        AddressControllerShutdown {
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }

    /// Drive the controller event loop.
    ///
    /// Static mode (no apply channel) is equivalent to [`Self::run_until_idle`]. Managed
    /// mode selects on assignment applies, worker completions, and shutdown.
    pub async fn run(&mut self) -> Result<(), String> {
        match &mut self.mode {
            ControllerMode::Managed {
                factory,
                apply_rx,
                convergence,
            } => {
                let Some(mut apply_rx) = apply_rx.take() else {
                    return self.run_until_idle().await;
                };
                let factory = factory.clone();
                let convergence = convergence.clone();
                let mut shutdown_rx = self.shutdown_rx.clone();

                loop {
                    let drive_workers = self.has_inflight_workers();
                    tokio::select! {
                        biased;
                        apply = apply_rx.recv() => {
                            let Some(ClientAssignmentApply { addresses, done }) = apply else {
                                self.request_shutdown();
                                return self.run_until_idle().await;
                            };
                            let status = convergence
                                .set_assigned(&addresses)
                                .unwrap_or_else(|| convergence.current());
                            crate::runtime_log::client_assignment_convergence(status);
                            self.replace_intent_with_factory(&addresses, &factory);
                            let _ = done.send(Ok(()));
                        }
                        completion = self.next_completion(), if drive_workers => {
                            match completion {
                                Some(Ok(_)) => {}
                                Some(Err((_address, error))) => {
                                    self.request_shutdown();
                                    return Err(error);
                                }
                                None => {}
                            }
                        }
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                return self.run_until_idle().await;
                            }
                        }
                    }
                }
            }
            ControllerMode::Manual { .. } | ControllerMode::Static { .. } => {
                self.run_until_idle().await
            }
        }
    }

    /// Wait for the next current worker completion and drop its slot.
    ///
    /// Completions from workers that were already replaced are ignored so a stale
    /// exit cannot clear a respawned slot. Unexpected worker failures are returned
    /// as `Err`. Clean completion is `Ok`.
    pub async fn next_completion(
        &mut self,
    ) -> Option<Result<ServerAddress, (ServerAddress, String)>> {
        while let Some((address, generation, result)) = self.running.next().await {
            let is_current = self
                .workers
                .get(&address)
                .is_some_and(|slot| slot.generation == generation);
            if !is_current {
                continue;
            }
            self.workers.remove(&address);
            self.decrement_shared_worker_count();
            return Some(match result {
                Ok(()) => Ok(address),
                Err(error) => Err((address, error)),
            });
        }
        None
    }

    /// Drive workers until every slot has completed, or one fails unexpectedly.
    pub async fn run_until_idle(&mut self) -> Result<(), String> {
        while self.worker_count() > 0 || !self.running.is_empty() {
            match self.next_completion().await {
                Some(Ok(_)) => {}
                Some(Err((_address, error))) => return Err(error),
                None => break,
            }
        }
        Ok(())
    }

    fn worker_is_live(&self, address: &ServerAddress) -> bool {
        self.workers.get(address).is_some_and(WorkerSlot::is_live)
    }

    fn increment_shared_worker_count(&self) {
        self.shared_worker_count.fetch_add(1, Ordering::SeqCst);
    }

    fn decrement_shared_worker_count(&self) {
        self.shared_worker_count.fetch_sub(1, Ordering::SeqCst);
    }

    fn spawn_worker<F, Fut>(&mut self, address: ServerAddress, spawn: F)
    where
        F: FnOnce(ServerAddress, AddressWorkerControl) -> Fut,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);

        let (maintenance_tx, maintenance_rx) = watch::channel(MaintenanceIntent::Maintain);
        let control = AddressWorkerControl {
            maintenance: maintenance_rx,
            shutdown: self.shutdown_rx.clone(),
            ready_logged: Arc::clone(&self.ready_logged),
            client_ready_enabled: self.client_ready_enabled(),
            convergence: self.convergence_tracker().cloned(),
        };
        let worker_address = address.clone();
        let future = spawn(address.clone(), control);
        let join = tokio::spawn(future);
        self.running.push(Box::pin(async move {
            let result = match join.await {
                Ok(result) => result,
                Err(join_error) => Err(join_error.to_string()),
            };
            (worker_address, generation, result)
        }));
        self.workers.insert(
            address,
            WorkerSlot {
                maintenance_tx,
                generation,
            },
        );
        self.increment_shared_worker_count();
    }
}

impl WorkerSlot {
    fn is_live(&self) -> bool {
        self.maintenance_tx.receiver_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use futures_util::FutureExt;
    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::time::{sleep, timeout};

    use super::{
        AddressController, AddressWorkerControl, AddressWorkerFactory, AssignmentConvergence,
        MaintenanceIntent,
    };
    use crate::ServerAddress;
    use crate::managed_session::{ManagedSessionLimits, RoleAdapter};

    fn address(value: &str) -> ServerAddress {
        ServerAddress::parse(value).expect("test server address should parse")
    }

    async fn wait_until_or(label: &'static str, mut predicate: impl FnMut() -> bool) {
        if let Err(error) = timeout(Duration::from_secs(2), async {
            loop {
                if predicate() {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        {
            panic!("{label}: {error}");
        }
    }

    async fn wait_until(predicate: impl FnMut() -> bool) {
        wait_until_or("condition", predicate).await;
    }

    fn shutdown_waiting_factory() -> AddressWorkerFactory {
        Arc::new(|_address, control| {
            async move {
                wait_for_shutdown(&control).await;
                Ok(())
            }
            .boxed()
        })
    }

    fn intent_echo_factory(
        intent_tx: mpsc::UnboundedSender<MaintenanceIntent>,
    ) -> AddressWorkerFactory {
        Arc::new(move |_address, control| {
            let intent_tx = intent_tx.clone();
            async move {
                let mut maintenance = control.subscribe_maintenance();
                let _ = intent_tx.send(control.maintenance_intent());
                loop {
                    if control.shutdown_requested() {
                        return Ok(());
                    }
                    tokio::select! {
                        changed = maintenance.changed() => {
                            if changed.is_err() {
                                return Ok(());
                            }
                            let _ = intent_tx.send(*maintenance.borrow());
                        }
                        _ = wait_for_shutdown(&control) => return Ok(()),
                    }
                }
            }
            .boxed()
        })
    }

    fn started_control_factory(
        started_tx: mpsc::UnboundedSender<AddressWorkerControl>,
    ) -> AddressWorkerFactory {
        Arc::new(move |_address, control| {
            let started_tx = started_tx.clone();
            async move {
                let observed = control.clone();
                let _ = started_tx.send(observed);
                wait_until_retired_or_shutdown(&control).await;
                Ok(())
            }
            .boxed()
        })
    }

    fn retention_tracking_factory(
        starts: Arc<AtomicUsize>,
        intent_tx: mpsc::UnboundedSender<MaintenanceIntent>,
    ) -> AddressWorkerFactory {
        Arc::new(move |_address, control| {
            let starts = Arc::clone(&starts);
            let intent_tx = intent_tx.clone();
            async move {
                starts.fetch_add(1, Ordering::SeqCst);
                let _ = intent_tx.send(control.maintenance_intent());
                let mut maintenance = control.subscribe_maintenance();
                loop {
                    if control.shutdown_requested()
                        || control.maintenance_intent() == MaintenanceIntent::Retire
                    {
                        return Ok(());
                    }
                    tokio::select! {
                        changed = maintenance.changed() => {
                            if changed.is_err() {
                                return Ok(());
                            }
                            let _ = intent_tx.send(*maintenance.borrow());
                        }
                        _ = wait_for_shutdown(&control) => return Ok(()),
                    }
                }
            }
            .boxed()
        })
    }

    async fn wait_for_connect_gate(
        control: &AddressWorkerControl,
        connect_tx: &watch::Sender<bool>,
    ) -> bool {
        let mut connect_rx = connect_tx.subscribe();
        loop {
            if control.shutdown_requested() {
                return false;
            }
            if *connect_rx.borrow_and_update() {
                return true;
            }
            if connect_rx.changed().await.is_err() {
                return false;
            }
        }
    }

    async fn wait_for_disconnect_gate(disconnect_tx: &watch::Sender<bool>) -> bool {
        let mut disconnect_rx = disconnect_tx.subscribe();
        loop {
            if *disconnect_rx.borrow_and_update() {
                return true;
            }
            if disconnect_rx.changed().await.is_err() {
                return false;
            }
        }
    }

    fn convergence_gated_factory(
        connect_gates: Arc<tokio::sync::Mutex<HashMap<ServerAddress, watch::Sender<bool>>>>,
        disconnect_gates: Arc<tokio::sync::Mutex<HashMap<ServerAddress, watch::Sender<bool>>>>,
    ) -> AddressWorkerFactory {
        Arc::new(move |server_address, control| {
            let connect_gates = Arc::clone(&connect_gates);
            let disconnect_gates = Arc::clone(&disconnect_gates);
            async move {
                if let Some(connect_tx) = connect_gates.lock().await.get(&server_address).cloned()
                    && !wait_for_connect_gate(&control, &connect_tx).await
                {
                    return Ok(());
                }
                let _ = control.observe_connected(&server_address);

                let mut maintenance = control.subscribe_maintenance();
                loop {
                    if control.shutdown_requested()
                        || control.maintenance_intent() == MaintenanceIntent::Retire
                    {
                        let _ = control.observe_disconnected(&server_address);
                        return Ok(());
                    }

                    let disconnect_tx = disconnect_gates.lock().await.get(&server_address).cloned();

                    tokio::select! {
                        changed = maintenance.changed() => {
                            if changed.is_err()
                                || control.maintenance_intent() == MaintenanceIntent::Retire
                            {
                                let _ = control.observe_disconnected(&server_address);
                                return Ok(());
                            }
                        }
                        _ = async {
                            match disconnect_tx {
                                Some(tx) => wait_for_disconnect_gate(&tx).await,
                                None => std::future::pending::<bool>().await,
                            }
                        } => {
                            let _ = control.observe_disconnected(&server_address);
                        }
                        _ = wait_for_shutdown(&control) => {
                            let _ = control.observe_disconnected(&server_address);
                            return Ok(());
                        }
                    }
                }
            }
            .boxed()
        })
    }

    async fn register_connect_gate(
        gates: &Arc<tokio::sync::Mutex<HashMap<ServerAddress, watch::Sender<bool>>>>,
        address: ServerAddress,
    ) -> watch::Sender<bool> {
        let (tx, _rx) = watch::channel(false);
        gates.lock().await.insert(address, tx.clone());
        tx
    }

    async fn parse_server_addresses(addresses: &[ServerAddress]) -> Vec<ServerAddress> {
        let json_addresses: Vec<String> = addresses
            .iter()
            .map(|address| format!("{}:{}", address.hostname(), address.port()))
            .collect();
        crate::ClientAssignmentAdapter::parse_input(
            serde_json::json!({ "server_addresses": json_addresses }),
            &ManagedSessionLimits::default(),
        )
        .expect("input should parse")
        .server_addresses
    }

    async fn apply_server_addresses(
        adapter: &mut crate::ClientAssignmentAdapter,
        addresses: &[ServerAddress],
    ) -> Vec<ServerAddress> {
        let applied = parse_server_addresses(addresses).await;
        adapter
            .apply(crate::managed_session::ClientManagedInput {
                server_addresses: applied.clone(),
            })
            .await
            .expect("apply ok");
        applied
    }

    // --- existing low-level unit tests ---

    #[tokio::test]
    async fn seed_static_starts_one_worker_per_normalized_address() {
        let starts = Arc::new(AtomicUsize::new(0));
        let mut controller = AddressController::new();
        let starts_for_spawn = Arc::clone(&starts);
        controller.seed_static(
            [address("a.example.test"), address("b.example.test:9443")],
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    wait_for_shutdown(&control).await;
                    Ok(())
                }
            },
        );

        assert_eq!(controller.worker_count(), 2);
        wait_until(|| starts.load(Ordering::SeqCst) == 2).await;

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
        assert_eq!(controller.worker_count(), 0);
    }

    #[tokio::test]
    async fn add_rejects_a_second_maintain_worker_for_the_same_address() {
        let starts = Arc::new(AtomicUsize::new(0));
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");
        let starts_for_spawn = Arc::clone(&starts);

        assert!(controller.add(target.clone(), {
            let starts_for_spawn = Arc::clone(&starts_for_spawn);
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    wait_for_shutdown(&control).await;
                    Ok(())
                }
            }
        }));
        assert!(!controller.add(target.clone(), {
            let starts_for_spawn = Arc::clone(&starts_for_spawn);
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    wait_for_shutdown(&control).await;
                    Ok(())
                }
            }
        }));

        wait_until(|| starts.load(Ordering::SeqCst) == 1).await;
        assert_eq!(controller.worker_count(), 1);
        assert_eq!(
            controller.maintenance_intent(&target),
            Some(MaintenanceIntent::Maintain)
        );

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
    }

    #[tokio::test]
    async fn add_respawns_after_a_worker_exits_before_completion_is_reaped() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (exit_tx, exit_rx) = oneshot::channel::<()>();
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");
        let starts_for_spawn = Arc::clone(&starts);

        assert!(controller.add(target.clone(), {
            let starts_for_spawn = Arc::clone(&starts_for_spawn);
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    let _ = exit_tx.send(());
                    drop(control);
                    Ok(())
                }
            }
        }));
        exit_rx.await.expect("first worker should exit");
        wait_until(|| starts.load(Ordering::SeqCst) == 1).await;
        assert!(controller.contains(&target));

        assert!(controller.add(target.clone(), {
            let starts_for_spawn = Arc::clone(&starts_for_spawn);
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    wait_for_shutdown(&control).await;
                    Ok(())
                }
            }
        }));
        wait_until(|| starts.load(Ordering::SeqCst) == 2).await;
        assert_eq!(
            controller.maintenance_intent(&target),
            Some(MaintenanceIntent::Maintain)
        );

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
        assert_eq!(controller.worker_count(), 0);
    }

    #[tokio::test]
    async fn remove_cancels_an_establishing_worker() {
        let (started_tx, started_rx) = oneshot::channel::<AddressWorkerControl>();
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");

        assert!(controller.add(target.clone(), move |_address, control| {
            async move {
                let observed = control.clone();
                let _ = started_tx.send(observed);
                wait_until_retired_or_shutdown(&control).await;
                Ok(())
            }
        }));

        let control = started_rx.await.expect("worker should start");
        assert_eq!(control.maintenance_intent(), MaintenanceIntent::Maintain);
        assert!(controller.remove(&target));
        wait_until(|| control.maintenance_intent() == MaintenanceIntent::Retire).await;

        timeout(Duration::from_secs(2), controller.next_completion())
            .await
            .expect("cancelled worker should complete")
            .expect("controller should observe completion")
            .expect("cancellation is a clean completion");
        assert!(!controller.contains(&target));
    }

    #[tokio::test]
    async fn re_adopt_restores_maintenance_for_a_retiring_worker_without_spawning() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (intent_tx, mut intent_rx) = mpsc::unbounded_channel::<MaintenanceIntent>();
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");
        let starts_for_spawn = Arc::clone(&starts);

        assert!(controller.add(target.clone(), move |_address, control| {
            starts_for_spawn.fetch_add(1, Ordering::SeqCst);
            let intent_tx = intent_tx.clone();
            async move {
                let mut maintenance = control.subscribe_maintenance();
                let _ = intent_tx.send(control.maintenance_intent());
                loop {
                    if control.shutdown_requested() {
                        return Ok(());
                    }
                    tokio::select! {
                        changed = maintenance.changed() => {
                            if changed.is_err() {
                                return Ok(());
                            }
                            let _ = intent_tx.send(*maintenance.borrow());
                        }
                        _ = wait_for_shutdown(&control) => return Ok(()),
                    }
                }
            }
        }));

        wait_until(|| starts.load(Ordering::SeqCst) == 1).await;
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Maintain));
        assert!(controller.remove(&target));
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Retire));
        assert!(controller.re_adopt(&target));
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Maintain));
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(controller.worker_count(), 1);

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
    }

    #[tokio::test]
    async fn unexpected_worker_failure_surfaces_through_the_controller() {
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");
        assert!(controller.add(target.clone(), |_address, _control| async {
            Err("worker exploded".to_owned())
        }));

        let err = timeout(Duration::from_secs(2), controller.run_until_idle())
            .await
            .expect("failure should surface")
            .expect_err("unexpected worker failure should not look clean");
        assert_eq!(err, "worker exploded");
        assert!(!controller.contains(&target));
    }

    #[tokio::test]
    async fn replace_intent_dispatches_add_remove_and_re_adopt() {
        let starts = Arc::new(AtomicUsize::new(0));
        let mut controller = AddressController::new();
        let a = address("a.example.test");
        let b = address("b.example.test");
        let c = address("c.example.test");
        let starts_for_spawn = Arc::clone(&starts);

        controller.seed_static([a.clone(), b.clone()], {
            let starts_for_spawn = Arc::clone(&starts_for_spawn);
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    let mut maintenance = control.subscribe_maintenance();
                    loop {
                        if control.shutdown_requested() {
                            return Ok(());
                        }
                        tokio::select! {
                            changed = maintenance.changed() => {
                                if changed.is_err() {
                                    return Ok(());
                                }
                            }
                            _ = wait_for_shutdown(&control) => return Ok(()),
                        }
                    }
                }
            }
        });
        wait_until(|| starts.load(Ordering::SeqCst) == 2).await;
        assert!(controller.remove(&b));
        assert_eq!(
            controller.maintenance_intent(&b),
            Some(MaintenanceIntent::Retire)
        );

        controller.replace_intent(&[b.clone(), c.clone()], {
            let starts_for_spawn = Arc::clone(&starts_for_spawn);
            move |_address, control| {
                starts_for_spawn.fetch_add(1, Ordering::SeqCst);
                async move {
                    wait_until_retired_or_shutdown(&control).await;
                    Ok(())
                }
            }
        });

        assert_eq!(
            controller.maintenance_intent(&a),
            Some(MaintenanceIntent::Retire)
        );
        assert_eq!(
            controller.maintenance_intent(&b),
            Some(MaintenanceIntent::Maintain)
        );
        assert_eq!(
            controller.maintenance_intent(&c),
            Some(MaintenanceIntent::Maintain)
        );
        wait_until(|| starts.load(Ordering::SeqCst) == 3).await;

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
    }

    #[tokio::test]
    async fn remove_during_backoff_then_re_add_does_not_duplicate_workers() {
        let starts = Arc::new(AtomicUsize::new(0));
        let backoff_entered = Arc::new(AtomicUsize::new(0));
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");
        let starts_for_spawn = Arc::clone(&starts);
        let backoff_for_spawn = Arc::clone(&backoff_entered);

        assert!(controller.add(target.clone(), move |_address, control| {
            starts_for_spawn.fetch_add(1, Ordering::SeqCst);
            let backoff_for_spawn = Arc::clone(&backoff_for_spawn);
            async move {
                backoff_for_spawn.fetch_add(1, Ordering::SeqCst);
                let mut maintenance = control.subscribe_maintenance();
                loop {
                    if control.shutdown_requested() {
                        return Ok(());
                    }
                    tokio::select! {
                        changed = maintenance.changed() => {
                            if changed.is_err() {
                                return Ok(());
                            }
                        }
                        _ = wait_for_shutdown(&control) => return Ok(()),
                    }
                }
            }
        }));

        wait_until(|| backoff_entered.load(Ordering::SeqCst) == 1).await;
        assert!(controller.remove(&target));
        wait_until(|| controller.maintenance_intent(&target) == Some(MaintenanceIntent::Retire))
            .await;
        assert!(controller.re_adopt(&target));
        assert_eq!(
            controller.maintenance_intent(&target),
            Some(MaintenanceIntent::Maintain)
        );
        assert_eq!(starts.load(Ordering::SeqCst), 1);

        assert!(controller.remove(&target));
        assert!(controller.re_adopt(&target));
        assert!(controller.remove(&target));
        assert_eq!(controller.worker_count(), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.maintenance_intent(&target),
            Some(MaintenanceIntent::Retire)
        );

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
    }

    #[tokio::test]
    async fn empty_desired_set_leaves_retiring_workers_live() {
        let starts = Arc::new(AtomicUsize::new(0));
        let mut controller = AddressController::new();
        let target = address("tunnel.example.test");
        let starts_for_spawn = Arc::clone(&starts);

        assert!(controller.add(target.clone(), move |_address, control| {
            starts_for_spawn.fetch_add(1, Ordering::SeqCst);
            async move {
                let mut maintenance = control.subscribe_maintenance();
                loop {
                    if control.shutdown_requested() {
                        return Ok(());
                    }
                    tokio::select! {
                        changed = maintenance.changed() => {
                            if changed.is_err() {
                                return Ok(());
                            }
                        }
                        _ = wait_for_shutdown(&control) => return Ok(()),
                    }
                }
            }
        }));
        wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

        controller.replace_intent(&[], |_address, _control| async { Ok(()) });
        assert_eq!(
            controller.maintenance_intent(&target),
            Some(MaintenanceIntent::Retire)
        );
        assert_eq!(controller.worker_count(), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 1);

        controller.request_shutdown();
        controller
            .run_until_idle()
            .await
            .expect("shutdown should drain workers");
    }

    // --- deep-interface characterization tests ---

    #[tokio::test]
    async fn for_static_seed_configured_starts_workers_and_client_ready_once() {
        let ready_claims = Arc::new(AtomicUsize::new(0));
        let factory = {
            let ready_claims = Arc::clone(&ready_claims);
            Arc::new(
                move |_address: ServerAddress, control: AddressWorkerControl| {
                    let ready_claims = Arc::clone(&ready_claims);
                    async move {
                        if control.claim_client_ready_log() {
                            ready_claims.fetch_add(1, Ordering::SeqCst);
                        }
                        wait_for_shutdown(&control).await;
                        Ok(())
                    }
                    .boxed()
                },
            ) as AddressWorkerFactory
        };
        let mut controller = AddressController::for_static(factory);
        let view = controller.view();
        controller.seed_configured([address("a.example.test"), address("b.example.test")]);
        wait_until(|| view.worker_count() == 2).await;
        wait_until(|| ready_claims.load(Ordering::SeqCst) == 1).await;
        assert_eq!(ready_claims.load(Ordering::SeqCst), 1);

        controller.request_shutdown();
        controller
            .run()
            .await
            .expect("static run should drain on shutdown");
        assert_eq!(view.worker_count(), 0);
    }

    #[tokio::test]
    async fn for_managed_starts_with_no_workers_and_disables_client_ready() {
        let ready_claims = Arc::new(AtomicUsize::new(0));
        let factory = {
            let ready_claims = Arc::clone(&ready_claims);
            Arc::new(
                move |_address: ServerAddress, control: AddressWorkerControl| {
                    let ready_claims = Arc::clone(&ready_claims);
                    async move {
                        if control.claim_client_ready_log() {
                            ready_claims.fetch_add(1, Ordering::SeqCst);
                        }
                        wait_for_shutdown(&control).await;
                        Ok(())
                    }
                    .boxed()
                },
            ) as AddressWorkerFactory
        };
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let shutdown = controller.shutdown_handle();

        assert_eq!(controller.worker_count(), 0);
        assert_eq!(
            controller.assignment_convergence(),
            AssignmentConvergence::Converged
        );

        let runtime = tokio::spawn(async move { controller.run().await });
        apply_server_addresses(&mut adapter, &[address("a.example.test")]).await;
        wait_until(|| view.worker_count() == 1).await;
        assert_eq!(ready_claims.load(Ordering::SeqCst), 0);

        shutdown.request();
        runtime
            .await
            .expect("runtime join")
            .expect("managed run should drain");
    }

    #[tokio::test]
    async fn managed_apply_acks_before_worker_connects_and_marks_unconverged() {
        let (gate_tx, gate_rx) = oneshot::channel::<()>();
        let gate_rx = Arc::new(tokio::sync::Mutex::new(Some(gate_rx)));
        let factory = {
            let gate_rx = Arc::clone(&gate_rx);
            Arc::new(
                move |server_address: ServerAddress, control: AddressWorkerControl| {
                    let gate_rx = Arc::clone(&gate_rx);
                    async move {
                        if let Some(rx) = gate_rx.lock().await.take() {
                            let _ = rx.await;
                        }
                        let _ = control.observe_connected(&server_address);
                        wait_for_shutdown(&control).await;
                        Ok(())
                    }
                    .boxed()
                },
            ) as AddressWorkerFactory
        };
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });

        let apply = tokio::spawn(async move {
            adapter
                .apply(
                    crate::ClientAssignmentAdapter::parse_input(
                        serde_json::json!({ "server_addresses": ["tunnel.example.test"] }),
                        &ManagedSessionLimits::default(),
                    )
                    .expect("input should parse"),
                )
                .await
        });

        timeout(Duration::from_secs(2), apply)
            .await
            .expect("apply should ack without waiting for connect")
            .expect("apply join")
            .expect("apply ok");
        assert_eq!(view.worker_count(), 1);
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Unconverged
        );

        let _ = gate_tx.send(());
        shutdown.request();
        runtime
            .await
            .expect("runtime join")
            .expect("managed run should drain");
    }

    async fn register_convergence_gates(
        connect_gates: &Arc<tokio::sync::Mutex<HashMap<ServerAddress, watch::Sender<bool>>>>,
        disconnect_gates: &Arc<tokio::sync::Mutex<HashMap<ServerAddress, watch::Sender<bool>>>>,
        address: ServerAddress,
    ) -> (watch::Sender<bool>, watch::Sender<bool>) {
        let connect = register_connect_gate(connect_gates, address.clone()).await;
        let disconnect = register_connect_gate(disconnect_gates, address).await;
        (connect, disconnect)
    }

    #[tokio::test]
    async fn assignment_convergence_transitions_exclude_retiring() {
        let connect_gates = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let disconnect_gates = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let factory =
            convergence_gated_factory(Arc::clone(&connect_gates), Arc::clone(&disconnect_gates));
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });

        let a = address("a.example.test");
        let b = address("b.example.test");
        let c = address("c.example.test");
        let d = address("d.example.test");

        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Converged
        );

        let ab = parse_server_addresses(&[a.clone(), b.clone()]).await;
        let (connect_a, _) =
            register_convergence_gates(&connect_gates, &disconnect_gates, ab[0].clone()).await;
        let (connect_b, _) =
            register_convergence_gates(&connect_gates, &disconnect_gates, ab[1].clone()).await;
        apply_server_addresses(&mut adapter, &[a.clone(), b.clone()]).await;
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Unconverged
        );
        wait_until_or("workers for a and b spawned", || view.worker_count() == 2).await;

        connect_a.send(true).expect("connect a");
        wait_until_or("connect a -> partially converged", || {
            view.assignment_convergence() == AssignmentConvergence::PartiallyConverged
        })
        .await;

        connect_b.send(true).expect("connect b");
        wait_until_or("connect b -> converged", || {
            view.assignment_convergence() == AssignmentConvergence::Converged
        })
        .await;

        // Retiring: remove a connected address from assignment; convergence stays
        // Converged for the remaining connected Maintain worker.
        apply_server_addresses(&mut adapter, std::slice::from_ref(&b)).await;
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Converged
        );

        let cd = parse_server_addresses(&[c.clone(), d.clone()]).await;
        let (connect_c, disconnect_c) =
            register_convergence_gates(&connect_gates, &disconnect_gates, cd[0].clone()).await;
        let (connect_d, disconnect_d) =
            register_convergence_gates(&connect_gates, &disconnect_gates, cd[1].clone()).await;
        apply_server_addresses(&mut adapter, &[c.clone(), d.clone()]).await;
        assert_eq!(
            view.assignment_convergence(),
            AssignmentConvergence::Unconverged
        );

        connect_c.send(true).expect("connect c");
        wait_until_or("connect c -> partially converged", || {
            view.assignment_convergence() == AssignmentConvergence::PartiallyConverged
        })
        .await;

        connect_d.send(true).expect("connect d");
        wait_until_or("connect d -> converged", || {
            view.assignment_convergence() == AssignmentConvergence::Converged
        })
        .await;

        disconnect_c.send(true).expect("disconnect c");
        wait_until_or("disconnect c -> partially converged", || {
            view.assignment_convergence() == AssignmentConvergence::PartiallyConverged
        })
        .await;

        disconnect_d.send(true).expect("disconnect d");
        wait_until_or("disconnect d -> unconverged", || {
            view.assignment_convergence() == AssignmentConvergence::Unconverged
        })
        .await;

        shutdown.request();
        runtime.await.expect("runtime join").expect("drain");
    }

    #[tokio::test]
    async fn remove_establishing_worker_completes_cleanly_via_factory() {
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let factory = started_control_factory(started_tx);
        let mut controller = AddressController::for_static(factory);
        let target = address("tunnel.example.test");
        controller.seed_configured([target.clone()]);
        let control = started_rx.recv().await.expect("worker started");
        assert!(controller.remove(&target));
        wait_until(|| control.maintenance_intent() == MaintenanceIntent::Retire).await;
        controller
            .run()
            .await
            .expect("establishing worker should exit cleanly");
        assert_eq!(controller.worker_count(), 0);
    }

    #[tokio::test]
    async fn connected_remove_retires_and_re_adopt_restores_without_second_spawn() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (intent_tx, mut intent_rx) = mpsc::unbounded_channel();
        let factory = intent_echo_factory(intent_tx);
        // Count spawns via custom factory wrapper
        let factory = {
            let inner = factory;
            let starts = Arc::clone(&starts);
            Arc::new(
                move |address: ServerAddress, control: AddressWorkerControl| {
                    starts.fetch_add(1, Ordering::SeqCst);
                    inner(address, control)
                },
            ) as AddressWorkerFactory
        };
        let mut controller = AddressController::for_static(factory);
        let target = address("tunnel.example.test");
        controller.seed_configured([target.clone()]);
        wait_until(|| starts.load(Ordering::SeqCst) == 1).await;
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Maintain));

        assert!(controller.remove(&target));
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Retire));
        assert_eq!(starts.load(Ordering::SeqCst), 1);

        assert!(controller.re_adopt(&target));
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Maintain));
        assert_eq!(starts.load(Ordering::SeqCst), 1);

        controller.request_shutdown();
        controller.run().await.expect("drain");
    }

    #[tokio::test]
    async fn fatal_worker_makes_run_return_err() {
        let factory =
            Arc::new(|_address, _control| async { Err("worker exploded".to_owned()) }.boxed())
                as AddressWorkerFactory;
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let runtime = tokio::spawn(async move { controller.run().await });

        adapter
            .apply(
                crate::ClientAssignmentAdapter::parse_input(
                    serde_json::json!({ "server_addresses": ["tunnel.example.test"] }),
                    &ManagedSessionLimits::default(),
                )
                .expect("input should parse"),
            )
            .await
            .expect("apply acks before worker failure");

        let err = timeout(Duration::from_secs(2), runtime)
            .await
            .expect("runtime should end")
            .expect("join")
            .expect_err("fatal worker");
        assert_eq!(err, "worker exploded");
    }

    #[tokio::test]
    async fn shutdown_during_managed_run_drains_workers() {
        let factory = shutdown_waiting_factory();
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });

        adapter
            .apply(
                crate::ClientAssignmentAdapter::parse_input(
                    serde_json::json!({ "server_addresses": ["a.example.test", "b.example.test"] }),
                    &ManagedSessionLimits::default(),
                )
                .expect("input should parse"),
            )
            .await
            .expect("apply ok");
        wait_until(|| view.worker_count() == 2).await;

        shutdown.request();
        runtime
            .await
            .expect("runtime join")
            .expect("shutdown should drain managed workers");
        assert_eq!(view.worker_count(), 0);
    }

    #[tokio::test]
    async fn control_loss_retention_keeps_workers_on_last_assignment() {
        let starts = Arc::new(AtomicUsize::new(0));
        let (intent_tx, mut intent_rx) = mpsc::unbounded_channel();
        let factory = retention_tracking_factory(Arc::clone(&starts), intent_tx);
        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let view = controller.view();
        let shutdown = controller.shutdown_handle();
        let runtime = tokio::spawn(async move { controller.run().await });

        apply_server_addresses(&mut adapter, &[address("tunnel.example.test")]).await;
        wait_until(|| view.worker_count() == 1 && starts.load(Ordering::SeqCst) == 1).await;
        assert_eq!(intent_rx.recv().await, Some(MaintenanceIntent::Maintain));

        sleep(Duration::from_millis(100)).await;
        assert_eq!(view.worker_count(), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(
            intent_rx.try_recv().is_err(),
            "worker should stay on Maintain without further applies"
        );

        shutdown.request();
        runtime.await.expect("runtime join").expect("drain");
    }

    async fn wait_for_shutdown(control: &AddressWorkerControl) {
        crate::wait_for_shutdown(control).await;
    }

    async fn wait_until_retired_or_shutdown(control: &AddressWorkerControl) {
        let mut maintenance = control.subscribe_maintenance();
        let mut shutdown = control.subscribe_shutdown();
        loop {
            if control.shutdown_requested()
                || control.maintenance_intent() == MaintenanceIntent::Retire
            {
                return;
            }
            tokio::select! {
                changed = maintenance.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }
}
