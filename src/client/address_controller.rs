//! Client address controller owning one worker per normalized Server address.
//!
//! Static Client startup seeds the controller from configured Server addresses.
//! Explicit add / remove / re-adopt operations replace maintenance intent without
//! process restart, while preventing duplicate active dialing loops for one
//! normalized address. Managed-session reconciliation drives the same seam through
//! [`crate::ClientAssignmentAdapter`].

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::watch;

use crate::ServerAddress;

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
    /// Managed mode disables this so assignment convergence replaces the static
    /// one-shot Client-ready event.
    pub fn claim_client_ready_log(&self) -> bool {
        self.client_ready_enabled && !self.ready_logged.swap(true, Ordering::SeqCst)
    }
}

struct WorkerSlot {
    maintenance_tx: watch::Sender<MaintenanceIntent>,
    generation: u64,
}

type RunningWorker = BoxFuture<'static, (ServerAddress, u64, Result<(), String>)>;

/// Owns address-worker lifecycle keyed by normalized Server address.
pub struct AddressController {
    workers: HashMap<ServerAddress, WorkerSlot>,
    running: FuturesUnordered<RunningWorker>,
    ready_logged: Arc<AtomicBool>,
    client_ready_enabled: bool,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    next_generation: u64,
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
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            workers: HashMap::new(),
            running: FuturesUnordered::new(),
            ready_logged: Arc::new(AtomicBool::new(false)),
            client_ready_enabled: true,
            shutdown_tx,
            shutdown_rx,
            next_generation: 1,
        }
    }

    /// Disable the static one-shot Client-ready log for managed assignment mode.
    pub fn disable_client_ready_log(&mut self) {
        self.client_ready_enabled = false;
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len()
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
        }

        self.spawn_worker(address, spawn);
        true
    }

    /// Stop maintaining `address`.
    ///
    /// Establishing / reconnecting workers should exit after observing
    /// [`MaintenanceIntent::Retire`]. Connected workers stay Retiring until remote
    /// closure or process shutdown. Returns `false` when no live worker exists.
    pub fn remove(&mut self, address: &ServerAddress) -> bool {
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
    pub fn re_adopt(&mut self, address: &ServerAddress) -> bool {
        let Some(slot) = self.workers.get(address) else {
            return false;
        };
        if !slot.is_live() || *slot.maintenance_tx.borrow() != MaintenanceIntent::Retire {
            return false;
        }
        let _ = slot.maintenance_tx.send(MaintenanceIntent::Maintain);
        true
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
                    // Stale Retiring slot: fall through to spawn below.
                    self.workers.remove(&address);
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
            client_ready_enabled: self.client_ready_enabled,
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
    }
}

impl WorkerSlot {
    fn is_live(&self) -> bool {
        self.maintenance_tx.receiver_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{sleep, timeout};

    use super::{AddressController, AddressWorkerControl, MaintenanceIntent};
    use crate::ServerAddress;

    fn address(value: &str) -> ServerAddress {
        ServerAddress::parse(value).expect("test server address should parse")
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        timeout(Duration::from_secs(2), async {
            loop {
                if predicate() {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("condition should become true");
    }

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
                    // Drop control so the maintenance watch closes while the slot remains.
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

        // Workers stay alive across Retire so remove/readopt can target a live slot,
        // matching connected retirement rather than establishing cancellation.
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
                // Simulate reconnect backoff interrupted by Retire, then re-adopt.
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
                            // Stay alive across Retire so re-adopt can restore Maintain.
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

        // Rapid remove / re-add / remove races must keep a single live worker slot.
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

    async fn wait_for_shutdown(control: &AddressWorkerControl) {
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
