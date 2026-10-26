//! Permit-backed QUIC Visitor credit on one Client connection.

use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use super::MAX_IDLE_VISITOR_CREDIT;
use super::stream::StreamResource;

struct State {
    idle: Vec<OwnedSemaphorePermit>,
    /// Active handler permits plus idle permits. All Quinn limit changes use this mutex.
    held: usize,
    maintaining: bool,
    closed: bool,
}

pub(super) struct VisitorCredits {
    connection: quinn::Connection,
    budget: Arc<Semaphore>,
    state: Mutex<State>,
    active: watch::Sender<usize>,
    observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    #[cfg(test)]
    pub(super) guard_rejections: std::sync::atomic::AtomicUsize,
}

impl VisitorCredits {
    pub(super) fn new(
        connection: quinn::Connection,
        budget: Arc<Semaphore>,
        observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            connection,
            budget,
            state: Mutex::new(State {
                idle: Vec::new(),
                held: 0,
                maintaining: true,
                closed: false,
            }),
            active: watch::Sender::new(0),
            observer,
            #[cfg(test)]
            guard_rejections: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn set_limit(&self, state: &State) {
        let held = quinn::VarInt::from_u64(state.held as u64)
            .expect("held permits fit QUIC stream credit");
        self.connection.set_max_concurrent_bi_streams(held);
        // Quinn 0.11.11 / quinn-proto 0.11.19 batches MAX_STREAMS increments at
        // configured concurrency / 8. Setting zero queues any allocated, unsent
        // credit with a zero threshold; restoring held preserves our capacity.
        // Each call takes Quinn's own lock separately. Its driver can run between
        // calls: zero cannot allocate replacement credit, and restoring can only
        // allocate up to held. Already-sent credit is irrevocable, so assign's
        // no-wait guard is still required for FIN/ACK/EOF before handler Drop.
        // The controller mutex serializes all three calls against permit updates.
        // See ADR 0007 and quinn-rs/quinn#1517, comment 1474555820.
        self.connection.set_max_concurrent_bi_streams(0_u8.into());
        self.connection.set_max_concurrent_bi_streams(held);
    }

    pub(super) fn needs_idle(&self) -> bool {
        let state = self.state();
        state.maintaining && state.idle.len() < MAX_IDLE_VISITOR_CREDIT
    }

    pub(super) fn budget(&self) -> Arc<Semaphore> {
        self.budget.clone()
    }

    pub(super) fn note_budget(&self, acquired: bool) {
        if let Some(observer) = &self.observer {
            observer(acquired);
        }
    }

    pub(super) fn offer(&self, permit: OwnedSemaphorePermit) {
        let mut state = self.state();
        if !state.maintaining {
            return;
        }
        state.idle.push(permit);
        state.held += 1;
        self.set_limit(&state);
        drop(state);
        self.note_budget(true);
    }

    /// Transfer one already-reserved permit to a handler. Irrevocable credit can outlive a
    /// finished QUIC stream while its handler retains capacity; try the budget once in that case.
    pub(super) fn assign(self: &Arc<Self>) -> Option<Arc<dyn StreamResource>> {
        let mut state = self.state();
        if state.closed {
            return None;
        }
        let permit = if let Some(permit) = state.idle.pop() {
            permit
        } else {
            match self.budget.clone().try_acquire_owned() {
                Ok(permit) => {
                    state.held += 1;
                    self.set_limit(&state);
                    permit
                }
                Err(_) => {
                    #[cfg(test)]
                    crate::capacity_benchmark::GUARD_RESETS
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    #[cfg(test)]
                    self.guard_rejections
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    drop(state);
                    self.note_budget(false);
                    return None;
                }
            }
        };
        self.active.send_modify(|active| *active += 1);
        Some(Arc::new(VisitorPermit {
            credits: self.clone(),
            _permit: permit,
        }))
    }

    /// Wait for actual application resource release, rather than transport FIN enqueueing.
    pub(super) async fn drained(&self) {
        let _ = self
            .active
            .subscribe()
            .wait_for(|active| *active == 0)
            .await;
    }

    /// DRAIN ends idle maintenance while retaining intake and active/queued Visitor leases.
    /// GOAWAY alone cannot do this: a committed stream can still need its reserved permit.
    pub(super) fn stop_idle(&self) {
        self.release_idle(&mut self.state());
    }

    fn release_idle(&self, state: &mut State) {
        state.maintaining = false;
        state.held -= state.idle.len();
        // Lower the target before releasing actual capacity to another connection.
        self.set_limit(state);
        state.idle.clear();
    }

    pub(super) fn close(&self) {
        let mut state = self.state();
        state.closed = true;
        self.release_idle(&mut state);
    }

    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize) {
        let state = self.state();
        (state.held - state.idle.len(), state.idle.len())
    }
}

struct VisitorPermit {
    credits: Arc<VisitorCredits>,
    // Retained through both transport-handle drops, after before_drop lowers the limit.
    _permit: OwnedSemaphorePermit,
}

impl StreamResource for VisitorPermit {
    fn before_drop(&self) {
        let mut state = self.credits.state();
        state.held -= 1;
        self.credits.set_limit(&state);
    }
}

impl Drop for VisitorPermit {
    fn drop(&mut self) {
        self.credits.active.send_modify(|active| *active -= 1);
    }
}

/// Abort and connection-loss cleanup releases idle credit even while handlers retain the pool.
pub(super) struct CreditMaintenance(pub(super) Arc<VisitorCredits>);
impl Drop for CreditMaintenance {
    fn drop(&mut self) {
        self.0.close();
    }
}
