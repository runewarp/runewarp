//! Probe-only Server readiness gate.
//!
//! Marks when the Server should start accepting readiness probes. The listener
//! task owns port reservation and emits `server_readiness_gained` only after
//! `listen()` succeeds. Authorization replacement opens the gate on first
//! successful Managed apply.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// Shared gate for the probe-only readiness listener.
#[derive(Clone, Debug)]
pub(crate) struct ReadinessGate {
    ready: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ReadinessGate {
    pub(crate) fn new(initially_ready: bool) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(initially_ready)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub(crate) async fn wait_until_ready(&self) {
        loop {
            if self.is_ready() {
                return;
            }
            // Subscribe before re-checking so mark_ready between the check and
            // await cannot be missed.
            let notified = self.notify.notified();
            if self.is_ready() {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn mark_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(crate) fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::ReadinessGate;

    #[tokio::test]
    async fn wait_until_ready_observes_mark_ready_without_missing_notify() {
        let gate = ReadinessGate::new(false);
        let started = Arc::new(Notify::new());
        let waiter_started = started.clone();
        let waiter_gate = gate.clone();
        let waiter = tokio::spawn(async move {
            waiter_started.notify_one();
            waiter_gate.wait_until_ready().await;
        });

        started.notified().await;
        // Yield so the waiter reaches notified().await before mark_ready.
        tokio::task::yield_now().await;
        gate.mark_ready();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("wait_until_ready should observe mark_ready")
            .expect("waiter task should finish");
        assert!(gate.is_ready());
    }

    #[tokio::test]
    async fn wait_until_ready_returns_immediately_when_already_ready() {
        let gate = ReadinessGate::new(true);
        tokio::time::timeout(Duration::from_millis(50), gate.wait_until_ready())
            .await
            .expect("already-ready gate must not block");
    }
}
