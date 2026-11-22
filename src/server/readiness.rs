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
    certificate: Option<tokio::sync::watch::Receiver<bool>>,
}

impl ReadinessGate {
    #[cfg(test)]
    pub(crate) fn new(initially_ready: bool) -> Self {
        Self::with_certificate(initially_ready, None)
    }

    pub(crate) fn with_certificate(
        initially_ready: bool,
        certificate: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(initially_ready)),
            notify: Arc::new(Notify::new()),
            certificate,
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
            && self
                .certificate
                .as_ref()
                .is_none_or(|certificate| *certificate.borrow())
    }

    pub(crate) async fn wait_until_ready(&self) {
        let mut certificate = self.certificate.clone();
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
            tokio::select! {
                _ = notified => {},
                _ = async { match certificate.as_mut() { Some(certificate) => { let _ = certificate.changed().await; }, None => std::future::pending().await } } => {}
            }
        }
    }

    /// Report readiness to `on_change` now and after every possible change. Never returns.
    pub(crate) async fn watch(&self, mut on_change: impl FnMut(bool)) {
        let mut certificate = self.certificate.clone();
        loop {
            // Register before reading so a concurrent mark cannot be missed.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            on_change(self.is_ready());
            let certificate_changed = async {
                match certificate.as_mut() {
                    Some(receiver) => receiver.changed().await.is_ok(),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = &mut notified => {}
                open = certificate_changed => if !open {
                    // The controller is gone; its last value stays authoritative.
                    certificate = None;
                }
            }
        }
    }

    pub(crate) fn mark_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(crate) fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::SeqCst);
        self.notify.notify_waiters();
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
    async fn watch_reports_initial_state_and_every_mark() {
        let gate = ReadinessGate::new(false);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let watcher_gate = gate.clone();
        let watcher = tokio::spawn(async move {
            watcher_gate
                .watch(move |ready| {
                    let _ = sender.send(ready);
                })
                .await;
        });
        assert_eq!(receiver.recv().await, Some(false));
        gate.mark_ready();
        assert_eq!(receiver.recv().await, Some(true));
        gate.mark_not_ready();
        assert_eq!(receiver.recv().await, Some(false));
        watcher.abort();
    }

    #[tokio::test]
    async fn watch_follows_certificate_serving_state() {
        let (certificate, receiver_side) = tokio::sync::watch::channel(true);
        let gate = ReadinessGate::with_certificate(true, Some(receiver_side));
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let watcher_gate = gate.clone();
        let watcher = tokio::spawn(async move {
            watcher_gate
                .watch(move |ready| {
                    let _ = sender.send(ready);
                })
                .await;
        });
        assert_eq!(receiver.recv().await, Some(true));
        certificate.send_replace(false);
        assert_eq!(receiver.recv().await, Some(false));
        drop(certificate);
        watcher.abort();
    }

    #[tokio::test]
    async fn wait_until_ready_returns_immediately_when_already_ready() {
        let gate = ReadinessGate::new(true);
        tokio::time::timeout(Duration::from_millis(50), gate.wait_until_ready())
            .await
            .expect("already-ready gate must not block");
    }
}
