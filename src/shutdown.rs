use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Clone, Debug)]
pub struct GracefulShutdown {
    inner: Arc<GracefulShutdownInner>,
}

#[derive(Debug)]
struct GracefulShutdownInner {
    started: AtomicBool,
    notify: Notify,
    grace_period: Duration,
}

impl GracefulShutdown {
    pub fn new(grace_period: Duration) -> Self {
        Self {
            inner: Arc::new(GracefulShutdownInner {
                started: AtomicBool::new(false),
                notify: Notify::new(),
                grace_period,
            }),
        }
    }

    pub fn begin(&self) -> bool {
        let began = self
            .inner
            .started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if began {
            self.inner.notify.notify_waiters();
        }
        began
    }

    pub fn is_started(&self) -> bool {
        self.inner.started.load(Ordering::SeqCst)
    }

    pub fn grace_period(&self) -> Duration {
        self.inner.grace_period
    }

    pub async fn wait(&self) {
        if self.is_started() {
            return;
        }
        loop {
            let notified = self.inner.notify.notified();
            if self.is_started() {
                return;
            }
            notified.await;
            if self.is_started() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::GracefulShutdown;

    #[tokio::test]
    async fn wait_returns_after_shutdown_begins() {
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));
        let waiter = shutdown.clone();

        let wait_task = tokio::spawn(async move {
            waiter.wait().await;
        });

        shutdown.begin();

        timeout(Duration::from_secs(1), wait_task)
            .await
            .expect("wait task should complete after shutdown begins")
            .expect("wait task should not panic");
    }

    #[test]
    fn begin_is_idempotent_and_keeps_grace_period() {
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));

        assert_eq!(shutdown.grace_period(), Duration::from_millis(25));
        assert!(shutdown.begin());
        assert!(!shutdown.begin());
        assert!(shutdown.is_started());
    }
}
