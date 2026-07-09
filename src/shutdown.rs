use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownMode {
    Graceful,
    Fast,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownTransition {
    Started(ShutdownMode),
    EscalatedToFast,
    AlreadyStarted(ShutdownMode),
}

#[derive(Clone, Debug)]
pub struct OrderlyShutdown {
    inner: Arc<OrderlyShutdownInner>,
}

#[derive(Debug)]
struct OrderlyShutdownInner {
    state: AtomicU8,
    notify: Notify,
    graceful_shutdown_duration: Duration,
    quic_close_flush_duration: Duration,
}

impl OrderlyShutdown {
    pub fn new(graceful_shutdown_duration: Duration, quic_close_flush_duration: Duration) -> Self {
        Self {
            inner: Arc::new(OrderlyShutdownInner {
                state: AtomicU8::new(0),
                notify: Notify::new(),
                graceful_shutdown_duration,
                quic_close_flush_duration,
            }),
        }
    }

    pub fn begin_graceful(&self) -> ShutdownTransition {
        self.transition_to(1)
    }

    pub fn begin_fast(&self) -> ShutdownTransition {
        self.transition_to(2)
    }

    pub fn mode(&self) -> Option<ShutdownMode> {
        match self.inner.state.load(Ordering::SeqCst) {
            1 => Some(ShutdownMode::Graceful),
            2 => Some(ShutdownMode::Fast),
            _ => None,
        }
    }

    pub fn graceful_shutdown_duration(&self) -> Duration {
        self.inner.graceful_shutdown_duration
    }

    pub fn quic_close_flush_duration(&self) -> Duration {
        self.inner.quic_close_flush_duration
    }

    pub async fn wait_started(&self) -> ShutdownMode {
        loop {
            let notified = self.inner.notify.notified();
            if let Some(mode) = self.mode() {
                return mode;
            }
            notified.await;
        }
    }

    pub async fn wait_for_fast(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if matches!(self.mode(), Some(ShutdownMode::Fast)) {
                return;
            }
            notified.await;
        }
    }

    fn transition_to(&self, new_state: u8) -> ShutdownTransition {
        loop {
            let current = self.inner.state.load(Ordering::SeqCst);
            if current >= new_state {
                return ShutdownTransition::AlreadyStarted(mode_from_state(current));
            }
            if self
                .inner
                .state
                .compare_exchange(current, new_state, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.inner.notify.notify_waiters();
                return match (current, new_state) {
                    (0, 1) => ShutdownTransition::Started(ShutdownMode::Graceful),
                    (0, 2) => ShutdownTransition::Started(ShutdownMode::Fast),
                    (1, 2) => ShutdownTransition::EscalatedToFast,
                    _ => unreachable!("only ordered shutdown transitions are valid"),
                };
            }
        }
    }
}

fn mode_from_state(state: u8) -> ShutdownMode {
    match state {
        1 => ShutdownMode::Graceful,
        2 => ShutdownMode::Fast,
        _ => unreachable!("shutdown mode requested before shutdown started"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::{OrderlyShutdown, ShutdownMode, ShutdownTransition};

    #[tokio::test]
    async fn wait_started_returns_after_graceful_shutdown_begins() {
        let shutdown = OrderlyShutdown::new(Duration::from_millis(25), Duration::from_millis(5));
        let waiter = shutdown.clone();

        let wait_task = tokio::spawn(async move { waiter.wait_started().await });

        assert_eq!(
            shutdown.begin_graceful(),
            ShutdownTransition::Started(ShutdownMode::Graceful)
        );

        let mode = timeout(Duration::from_secs(1), wait_task)
            .await
            .expect("wait task should complete after shutdown begins")
            .expect("wait task should not panic");
        assert_eq!(mode, ShutdownMode::Graceful);
    }

    #[tokio::test]
    async fn wait_for_fast_returns_after_escalation() {
        let shutdown = OrderlyShutdown::new(Duration::from_millis(25), Duration::from_millis(5));
        let waiter = shutdown.clone();

        shutdown.begin_graceful();
        let wait_task = tokio::spawn(async move {
            waiter.wait_for_fast().await;
        });

        assert_eq!(shutdown.begin_fast(), ShutdownTransition::EscalatedToFast);

        timeout(Duration::from_secs(1), wait_task)
            .await
            .expect("wait task should complete after escalation")
            .expect("wait task should not panic");
    }

    #[tokio::test]
    async fn wait_started_returns_immediately_after_shutdown_already_began() {
        let shutdown = OrderlyShutdown::new(Duration::from_millis(25), Duration::from_millis(5));

        shutdown.begin_fast();

        let mode = timeout(Duration::from_secs(1), shutdown.wait_started())
            .await
            .expect("wait should not block after shutdown already began");
        assert_eq!(mode, ShutdownMode::Fast);
    }

    #[test]
    fn transitions_are_idempotent_and_keep_configured_durations() {
        let shutdown = OrderlyShutdown::new(Duration::from_secs(60), Duration::from_millis(100));

        assert_eq!(
            shutdown.graceful_shutdown_duration(),
            Duration::from_secs(60)
        );
        assert_eq!(
            shutdown.quic_close_flush_duration(),
            Duration::from_millis(100)
        );
        assert_eq!(
            shutdown.begin_graceful(),
            ShutdownTransition::Started(ShutdownMode::Graceful)
        );
        assert_eq!(
            shutdown.begin_graceful(),
            ShutdownTransition::AlreadyStarted(ShutdownMode::Graceful)
        );
        assert_eq!(shutdown.begin_fast(), ShutdownTransition::EscalatedToFast);
        assert_eq!(
            shutdown.begin_fast(),
            ShutdownTransition::AlreadyStarted(ShutdownMode::Fast)
        );
    }
}
