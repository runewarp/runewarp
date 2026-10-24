use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::runtime_log;

const SATURATION_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Fixed Client routed-stream setup policy. Not operator-configurable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientStreamLimits {
    pub(crate) max_stream_handlers: usize,
    pub(crate) client_hello_timeout: Duration,
    pub(crate) backend_connect_timeout: Duration,
    pub(crate) initial_backend_write_timeout: Duration,
    pub(crate) terminate_handshake_timeout: Duration,
    pub(crate) acme_challenge_handshake_timeout: Duration,
}

impl Default for ClientStreamLimits {
    fn default() -> Self {
        Self {
            // Idle and assigned receive slots share this Client-instance bound.
            max_stream_handlers: 1024,
            client_hello_timeout: Duration::from_secs(5),
            backend_connect_timeout: Duration::from_secs(5),
            initial_backend_write_timeout: Duration::from_secs(5),
            terminate_handshake_timeout: Duration::from_secs(5),
            acme_challenge_handshake_timeout: Duration::from_secs(5),
        }
    }
}

impl ClientStreamLimits {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            max_stream_handlers: 2,
            client_hello_timeout: Duration::from_millis(50),
            backend_connect_timeout: Duration::from_millis(50),
            initial_backend_write_timeout: Duration::from_millis(50),
            terminate_handshake_timeout: Duration::from_millis(50),
            acme_challenge_handshake_timeout: Duration::from_millis(50),
        }
    }
}

/// Client-instance aggregate bound shared by every live Tunnel connection.
#[derive(Clone)]
pub(crate) struct ClientStreamBudget {
    limits: ClientStreamLimits,
    handlers: Arc<Semaphore>,
    last_saturation_log: Arc<Mutex<Option<Instant>>>,
    saturated: Arc<Mutex<bool>>,
}

impl ClientStreamBudget {
    pub(crate) fn new(limits: ClientStreamLimits) -> Self {
        Self {
            handlers: Arc::new(Semaphore::new(limits.max_stream_handlers)),
            last_saturation_log: Arc::new(Mutex::new(None)),
            saturated: Arc::new(Mutex::new(false)),
            limits,
        }
    }

    pub(crate) fn limits(&self) -> ClientStreamLimits {
        self.limits
    }

    pub(crate) fn semaphore(&self) -> Arc<Semaphore> {
        self.handlers.clone()
    }

    pub(crate) fn note_saturation(&self) {
        let now = Instant::now();
        let mut last_logged = self
            .last_saturation_log
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last_logged
            .as_ref()
            .is_some_and(|last| now.saturating_duration_since(*last) < SATURATION_LOG_INTERVAL)
        {
            return;
        }
        *last_logged = Some(now);
        *self
            .saturated
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        runtime_log::client_stream_handler_saturated(
            self.limits.max_stream_handlers,
            self.limits.max_stream_handlers,
        );
    }

    pub(crate) fn note_recovery(&self) {
        let was_saturated = std::mem::replace(
            &mut *self
                .saturated
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            false,
        );
        if was_saturated {
            runtime_log::client_stream_handler_recovered();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientStreamBudget, ClientStreamLimits};

    #[test]
    fn production_limits_bound_idle_and_assigned_receive_slots() {
        let limits = ClientStreamLimits::default();
        assert_eq!(limits.max_stream_handlers, 1024);
        assert!(u32::try_from(limits.max_stream_handlers).is_ok());
    }

    #[test]
    fn recovery_is_armed_only_by_an_emitted_saturation_warning() {
        let budget = ClientStreamBudget::new(ClientStreamLimits::for_test());
        budget.note_saturation();
        assert!(*budget.saturated.lock().expect("saturation state"));
        budget.note_recovery();
        assert!(!*budget.saturated.lock().expect("saturation state"));

        // A suppressed warning during continued permit churn must not arm another recovery.
        budget.note_saturation();
        assert!(!*budget.saturated.lock().expect("saturation state"));
        budget.note_recovery();
        assert!(!*budget.saturated.lock().expect("saturation state"));
    }
}
