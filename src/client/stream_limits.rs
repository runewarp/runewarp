use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::MAX_SERVER_OPENED_BIDI_STREAMS;
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
            // Per-connection QUIC credit must not exceed this aggregate Client bound.
            max_stream_handlers: MAX_SERVER_OPENED_BIDI_STREAMS as usize,
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

    pub(crate) fn try_admit_handler(&self) -> Result<OwnedSemaphorePermit, ()> {
        match self.handlers.clone().try_acquire_owned() {
            Ok(permit) => {
                self.note_recovery();
                Ok(permit)
            }
            Err(_) => {
                self.note_saturation();
                Err(())
            }
        }
    }

    fn note_saturation(&self) {
        let now = Instant::now();
        *self
            .saturated
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
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
        runtime_log::client_stream_handler_saturated(
            self.limits.max_stream_handlers,
            self.limits.max_stream_handlers,
        );
    }

    fn note_recovery(&self) {
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
    use std::sync::Arc;

    use super::{ClientStreamBudget, ClientStreamLimits};
    use crate::MAX_SERVER_OPENED_BIDI_STREAMS;

    #[test]
    fn production_limits_keep_quic_credit_within_handler_capacity() {
        let limits = ClientStreamLimits::default();
        assert_eq!(
            limits.max_stream_handlers,
            MAX_SERVER_OPENED_BIDI_STREAMS as usize
        );
        assert!(u32::try_from(limits.max_stream_handlers).is_ok());
        assert!(MAX_SERVER_OPENED_BIDI_STREAMS <= limits.max_stream_handlers as u32);
    }

    #[test]
    fn stream_handler_budget_releases_capacity_after_completion() {
        let budget = ClientStreamBudget::new(ClientStreamLimits {
            max_stream_handlers: 1,
            ..ClientStreamLimits::for_test()
        });
        let permit = budget
            .try_admit_handler()
            .expect("first handler should fit");
        assert!(budget.try_admit_handler().is_err());
        drop(permit);
        assert!(budget.try_admit_handler().is_ok());
    }

    #[test]
    fn shared_budget_bounds_handlers_across_multiple_tunnel_connections() {
        let budget = Arc::new(ClientStreamBudget::new(ClientStreamLimits {
            max_stream_handlers: 1,
            ..ClientStreamLimits::for_test()
        }));
        let first_connection_budget = Arc::clone(&budget);
        let second_connection_budget = Arc::clone(&budget);

        let first = first_connection_budget
            .try_admit_handler()
            .expect("first connection handler should fit");
        assert!(
            second_connection_budget.try_admit_handler().is_err(),
            "second Tunnel connection must share the Client-instance aggregate"
        );
        drop(first);
        assert!(second_connection_budget.try_admit_handler().is_ok());
    }
}
