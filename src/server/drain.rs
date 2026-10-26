//! One-way Managed drain for a running Server.
//!
//! Control asks a Managed Server to drain with `drain: true` in its input. Drain is permanent for
//! the process: the Server runs its bounded graceful drain without exiting, so it keeps applying
//! input and reporting state until the process is terminated.

use std::sync::Arc;

use tokio::sync::watch;

/// Shared drain flag set by the Managed adapter and followed by the Server runtime.
#[derive(Clone, Debug)]
pub(crate) struct ServerDrain {
    started: Arc<watch::Sender<bool>>,
}

impl ServerDrain {
    pub(crate) fn new() -> Self {
        Self {
            started: Arc::new(watch::Sender::new(false)),
        }
    }

    /// Start draining. Later calls change nothing; drain never resumes serving.
    pub(crate) fn begin(&self) {
        self.started
            .send_if_modified(|started| !std::mem::replace(started, true));
    }

    pub(crate) fn is_draining(&self) -> bool {
        *self.started.borrow()
    }

    /// Resolve once drain has started.
    pub(crate) async fn wait(&self) {
        let mut started = self.started.subscribe();
        let _ = started.wait_for(|started| *started).await;
    }
}

#[cfg(test)]
mod tests {
    use super::ServerDrain;

    #[tokio::test]
    async fn drain_is_one_way() {
        let drain = ServerDrain::new();
        assert!(!drain.is_draining());
        drain.begin();
        drain.begin();
        assert!(drain.is_draining());
        drain.wait().await;
    }
}
