use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use quinn::Connection;
use tokio::sync::RwLock;

#[derive(Clone)]
struct ActiveClientInstance {
    generation: u64,
    connection: Connection,
}

#[derive(Clone)]
pub(crate) struct ActiveClientSlot {
    active_client: Arc<RwLock<Option<ActiveClientInstance>>>,
    next_generation: Arc<AtomicU64>,
}

impl ActiveClientSlot {
    pub(crate) fn new() -> Self {
        Self {
            active_client: Arc::new(RwLock::new(None)),
            next_generation: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) async fn current_connection(&self) -> Option<Connection> {
        self.active_client
            .read()
            .await
            .as_ref()
            .map(|active_client| active_client.connection.clone())
    }

    pub(crate) async fn register(&self, connection: Connection) {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let (installed, previous) = {
            let mut active_client = self.active_client.write().await;
            let current_generation = active_client.as_ref().map(|active| active.generation);
            if !incoming_generation_supersedes(current_generation, generation) {
                (false, None)
            } else {
                (
                    true,
                    active_client.replace(ActiveClientInstance {
                        generation,
                        connection: connection.clone(),
                    }),
                )
            }
        };
        if !installed {
            connection.close(0_u32.into(), b"replaced");
            return;
        }

        if let Some(previous) = previous {
            previous.connection.close(0_u32.into(), b"replaced");
        }

        let active_client = self.active_client.clone();
        tokio::spawn(async move {
            let _ = connection.closed().await;
            let mut active_client_guard = active_client.write().await;
            if active_client_guard
                .as_ref()
                .is_some_and(|active| active.generation == generation)
            {
                *active_client_guard = None;
            }
        });
    }
}

fn incoming_generation_supersedes(
    current_generation: Option<u64>,
    incoming_generation: u64,
) -> bool {
    current_generation.is_none_or(|current_generation| incoming_generation > current_generation)
}

#[cfg(test)]
mod tests {
    use super::incoming_generation_supersedes;

    #[test]
    fn newer_generations_supersede_older_active_connections() {
        assert!(incoming_generation_supersedes(None, 1));
        assert!(incoming_generation_supersedes(Some(1), 2));
    }

    #[test]
    fn stale_generations_do_not_replace_newer_active_connections() {
        assert!(!incoming_generation_supersedes(Some(2), 1));
        assert!(!incoming_generation_supersedes(Some(2), 2));
    }
}
