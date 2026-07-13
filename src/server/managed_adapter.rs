//! Server role adapter for Managed-session authorization applies.
//!
//! Prepares a complete candidate beside the live snapshot, commits it through
//! the Tunnel registry (atomic swap plus local revocation dispatch), and opens
//! Server readiness after the first successful apply.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use tokio::sync::Notify;

use crate::managed_session::{ApplyError, RoleAdapter, ServerManagedInput, parse_server_input};
use crate::{ServerHostname, ServerTunnelConfig};

use super::tunnel_registry::TunnelRegistry;

/// Shared gate for the probe-only readiness listener.
///
/// Marks when the Server should start accepting readiness probes. The listener
/// task owns port reservation and emits `server_readiness_gained` only after
/// `listen()` succeeds.
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

/// Applies validated Server Managed-session input onto live authorization state.
#[derive(Clone)]
pub struct ServerAuthorizationAdapter {
    server_hostname: ServerHostname,
    registry: TunnelRegistry,
    readiness: Option<ReadinessGate>,
    applied_once: Arc<AtomicBool>,
}

impl ServerAuthorizationAdapter {
    pub(crate) fn new(
        server_hostname: ServerHostname,
        registry: TunnelRegistry,
        readiness: Option<ReadinessGate>,
    ) -> Self {
        Self {
            server_hostname,
            registry,
            readiness,
            applied_once: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn commit_tunnels(&self, tunnels: &[ServerTunnelConfig]) -> Result<(), ApplyError> {
        let prepared = self
            .registry
            .authorization()
            .prepare(&self.server_hostname, tunnels)
            .map_err(|error| ApplyError::new(error.to_string()))?;
        // Mark applied after the atomic swap and local revocation dispatch.
        // Do not await peer acknowledgment or remote closure.
        let _dispatch = self.registry.commit_authorization(prepared).await;
        if !self.applied_once.swap(true, Ordering::SeqCst)
            && let Some(readiness) = self.readiness.as_ref()
        {
            readiness.mark_ready();
        }
        Ok(())
    }
}

impl RoleAdapter for ServerAuthorizationAdapter {
    type Input = ServerManagedInput;

    fn parse_input(input: &Value) -> Result<Self::Input, crate::managed_session::InputError> {
        parse_server_input(input)
    }

    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        self.commit_tunnels(&input.tunnels).await
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
