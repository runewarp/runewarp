//! Server role adapter for Managed-session authorization applies.
//!
//! Supplies validated Server input to one Authorization replacement operation
//! and observes success or failure. Prepare, commit, pool realignment,
//! selective revocation, and first-success readiness live behind that seam.
//! A successful apply then publishes the input's replacement hint to every
//! Tunnel event stream, and acknowledgments report this runtime's generation.

use serde_json::Value;

use std::sync::Arc;

use futures_util::future::BoxFuture;
use tokio::sync::Notify;

use crate::managed_session::{
    ApplyError, ManagedSessionLimits, RoleAdapter, RoleState, ServerManagedInput, StateFields,
    parse_server_input,
};
use crate::tunnel::ServerTunnelEvents;
use crate::{ServerHostname, ServerTunnelConfig};

use super::drain::ServerDrain;
use super::tunnel_registry::TunnelRegistry;

/// Applies validated Server Managed-session input onto live authorization state.
#[derive(Clone)]
pub struct ServerAuthorizationAdapter {
    server_hostname: ServerHostname,
    registry: TunnelRegistry,
    tunnel_events: ServerTunnelEvents,
    drain: ServerDrain,
}

impl ServerAuthorizationAdapter {
    pub(crate) fn new(
        server_hostname: ServerHostname,
        registry: TunnelRegistry,
        tunnel_events: ServerTunnelEvents,
        drain: ServerDrain,
    ) -> Self {
        Self {
            server_hostname,
            registry,
            tunnel_events,
            drain,
        }
    }

    /// Runtime generation this Server reports in its state documents.
    pub fn server_generation(&self) -> crate::tunnel::ServerRuntimeGeneration {
        self.tunnel_events.server_generation()
    }

    async fn replace_authorization(
        &self,
        tunnels: &[ServerTunnelConfig],
    ) -> Result<(), ApplyError> {
        self.registry
            .replace_authorization(&self.server_hostname, tunnels)
            .await
            .map(|_| ())
            .map_err(|error| ApplyError::new(error.to_string()))
    }
}

impl RoleAdapter for ServerAuthorizationAdapter {
    type Input = ServerManagedInput;

    fn parse_input(
        input: Value,
        limits: &ManagedSessionLimits,
    ) -> Result<Self::Input, crate::managed_session::InputError> {
        parse_server_input(input, limits)
    }

    /// Replace authorization, publish the hint, and start a requested drain before the revision
    /// is reported. The hint and drain flag were validated with the rest of the input, so a
    /// rejected input changes none of them. An input without `drain` never ends a drain.
    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        self.replace_authorization(&input.tunnels).await?;
        self.tunnel_events
            .set_replacement_generation(input.replacement_generation);
        if input.drain {
            self.drain.begin();
        }
        Ok(())
    }

    fn role_state(&self) -> Option<Arc<dyn RoleState>> {
        Some(Arc::new(ServerReportedState {
            generation: self.tunnel_events.server_generation().to_string(),
            drain: self.drain.clone(),
            registry: self.registry.clone(),
            changed: self.registry.reported_state_changed(),
        }))
    }
}

/// Facts a Managed Server reports: its generation, whether it drains, open Tunnel connections per
/// Tunnel ID, and in-flight Visitors. Quiescence is `draining` with zero `visitors`.
struct ServerReportedState {
    generation: String,
    drain: ServerDrain,
    registry: TunnelRegistry,
    changed: Arc<Notify>,
}

impl RoleState for ServerReportedState {
    fn fields(&self) -> BoxFuture<'_, StateFields> {
        Box::pin(async move {
            let tunnels: serde_json::Map<String, Value> = self
                .registry
                .reported_tunnel_connections()
                .await
                .into_iter()
                .map(|(id, count)| (id, Value::from(count)))
                .collect();
            vec![
                ("generation", Value::from(self.generation.as_str())),
                ("draining", Value::from(self.drain.is_draining())),
                ("tunnels", Value::Object(tunnels)),
                (
                    "visitors",
                    Value::from(self.registry.in_flight_visitor_count()),
                ),
            ]
        })
    }

    fn changed(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.changed.notified())
    }
}
