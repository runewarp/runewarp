//! Server role adapter for Managed-session authorization applies.
//!
//! Supplies validated Server input to one Authorization replacement operation
//! and observes success or failure. Prepare, commit, pool realignment,
//! selective revocation, and first-success readiness live behind that seam.
//! A successful apply then publishes the input's replacement hint to every
//! Tunnel event stream, and acknowledgments report this runtime's generation.

use serde_json::Value;

use crate::managed_session::{
    ApplyError, ManagedSessionLimits, RoleAdapter, ServerManagedInput, parse_server_input,
};
use crate::tunnel::ServerTunnelEvents;
use crate::{ServerHostname, ServerTunnelConfig};

use super::tunnel_registry::TunnelRegistry;

/// Applies validated Server Managed-session input onto live authorization state.
#[derive(Clone)]
pub struct ServerAuthorizationAdapter {
    server_hostname: ServerHostname,
    registry: TunnelRegistry,
    tunnel_events: ServerTunnelEvents,
}

impl ServerAuthorizationAdapter {
    pub(crate) fn new(
        server_hostname: ServerHostname,
        registry: TunnelRegistry,
        tunnel_events: ServerTunnelEvents,
    ) -> Self {
        Self {
            server_hostname,
            registry,
            tunnel_events,
        }
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

    /// Replace authorization, then publish the hint before the revision becomes acknowledgeable.
    /// The hint was validated with the rest of the input, so a rejected input changes neither.
    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        self.replace_authorization(&input.tunnels).await?;
        self.tunnel_events
            .set_replacement_generation(input.replacement_generation);
        Ok(())
    }

    fn acknowledgment_fields(&self) -> Vec<(&'static str, String)> {
        vec![(
            "generation",
            self.tunnel_events.server_generation().to_string(),
        )]
    }
}
