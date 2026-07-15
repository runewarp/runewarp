//! Server role adapter for Managed-session authorization applies.
//!
//! Supplies validated Server input to one Authorization replacement operation
//! and observes success or failure. Prepare, commit, pool realignment,
//! selective revocation, and first-success readiness live behind that seam.

use serde_json::Value;

use crate::managed_session::{
    ApplyError, ManagedSessionLimits, RoleAdapter, ServerManagedInput, parse_server_input,
};
use crate::{ServerHostname, ServerTunnelConfig};

use super::tunnel_registry::TunnelRegistry;

/// Applies validated Server Managed-session input onto live authorization state.
#[derive(Clone)]
pub struct ServerAuthorizationAdapter {
    server_hostname: ServerHostname,
    registry: TunnelRegistry,
}

impl ServerAuthorizationAdapter {
    pub(crate) fn new(server_hostname: ServerHostname, registry: TunnelRegistry) -> Self {
        Self {
            server_hostname,
            registry,
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

    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        self.replace_authorization(&input.tunnels).await
    }
}
