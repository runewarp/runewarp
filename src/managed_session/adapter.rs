//! Role-adapter seam for Managed-session reconciliation.
//!
//! The shared session owns transport, revision tracking, and state reporting.
//! Role-specific apply behavior lives behind this trait so Server and Client
//! do not duplicate those concerns.

use std::fmt;
use std::future::Future;

use serde_json::Value;

use super::input::{
    ClientManagedInput, InputError, ServerManagedInput, parse_client_input, parse_server_input,
};

/// Failure applying a validated role input. The session keeps the prior
/// successfully applied revision and does not acknowledge the rejected one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyError {
    message: String,
}

impl ApplyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApplyError {}

/// Role-specific reconciliation behind the Managed-session engine.
pub trait RoleAdapter: Send {
    type Input: Send;

    /// Validate role-specific snapshot `input` JSON.
    fn parse_input(input: &Value) -> Result<Self::Input, InputError>;

    /// Atomically apply a validated input. Returning `Err` rejects the
    /// candidate without acknowledging its revision.
    fn apply(&mut self, input: Self::Input) -> impl Future<Output = Result<(), ApplyError>> + Send;
}

/// Temporary Server adapter that accepts validated inputs without wiring live
/// authorization. Production managed Servers use [`crate::ServerAuthorizationAdapter`].
#[derive(Clone, Debug, Default)]
pub struct DeferredServerAdapter;

impl RoleAdapter for DeferredServerAdapter {
    type Input = ServerManagedInput;

    fn parse_input(input: &Value) -> Result<Self::Input, InputError> {
        parse_server_input(input)
    }

    async fn apply(&mut self, _input: Self::Input) -> Result<(), ApplyError> {
        Ok(())
    }
}

/// Temporary Client adapter that accepts validated inputs without wiring the
/// address controller. Production managed Clients use [`crate::ClientAssignmentAdapter`].
#[derive(Clone, Debug, Default)]
pub struct DeferredClientAdapter;

impl RoleAdapter for DeferredClientAdapter {
    type Input = ClientManagedInput;

    fn parse_input(input: &Value) -> Result<Self::Input, InputError> {
        parse_client_input(input)
    }

    async fn apply(&mut self, _input: Self::Input) -> Result<(), ApplyError> {
        Ok(())
    }
}
