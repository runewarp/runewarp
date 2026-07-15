//! Client role adapter for Managed-session Server-address assignment applies.
//!
//! Atomically replaces **Address controller** maintenance intent through a command
//! channel so the session can acknowledge a revision without waiting for
//! network convergence. Production obtains this adapter only from
//! [`crate::AddressController::for_managed`]; the apply channel is owned by the
//! controller's [`crate::AddressController::run`] loop, which dispatches each
//! command before answering the oneshot.

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::ServerAddress;
use crate::managed_session::{
    ApplyError, ClientManagedInput, InputError, ManagedSessionLimits, RoleAdapter,
    parse_client_input,
};

/// One assignment apply dispatched to the Address-controller owner.
#[derive(Debug)]
pub(crate) struct ClientAssignmentApply {
    pub(crate) addresses: Vec<ServerAddress>,
    pub(crate) done: oneshot::Sender<Result<(), ApplyError>>,
}

/// Applies validated Client Managed-session input onto Address-controller intent.
#[derive(Debug)]
pub struct ClientAssignmentAdapter {
    apply_tx: mpsc::UnboundedSender<ClientAssignmentApply>,
}

impl ClientAssignmentAdapter {
    pub(crate) fn new(apply_tx: mpsc::UnboundedSender<ClientAssignmentApply>) -> Self {
        Self { apply_tx }
    }
}

impl RoleAdapter for ClientAssignmentAdapter {
    type Input = ClientManagedInput;

    fn parse_input(input: Value, limits: &ManagedSessionLimits) -> Result<Self::Input, InputError> {
        parse_client_input(input, limits)
    }

    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        let (done_tx, done_rx) = oneshot::channel();
        self.apply_tx
            .send(ClientAssignmentApply {
                addresses: input.server_addresses,
                done: done_tx,
            })
            .map_err(|_| ApplyError::new("address controller closed"))?;
        done_rx
            .await
            .map_err(|_| ApplyError::new("address controller dropped apply acknowledgment"))?
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::{ClientAssignmentAdapter, ClientAssignmentApply};
    use crate::managed_session::{ApplyError, ManagedSessionLimits, RoleAdapter};

    #[tokio::test]
    async fn apply_dispatches_addresses_and_awaits_acknowledgment() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut adapter = ClientAssignmentAdapter::new(tx);
        let apply = tokio::spawn(async move {
            adapter
                .apply(
                    ClientAssignmentAdapter::parse_input(
                        json!({
                            "server_addresses": ["a.example.test:443", "b.example.test"]
                        }),
                        &ManagedSessionLimits::default(),
                    )
                    .expect("input should parse"),
                )
                .await
        });

        let ClientAssignmentApply { addresses, done } = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("apply should dispatch")
            .expect("channel open");
        assert_eq!(addresses.len(), 2);
        done.send(Ok(())).expect("apply still waiting");
        assert!(apply.await.expect("join").is_ok());
    }

    #[tokio::test]
    async fn apply_propagates_controller_failure() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut adapter = ClientAssignmentAdapter::new(tx);
        let apply = tokio::spawn(async move {
            adapter
                .apply(
                    ClientAssignmentAdapter::parse_input(
                        json!({
                            "server_addresses": []
                        }),
                        &ManagedSessionLimits::default(),
                    )
                    .expect("empty input should parse"),
                )
                .await
        });

        let ClientAssignmentApply { addresses, done } = rx.recv().await.expect("dispatch");
        assert!(addresses.is_empty());
        done.send(Err(ApplyError::new("boom")))
            .expect("apply still waiting");
        let error = apply.await.expect("join").expect_err("should fail");
        assert_eq!(error.to_string(), "boom");
    }

    #[tokio::test]
    async fn apply_fails_when_controller_channel_is_closed() {
        let (tx, rx) = mpsc::unbounded_channel::<ClientAssignmentApply>();
        drop(rx);
        let mut adapter = ClientAssignmentAdapter::new(tx);
        let error = adapter
            .apply(
                ClientAssignmentAdapter::parse_input(
                    json!({
                        "server_addresses": ["a.example.test"]
                    }),
                    &ManagedSessionLimits::default(),
                )
                .expect("input should parse"),
            )
            .await
            .expect_err("closed controller must reject apply");
        assert_eq!(error.to_string(), "address controller closed");
    }
}
