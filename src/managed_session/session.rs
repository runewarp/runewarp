//! Managed-session reconnect and applied-revision ownership.

use std::future::Future;

use rand::rngs::StdRng;

use super::adapter::RoleAdapter;
use super::lifecycle::{ConnectionLifecycle, ManagedSessionError};
use super::limits::ManagedSessionLimits;
use super::reconcile::AppliedRevision;
use super::role::ManagedSessionRole;
use super::tls::{ControlTlsMaterialError, SessionMaterial, load_control_tls_material};
use crate::ControlAddress;
use crate::reconnect_policy::ReconnectPolicy;

/// Events emitted by the Managed-session engine for local observability.
///
/// Server reconciliation surfaces as Received (`Snapshot`), `Applying`,
/// `Applied`, `Rejected`, and `Superseded` without a separate status endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedSessionEvent {
    /// A validated snapshot envelope was received on the active downlink.
    Snapshot { revision: String },
    /// Role-adapter apply has started for this revision.
    Applying { revision: String },
    /// A revision was successfully applied through the role adapter.
    Applied { revision: String },
    /// Role input was rejected or invalid; prior applied revision is retained.
    Rejected { revision: String },
    /// A queued snapshot was discarded because a newer complete snapshot arrived.
    Superseded { revision: String },
    /// The session is waiting before replacing a failed connection.
    Reconnecting { display_delay_secs: u64 },
}

/// Role-neutral Managed-session engine.
pub struct ManagedSession {
    address: ControlAddress,
    role: ManagedSessionRole,
    material: SessionMaterial,
    limits: ManagedSessionLimits,
    reconnect: ReconnectPolicy<StdRng>,
    applied: AppliedRevision,
}

impl ManagedSession {
    pub fn new(
        address: ControlAddress,
        role: ManagedSessionRole,
        material: SessionMaterial,
    ) -> Result<Self, ControlTlsMaterialError> {
        Self::with_limits(address, role, material, ManagedSessionLimits::default())
    }

    pub fn with_limits(
        address: ControlAddress,
        role: ManagedSessionRole,
        material: SessionMaterial,
        limits: ManagedSessionLimits,
    ) -> Result<Self, ControlTlsMaterialError> {
        // Initial local material is a startup invariant. Later connection
        // attempts reload the same paths so post-start replacement failures
        // remain recoverable through the reconnect loop.
        load_control_tls_material(&material)?;
        Ok(Self {
            address,
            role,
            material,
            limits,
            reconnect: ReconnectPolicy::new(),
            applied: AppliedRevision::new(),
        })
    }

    /// Last successfully applied revision retained in this process only.
    pub fn applied_revision(&self) -> Option<&str> {
        self.applied.get()
    }

    /// Injected limits for this session (production defaults unless overridden).
    pub fn limits(&self) -> ManagedSessionLimits {
        self.limits
    }

    /// Run until `shutdown` completes, driving the role adapter and acknowledgments.
    pub async fn run<A, F, Fut, S, Shut>(
        &mut self,
        adapter: &mut A,
        mut on_event: F,
        shutdown: S,
    ) -> Shut
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
        S: Future<Output = Shut>,
    {
        tokio::pin!(shutdown);
        loop {
            let outcome = tokio::select! {
                biased;
                shutdown_result = &mut shutdown => return shutdown_result,
                outcome = self.run_one_connection(adapter, &mut on_event) => outcome,
            };

            if let Err(error) = outcome {
                tracing::warn!(error = %error, "managed session failed");
            }

            let retry = self.reconnect.next_retry();
            on_event(ManagedSessionEvent::Reconnecting {
                display_delay_secs: retry.display_delay_secs,
            })
            .await;

            tokio::select! {
                biased;
                shutdown_result = &mut shutdown => return shutdown_result,
                _ = tokio::time::sleep(retry.delay) => {}
            }
        }
    }

    async fn run_one_connection<A, F, Fut>(
        &mut self,
        adapter: &mut A,
        on_event: &mut F,
    ) -> Result<(), ManagedSessionAttemptError>
    where
        A: RoleAdapter,
        F: FnMut(ManagedSessionEvent) -> Fut,
        Fut: Future<Output = ()>,
    {
        let tls = load_control_tls_material(&self.material)
            .map_err(ManagedSessionAttemptError::TlsMaterial)?;
        let lifecycle =
            ConnectionLifecycle::<A::Input>::connect(&self.address, &tls, self.role, self.limits)
                .await
                .map_err(ManagedSessionAttemptError::Lifecycle)?;
        let outcome = lifecycle.run(adapter, &mut self.applied, on_event).await;
        if outcome.received_valid_snapshot {
            self.reconnect.reset();
        }
        outcome
            .result
            .map_err(ManagedSessionAttemptError::Lifecycle)
    }
}

#[derive(Debug)]
enum ManagedSessionAttemptError {
    TlsMaterial(ControlTlsMaterialError),
    Lifecycle(ManagedSessionError),
}

impl std::fmt::Display for ManagedSessionAttemptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsMaterial(error) => write!(formatter, "{error}"),
            Self::Lifecycle(error) => write!(formatter, "{error}"),
        }
    }
}
