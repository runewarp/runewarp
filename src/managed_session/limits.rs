//! Fixed Managed-session input and reporting limits.
//!
//! Production defaults are safe powers-of-two aligned with Server admission
//! scale. Tests inject smaller values through [`ManagedSessionLimits`]; there is
//! no operator configuration or wire-level negotiation.

use std::time::Duration;

use crate::opaque_control_token::OPAQUE_CONTROL_TOKEN_MAX_CHARS;

/// Production and injectable budgets for one Managed session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSessionLimits {
    /// Maximum unfinished SSE line length in bytes.
    pub max_sse_line_bytes: usize,
    /// Maximum SSE `event:` field value length in bytes.
    pub max_sse_event_type_bytes: usize,
    /// Maximum accumulated SSE `data:` payload bytes before dispatch.
    pub max_sse_event_data_bytes: usize,
    /// Maximum complete snapshot JSON bytes.
    pub max_snapshot_bytes: usize,
    /// Maximum cumulative decoded allocation while parsing a snapshot.
    pub max_decoded_allocation_bytes: usize,
    /// Maximum opaque revision length in Unicode scalars.
    pub max_revision_chars: usize,
    /// Maximum tunnels in one Server snapshot.
    pub max_tunnels: usize,
    /// Maximum Public hostnames across all tunnels.
    pub max_public_hostnames_total: usize,
    /// Maximum Public hostnames on one tunnel.
    pub max_public_hostnames_per_tunnel: usize,
    /// Maximum Client identities across all tunnels.
    pub max_client_identities_total: usize,
    /// Maximum Client identities on one tunnel.
    pub max_client_identities_per_tunnel: usize,
    /// Maximum Server addresses in one Client snapshot.
    pub max_server_addresses: usize,
    /// Deadline for an applied-state request through response headers.
    pub state_request_deadline: Duration,
    /// Deadline for classifying an applied-state response body.
    pub state_response_deadline: Duration,
}

impl Default for ManagedSessionLimits {
    fn default() -> Self {
        Self {
            max_sse_line_bytes: 4 * 1024,
            max_sse_event_type_bytes: 64,
            max_sse_event_data_bytes: 1024 * 1024,
            max_snapshot_bytes: 1024 * 1024,
            max_decoded_allocation_bytes: 2 * 1024 * 1024,
            max_revision_chars: OPAQUE_CONTROL_TOKEN_MAX_CHARS,
            max_tunnels: 4_096,
            max_public_hostnames_total: 4_096,
            max_public_hostnames_per_tunnel: 256,
            max_client_identities_total: 4_096,
            max_client_identities_per_tunnel: 64,
            max_server_addresses: 256,
            state_request_deadline: Duration::from_secs(5),
            state_response_deadline: Duration::from_secs(5),
        }
    }
}

impl ManagedSessionLimits {
    /// Smaller deadlines for deterministic Tokio time tests; byte and
    /// cardinality caps remain at production defaults unless overridden.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            state_request_deadline: Duration::from_millis(50),
            state_response_deadline: Duration::from_millis(50),
            ..Self::default()
        }
    }
}

/// Named limit for bounded rejection logs and errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSessionLimitKind {
    SseLineBytes,
    SseEventTypeBytes,
    SseEventDataBytes,
    SnapshotBytes,
    DecodedAllocationBytes,
    RevisionChars,
    Tunnels,
    PublicHostnamesTotal,
    PublicHostnamesPerTunnel,
    ClientIdentitiesTotal,
    ClientIdentitiesPerTunnel,
    ServerAddresses,
}

impl ManagedSessionLimitKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SseLineBytes => "sse-line-bytes",
            Self::SseEventTypeBytes => "sse-event-type-bytes",
            Self::SseEventDataBytes => "sse-event-data-bytes",
            Self::SnapshotBytes => "snapshot-bytes",
            Self::DecodedAllocationBytes => "decoded-allocation-bytes",
            Self::RevisionChars => "revision-chars",
            Self::Tunnels => "tunnels",
            Self::PublicHostnamesTotal => "public-hostnames-total",
            Self::PublicHostnamesPerTunnel => "public-hostnames-per-tunnel",
            Self::ClientIdentitiesTotal => "client-identities-total",
            Self::ClientIdentitiesPerTunnel => "client-identities-per-tunnel",
            Self::ServerAddresses => "server-addresses",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ManagedSessionLimits;
    use crate::opaque_control_token::OPAQUE_CONTROL_TOKEN_MAX_CHARS;

    #[test]
    fn production_defaults_match_documented_powers_of_two() {
        let limits = ManagedSessionLimits::default();
        assert_eq!(limits.max_sse_line_bytes, 4 * 1024);
        assert_eq!(limits.max_sse_event_type_bytes, 64);
        assert_eq!(limits.max_sse_event_data_bytes, 1024 * 1024);
        assert_eq!(limits.max_snapshot_bytes, 1024 * 1024);
        assert_eq!(limits.max_decoded_allocation_bytes, 2 * 1024 * 1024);
        assert_eq!(limits.max_revision_chars, OPAQUE_CONTROL_TOKEN_MAX_CHARS);
        assert_eq!(limits.max_tunnels, 4_096);
        assert_eq!(limits.max_public_hostnames_total, 4_096);
        assert_eq!(limits.max_public_hostnames_per_tunnel, 256);
        assert_eq!(limits.max_client_identities_total, 4_096);
        assert_eq!(limits.max_client_identities_per_tunnel, 64);
        assert_eq!(limits.max_server_addresses, 256);
        assert_eq!(limits.state_request_deadline.as_secs(), 5);
        assert_eq!(limits.state_response_deadline.as_secs(), 5);
    }

    #[test]
    fn for_test_shortens_only_state_deadlines() {
        let limits = ManagedSessionLimits::for_test();
        assert_eq!(limits.state_request_deadline.as_millis(), 50);
        assert_eq!(limits.state_response_deadline.as_millis(), 50);
        assert_eq!(
            limits.max_tunnels,
            ManagedSessionLimits::default().max_tunnels
        );
    }
}
