//! Atomically replaceable Server authorization state.
//!
//! Public-hostname routing and Client-identity handshake admission consult one
//! immutable **Authorization snapshot**. Live **Authorization replacement** is
//! owned by the Tunnel registry: validate a candidate beside the live snapshot,
//! commit routing and admission together, realign Tunnel pools, revoke selective
//! live work, and open first-success Server readiness.
//!
//! Continuity is first-class at construction: static snapshots have no Tunnel
//! IDs (startup-only, ordinal pools); managed snapshots carry Tunnel IDs (live
//! replacement, ID-keyed pools).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, RwLock};

use crate::quic::ClientIdentityAdmission;
use crate::{ClientIdentity, PublicHostname, ServerHostname, ServerTunnelConfig, TunnelId};

/// Shared Server authorization handle used by routing and QUIC handshake admission.
#[derive(Clone, Debug)]
pub struct ServerAuthorization {
    state: Arc<AuthorizationState>,
}

impl ServerAuthorization {
    /// Static-mode startup authorization. Tunnels must not carry Tunnel IDs.
    pub fn from_static_tunnels(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(AuthorizationState::from_static_config(
                server_hostname,
                tunnels,
            )?),
        })
    }

    /// Managed-mode startup authorization: empty snapshot ready for live replacement.
    pub fn empty_managed() -> Self {
        Self {
            state: Arc::new(AuthorizationState::empty_managed()),
        }
    }

    /// Managed-mode authorization from tunnels that each carry a Tunnel ID.
    #[cfg(test)]
    pub(crate) fn from_managed_tunnels(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        Ok(Self {
            state: Arc::new(AuthorizationState::from_managed_config(
                server_hostname,
                tunnels,
            )?),
        })
    }

    pub(crate) fn state(&self) -> &Arc<AuthorizationState> {
        &self.state
    }

    pub fn current_tunnel_count(&self) -> usize {
        self.state.current().tunnel_count()
    }

    pub fn trusted_client_identities(&self) -> Vec<ClientIdentity> {
        self.state
            .current()
            .trusted_client_identities()
            .iter()
            .cloned()
            .collect()
    }
}

impl ClientIdentityAdmission for ServerAuthorization {
    fn authorizes_client_identity(&self, identity: &ClientIdentity) -> bool {
        self.state.current().authorizes_client_identity(identity)
    }
}

/// How Tunnel pools continue under an Authorization snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationContinuity {
    /// Static mode: no Tunnel IDs; ordinal pool layout; startup-only authorization.
    Static,
    /// Managed mode: Tunnel IDs key live pools across Authorization replacement.
    Managed(Vec<TunnelId>),
}

/// Immutable authorization facts consulted by routing and handshake admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationSnapshot {
    client_identity_to_tunnel: HashMap<ClientIdentity, usize>,
    public_hostname_to_tunnel: HashMap<PublicHostname, usize>,
    trusted_client_identities: HashSet<ClientIdentity>,
    continuity: AuthorizationContinuity,
    tunnel_count: usize,
}

impl AuthorizationSnapshot {
    pub(crate) fn try_from_static_tunnels(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        if tunnels.iter().any(|tunnel| tunnel.id.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "static Server authorization must not include Tunnel IDs",
            ));
        }
        let maps = build_authorization_maps(server_hostname, tunnels)?;
        Ok(Self {
            trusted_client_identities: maps.trusted_client_identities,
            client_identity_to_tunnel: maps.client_identity_to_tunnel,
            public_hostname_to_tunnel: maps.public_hostname_to_tunnel,
            continuity: AuthorizationContinuity::Static,
            tunnel_count: tunnels.len(),
        })
    }

    pub(crate) fn try_from_managed_tunnels(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        let mut tunnel_ids = Vec::with_capacity(tunnels.len());
        let mut seen_tunnel_ids = HashSet::new();
        for tunnel in tunnels {
            let Some(id) = tunnel.id.clone() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "managed Server authorization requires a Tunnel ID on every tunnel",
                ));
            };
            if !seen_tunnel_ids.insert(id.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Tunnel IDs must be unique across all Server Tunnels: {id}"),
                ));
            }
            tunnel_ids.push(id);
        }
        let maps = build_authorization_maps(server_hostname, tunnels)?;
        Ok(Self {
            trusted_client_identities: maps.trusted_client_identities,
            client_identity_to_tunnel: maps.client_identity_to_tunnel,
            public_hostname_to_tunnel: maps.public_hostname_to_tunnel,
            continuity: AuthorizationContinuity::Managed(tunnel_ids),
            tunnel_count: tunnels.len(),
        })
    }

    pub(crate) fn empty_managed() -> Self {
        Self {
            client_identity_to_tunnel: HashMap::new(),
            public_hostname_to_tunnel: HashMap::new(),
            trusted_client_identities: HashSet::new(),
            continuity: AuthorizationContinuity::Managed(Vec::new()),
            tunnel_count: 0,
        }
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnel_count
    }

    pub(crate) fn continuity(&self) -> &AuthorizationContinuity {
        &self.continuity
    }

    pub fn managed_tunnel_ids(&self) -> Option<&[TunnelId]> {
        match &self.continuity {
            AuthorizationContinuity::Managed(ids) => Some(ids),
            AuthorizationContinuity::Static => None,
        }
    }

    pub fn tunnel_index_for_public_hostname(
        &self,
        public_hostname: &PublicHostname,
    ) -> Option<usize> {
        self.public_hostname_to_tunnel.get(public_hostname).copied()
    }

    pub fn tunnel_index_for_client_identity(
        &self,
        client_identity: &ClientIdentity,
    ) -> Option<usize> {
        self.client_identity_to_tunnel.get(client_identity).copied()
    }

    pub fn authorizes_client_identity(&self, client_identity: &ClientIdentity) -> bool {
        self.trusted_client_identities.contains(client_identity)
    }

    pub fn authorized_public_hostnames(&self) -> impl Iterator<Item = &PublicHostname> {
        self.public_hostname_to_tunnel.keys()
    }

    pub fn trusted_client_identities(&self) -> &HashSet<ClientIdentity> {
        &self.trusted_client_identities
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        client_identity_to_tunnel: HashMap<ClientIdentity, usize>,
        public_hostname_to_tunnel: HashMap<PublicHostname, usize>,
        trusted_client_identities: HashSet<ClientIdentity>,
        tunnel_count: usize,
    ) -> Self {
        Self {
            client_identity_to_tunnel,
            public_hostname_to_tunnel,
            trusted_client_identities,
            continuity: AuthorizationContinuity::Static,
            tunnel_count,
        }
    }
}

struct AuthorizationMaps {
    client_identity_to_tunnel: HashMap<ClientIdentity, usize>,
    public_hostname_to_tunnel: HashMap<PublicHostname, usize>,
    trusted_client_identities: HashSet<ClientIdentity>,
}

fn build_authorization_maps(
    server_hostname: &ServerHostname,
    tunnels: &[ServerTunnelConfig],
) -> io::Result<AuthorizationMaps> {
    let mut client_identity_to_tunnel = HashMap::new();
    let mut public_hostname_to_tunnel = HashMap::new();
    let mut seen_client_identities = HashSet::new();
    let mut seen_public_hostnames = HashSet::new();

    for (index, tunnel) in tunnels.iter().enumerate() {
        if tunnel.public_hostnames.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server.tunnels[].public-hostnames must not be empty",
            ));
        }
        for client_identity in &tunnel.authorized_client_identities {
            if !seen_client_identities.insert(client_identity.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "authorized Client identities must be unique across all Server Tunnels: {}",
                        client_identity
                    ),
                ));
            }
            client_identity_to_tunnel.insert(client_identity.clone(), index);
        }
        for hostname in &tunnel.public_hostnames {
            if hostname.as_str() == server_hostname.as_str() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "server.tunnels[].public-hostnames must not include server.hostname `{server_hostname}`"
                    ),
                ));
            }
            if !seen_public_hostnames.insert(hostname.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "server.tunnels[].public-hostnames must be unique after normalization: {hostname}"
                    ),
                ));
            }
            public_hostname_to_tunnel.insert(hostname.clone(), index);
        }
    }
    Ok(AuthorizationMaps {
        trusted_client_identities: client_identity_to_tunnel.keys().cloned().collect(),
        client_identity_to_tunnel,
        public_hostname_to_tunnel,
    })
}

/// Validated managed candidate ready to replace the live authorization snapshot.
///
/// Not a complete Authorization replacement by itself: callers must still
/// realign Tunnel pools, revoke live work, and open readiness through the
/// registry replacement operation.
#[derive(Clone, Debug)]
pub(crate) struct PreparedAuthorization {
    snapshot: Arc<AuthorizationSnapshot>,
}

/// Live authorization state that readers observe as one coherent snapshot.
#[derive(Debug)]
pub(crate) struct AuthorizationState {
    current: RwLock<Arc<AuthorizationSnapshot>>,
}

impl AuthorizationState {
    pub(crate) fn from_static_config(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        let snapshot = AuthorizationSnapshot::try_from_static_tunnels(server_hostname, tunnels)?;
        Ok(Self {
            current: RwLock::new(Arc::new(snapshot)),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_managed_config(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        let snapshot = AuthorizationSnapshot::try_from_managed_tunnels(server_hostname, tunnels)?;
        Ok(Self {
            current: RwLock::new(Arc::new(snapshot)),
        })
    }

    pub(crate) fn empty_managed() -> Self {
        Self {
            current: RwLock::new(Arc::new(AuthorizationSnapshot::empty_managed())),
        }
    }

    pub(crate) fn current(&self) -> Arc<AuthorizationSnapshot> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Validate a managed replacement candidate beside the live snapshot.
    ///
    /// Rejects when the live snapshot is static (startup-only) or when the
    /// candidate fails managed Tunnel-ID validation. Does not mutate live state.
    pub(crate) fn prepare_managed_replacement(
        &self,
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<PreparedAuthorization> {
        match self.current().continuity() {
            AuthorizationContinuity::Static => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "static Server authorization does not support live replacement",
                ));
            }
            AuthorizationContinuity::Managed(_) => {}
        }
        let snapshot = AuthorizationSnapshot::try_from_managed_tunnels(server_hostname, tunnels)?;
        Ok(PreparedAuthorization {
            snapshot: Arc::new(snapshot),
        })
    }

    pub(crate) fn commit(&self, prepared: PreparedAuthorization) -> Arc<AuthorizationSnapshot> {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = prepared.snapshot.clone();
        prepared.snapshot
    }

    #[cfg(test)]
    pub(crate) fn from_snapshot_for_test(snapshot: AuthorizationSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{AuthorizationContinuity, AuthorizationSnapshot};
    use crate::{
        ClientIdentity, PublicHostname, ServerHostname, ServerTunnelConfig, TunnelId,
        generate_client_identity,
    };

    fn public_hostname(hostname: &str) -> PublicHostname {
        PublicHostname::try_from(hostname).unwrap()
    }

    fn server_hostname(hostname: &str) -> ServerHostname {
        ServerHostname::try_from(hostname).unwrap()
    }

    fn client_identity() -> ClientIdentity {
        generate_client_identity().unwrap().client_identity
    }

    fn tunnel_id(raw: &str) -> TunnelId {
        TunnelId::parse(raw).unwrap()
    }

    #[test]
    fn static_snapshot_builds_coherent_routing_without_tunnel_ids() -> io::Result<()> {
        let first_identity = client_identity();
        let second_identity = client_identity();
        let snapshot = AuthorizationSnapshot::try_from_static_tunnels(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    id: None,
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![first_identity.clone()],
                },
                ServerTunnelConfig {
                    id: None,
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![second_identity.clone()],
                },
            ],
        )?;

        assert_eq!(snapshot.tunnel_count(), 2);
        assert_eq!(snapshot.continuity(), &AuthorizationContinuity::Static);
        assert_eq!(snapshot.managed_tunnel_ids(), None);
        assert_eq!(
            snapshot.tunnel_index_for_public_hostname(&public_hostname("app.example.test")),
            Some(0)
        );
        assert_eq!(
            snapshot.tunnel_index_for_client_identity(&first_identity),
            Some(0)
        );
        assert!(snapshot.authorizes_client_identity(&first_identity));
        assert!(!snapshot.authorizes_client_identity(&client_identity()));
        Ok(())
    }

    #[test]
    fn static_snapshot_rejects_tunnel_ids() {
        let error = AuthorizationSnapshot::try_from_static_tunnels(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(tunnel_id("tunnel-a")),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![client_identity()],
            }],
        )
        .expect_err("static construction must reject Tunnel IDs");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("static Server authorization must not include Tunnel IDs")
        );
    }

    #[test]
    fn managed_snapshot_requires_tunnel_ids_and_keeps_empty_managed_continuity() -> io::Result<()> {
        let empty = AuthorizationSnapshot::empty_managed();
        assert_eq!(empty.tunnel_count(), 0);
        assert_eq!(
            empty.continuity(),
            &AuthorizationContinuity::Managed(Vec::new())
        );
        assert_eq!(empty.managed_tunnel_ids(), Some([].as_slice()));

        let identity = client_identity();
        let id = tunnel_id("tunnel-a");
        let snapshot = AuthorizationSnapshot::try_from_managed_tunnels(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(id.clone()),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![identity.clone()],
            }],
        )?;
        assert_eq!(
            snapshot.continuity(),
            &AuthorizationContinuity::Managed(vec![id])
        );
        assert!(snapshot.authorizes_client_identity(&identity));
        Ok(())
    }

    #[test]
    fn managed_snapshot_rejects_missing_tunnel_id() {
        let error = AuthorizationSnapshot::try_from_managed_tunnels(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![client_identity()],
            }],
        )
        .expect_err("managed construction must require Tunnel IDs");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("managed Server authorization requires a Tunnel ID on every tunnel")
        );
    }

    #[test]
    fn static_snapshot_rejects_duplicate_public_hostnames_without_building() {
        let identity = client_identity();
        let error = AuthorizationSnapshot::try_from_static_tunnels(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    id: None,
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![identity.clone()],
                },
                ServerTunnelConfig {
                    id: None,
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![client_identity()],
                },
            ],
        )
        .expect_err("duplicate public hostnames must fail validation");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("server.tunnels[].public-hostnames must be unique after normalization")
        );
    }
}
