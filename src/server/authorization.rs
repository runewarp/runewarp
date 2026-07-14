//! Atomically replaceable Server authorization state.
//!
//! Public-hostname routing and Client-identity handshake admission consult one
//! immutable snapshot. A prepared replacement can be validated independently,
//! then committed without exposing a partially updated view.

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
    pub fn from_tunnels(
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

    pub fn prepare(
        &self,
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<PreparedAuthorization> {
        self.state.prepare(server_hostname, tunnels)
    }

    pub fn commit(&self, prepared: PreparedAuthorization) -> Arc<AuthorizationSnapshot> {
        self.state.commit(prepared)
    }
}

impl ClientIdentityAdmission for ServerAuthorization {
    fn authorizes_client_identity(&self, identity: &ClientIdentity) -> bool {
        self.state.current().authorizes_client_identity(identity)
    }
}

/// Immutable authorization facts consulted by routing and handshake admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationSnapshot {
    client_identity_to_tunnel: HashMap<ClientIdentity, usize>,
    public_hostname_to_tunnel: HashMap<PublicHostname, usize>,
    trusted_client_identities: HashSet<ClientIdentity>,
    /// Parallel to tunnel indices. All `Some` in Managed mode; all `None` in static mode.
    tunnel_ids: Vec<Option<TunnelId>>,
    tunnel_count: usize,
}

impl AuthorizationSnapshot {
    pub(crate) fn try_from_tunnels(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        let mut client_identity_to_tunnel = HashMap::new();
        let mut public_hostname_to_tunnel = HashMap::new();
        let mut seen_client_identities = HashSet::new();
        let mut seen_public_hostnames = HashSet::new();
        let mut seen_tunnel_ids = HashSet::new();
        let mut tunnel_ids = Vec::with_capacity(tunnels.len());

        let id_count = tunnels.iter().filter(|tunnel| tunnel.id.is_some()).count();
        if id_count != 0 && id_count != tunnels.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Server Tunnel IDs must be present on every tunnel or on none",
            ));
        }

        for (index, tunnel) in tunnels.iter().enumerate() {
            if tunnel.public_hostnames.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "server.tunnels[].public-hostnames must not be empty",
                ));
            }
            if let Some(id) = &tunnel.id
                && !seen_tunnel_ids.insert(id.clone())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Tunnel IDs must be unique across all Server Tunnels: {id}"),
                ));
            }
            tunnel_ids.push(tunnel.id.clone());
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
        Ok(Self {
            trusted_client_identities: client_identity_to_tunnel.keys().cloned().collect(),
            client_identity_to_tunnel,
            public_hostname_to_tunnel,
            tunnel_ids,
            tunnel_count: tunnels.len(),
        })
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnel_count
    }

    pub fn tunnel_ids(&self) -> &[Option<TunnelId>] {
        &self.tunnel_ids
    }

    pub fn uses_tunnel_ids(&self) -> bool {
        !self.tunnel_ids.is_empty() && self.tunnel_ids.iter().all(|id| id.is_some())
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
            tunnel_ids: vec![None; tunnel_count],
            tunnel_count,
        }
    }
}

/// Validated candidate ready to replace the live authorization snapshot.
#[derive(Clone, Debug)]
pub struct PreparedAuthorization {
    snapshot: Arc<AuthorizationSnapshot>,
}

impl PreparedAuthorization {
    pub fn snapshot(&self) -> &AuthorizationSnapshot {
        &self.snapshot
    }
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
        let snapshot = AuthorizationSnapshot::try_from_tunnels(server_hostname, tunnels)?;
        Ok(Self {
            current: RwLock::new(Arc::new(snapshot)),
        })
    }

    pub(crate) fn current(&self) -> Arc<AuthorizationSnapshot> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn prepare(
        &self,
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<PreparedAuthorization> {
        let snapshot = AuthorizationSnapshot::try_from_tunnels(server_hostname, tunnels)?;
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{AuthorizationSnapshot, AuthorizationState, ServerAuthorization};
    use crate::quic::ClientIdentityAdmission;
    use crate::{
        ClientIdentity, PublicHostname, ServerHostname, ServerTunnelConfig,
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

    #[test]
    fn snapshot_builds_coherent_routing_and_trusted_identities() -> io::Result<()> {
        let first_identity = client_identity();
        let second_identity = client_identity();
        let snapshot = AuthorizationSnapshot::try_from_tunnels(
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
        assert_eq!(
            snapshot.tunnel_index_for_public_hostname(&public_hostname("app.example.test")),
            Some(0)
        );
        assert_eq!(
            snapshot.tunnel_index_for_public_hostname(&public_hostname("api.example.test")),
            Some(1)
        );
        assert_eq!(
            snapshot.tunnel_index_for_client_identity(&first_identity),
            Some(0)
        );
        assert_eq!(
            snapshot.tunnel_index_for_client_identity(&second_identity),
            Some(1)
        );
        assert!(snapshot.authorizes_client_identity(&first_identity));
        assert!(snapshot.authorizes_client_identity(&second_identity));
        assert!(!snapshot.authorizes_client_identity(&client_identity()));
        assert_eq!(snapshot.trusted_client_identities().len(), 2);
        Ok(())
    }

    #[test]
    fn snapshot_rejects_duplicate_public_hostnames_without_building() {
        let identity = client_identity();
        let error = AuthorizationSnapshot::try_from_tunnels(
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

    #[test]
    fn prepare_rejects_invalid_candidate_without_affecting_current() -> io::Result<()> {
        let identity = client_identity();
        let state = AuthorizationState::from_static_config(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![identity.clone()],
            }],
        )?;
        let before = state.current();

        let error = state
            .prepare(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: None,
                    public_hostnames: vec![],
                    authorized_client_identities: vec![client_identity()],
                }],
            )
            .expect_err("empty public hostnames must fail prepare");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(Arc::ptr_eq(&before, &state.current()));
        assert!(state.current().authorizes_client_identity(&identity));
        Ok(())
    }

    #[test]
    fn commit_replaces_routing_and_trusted_identities_together() -> io::Result<()> {
        let first_identity = client_identity();
        let second_identity = client_identity();
        let state = AuthorizationState::from_static_config(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![first_identity.clone()],
            }],
        )?;

        let prepared = state.prepare(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("api.example.test")],
                authorized_client_identities: vec![second_identity.clone()],
            }],
        )?;
        let committed = state.commit(prepared);

        assert_eq!(
            committed.tunnel_index_for_public_hostname(&public_hostname("api.example.test")),
            Some(0)
        );
        assert!(committed.authorizes_client_identity(&second_identity));
        assert!(!committed.authorizes_client_identity(&first_identity));
        assert_eq!(
            state
                .current()
                .tunnel_index_for_public_hostname(&public_hostname("app.example.test")),
            None
        );
        assert!(!state.current().authorizes_client_identity(&first_identity));
        Ok(())
    }

    #[test]
    fn concurrent_readers_observe_old_or_new_snapshot_not_a_mixed_view() -> io::Result<()> {
        let old_identity = client_identity();
        let new_identity = client_identity();
        let old_hostname = public_hostname("app.example.test");
        let new_hostname = public_hostname("api.example.test");
        let state = Arc::new(AuthorizationState::from_static_config(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![old_hostname.clone()],
                authorized_client_identities: vec![old_identity.clone()],
            }],
        )?);
        let stop = Arc::new(AtomicBool::new(false));
        let observations = Arc::new(AtomicUsize::new(0));
        let mixed_views = Arc::new(AtomicUsize::new(0));

        let mut readers = Vec::new();
        for _ in 0..8 {
            let state = state.clone();
            let stop = stop.clone();
            let observations = observations.clone();
            let mixed_views = mixed_views.clone();
            let old_identity = old_identity.clone();
            let new_identity = new_identity.clone();
            let old_hostname = old_hostname.clone();
            let new_hostname = new_hostname.clone();
            readers.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let snapshot = state.current();
                    let sees_old_hostname = snapshot
                        .tunnel_index_for_public_hostname(&old_hostname)
                        .is_some();
                    let sees_new_hostname = snapshot
                        .tunnel_index_for_public_hostname(&new_hostname)
                        .is_some();
                    let authorizes_old = snapshot.authorizes_client_identity(&old_identity);
                    let authorizes_new = snapshot.authorizes_client_identity(&new_identity);
                    let coherent_old = sees_old_hostname
                        && !sees_new_hostname
                        && authorizes_old
                        && !authorizes_new;
                    let coherent_new = !sees_old_hostname
                        && sees_new_hostname
                        && !authorizes_old
                        && authorizes_new;
                    if !(coherent_old || coherent_new) {
                        mixed_views.fetch_add(1, Ordering::Relaxed);
                    }
                    observations.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        wait_until(
            Duration::from_secs(2),
            || observations.load(Ordering::Relaxed) > 0,
            "readers should observe the initial snapshot before commit",
        );
        let prepared = state.prepare(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![new_hostname],
                authorized_client_identities: vec![new_identity],
            }],
        )?;
        let observations_before_commit = observations.load(Ordering::Relaxed);
        state.commit(prepared);
        wait_until(
            Duration::from_secs(2),
            || observations.load(Ordering::Relaxed) > observations_before_commit,
            "readers should observe the committed snapshot",
        );
        stop.store(true, Ordering::Release);
        for reader in readers {
            reader.join().expect("reader thread must not panic");
        }

        assert!(observations.load(Ordering::Relaxed) > 0);
        assert_eq!(mixed_views.load(Ordering::Relaxed), 0);
        Ok(())
    }

    fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool, message: &str) {
        let deadline = Instant::now() + timeout;
        while !ready() {
            assert!(Instant::now() < deadline, "{message} within {timeout:?}");
            thread::yield_now();
        }
    }

    #[test]
    fn handshake_admission_follows_committed_authorization_snapshot() -> io::Result<()> {
        let first_identity = client_identity();
        let second_identity = client_identity();
        let authorization = ServerAuthorization::from_tunnels(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![first_identity.clone()],
            }],
        )?;
        let admission: Arc<dyn ClientIdentityAdmission> = Arc::new(authorization.clone());

        assert!(admission.authorizes_client_identity(&first_identity));
        assert!(!admission.authorizes_client_identity(&second_identity));

        let prepared = authorization.prepare(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("api.example.test")],
                authorized_client_identities: vec![second_identity.clone()],
            }],
        )?;
        authorization.commit(prepared);

        assert!(!admission.authorizes_client_identity(&first_identity));
        assert!(admission.authorizes_client_identity(&second_identity));
        assert_eq!(
            authorization
                .state()
                .current()
                .tunnel_index_for_public_hostname(&public_hostname("api.example.test")),
            Some(0)
        );
        Ok(())
    }
}
