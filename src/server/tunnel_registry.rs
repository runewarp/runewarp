use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use quinn::Connection;
use rustls::pki_types::CertificateDer;
use tokio::sync::RwLock;
use tokio::task::AbortHandle;

use crate::{
    ClientIdentity, PublicHostname, ServerHostname, ServerTunnelConfig,
    client_identity_from_certificate_der,
};

use super::active_client::{ActiveClientPool, SelectedTunnelConnection};
#[cfg(test)]
use super::admission::ServerAdmissionLimits;
use super::admission::{AdmissionRejection, TunnelConnectionAdmission};
use super::authorization::{
    AuthorizationContinuity, AuthorizationSnapshot, AuthorizationState, PreparedAuthorization,
    ServerAuthorization,
};
use super::readiness::ReadinessGate;

pub(crate) enum TunnelRouteOutcome {
    Unauthorized,
    NoActiveTunnelConnection,
    Connected(SelectedTunnelConnection),
}

pub(crate) enum TunnelRegistrationOutcome {
    Registered,
    Rejected(AdmissionRejection),
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiveWorkDispatch {
    pub connections_closed: usize,
    pub streams_reset: usize,
}

struct ActiveVisitorStream {
    public_hostname: PublicHostname,
    member_id: u64,
    client_identity: ClientIdentity,
    abort_handle: AbortHandle,
}

#[derive(Clone)]
pub(crate) struct TunnelRegistry {
    authorization: Arc<AuthorizationState>,
    tunnel_pools: Arc<RwLock<Vec<ActiveClientPool>>>,
    // std lock so track/reset stay synchronous (no await gap after stream admission).
    visitor_streams: Arc<StdRwLock<HashMap<u64, ActiveVisitorStream>>>,
    next_stream_id: Arc<AtomicU64>,
    accepting_tunnel_connections: Arc<AtomicBool>,
    admitting_streams: Arc<AtomicBool>,
    tunnel_connection_admission: TunnelConnectionAdmission,
    readiness: Arc<StdRwLock<Option<ReadinessGate>>>,
    first_apply_completed: Arc<AtomicBool>,
}

impl TunnelRegistry {
    #[cfg(test)]
    pub(crate) fn single(public_hostnames: Vec<PublicHostname>) -> io::Result<Self> {
        use std::collections::{HashMap, HashSet};

        use super::authorization::AuthorizationSnapshot;

        let mut public_hostname_to_tunnel = HashMap::new();
        let mut seen_public_hostnames = HashSet::new();
        for hostname in public_hostnames {
            if !seen_public_hostnames.insert(hostname.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "authorized_public_hostnames must be unique after normalization: {hostname}"
                    ),
                ));
            }
            public_hostname_to_tunnel.insert(hostname, 0);
        }
        let snapshot = AuthorizationSnapshot::from_parts_for_test(
            HashMap::new(),
            public_hostname_to_tunnel,
            HashSet::new(),
            1,
        );
        let tunnel_connection_admission =
            TunnelConnectionAdmission::new(ServerAdmissionLimits::default());
        Ok(Self {
            authorization: Arc::new(AuthorizationState::from_snapshot_for_test(snapshot)),
            tunnel_pools: Arc::new(RwLock::new(vec![ActiveClientPool::with_admission(
                tunnel_connection_admission.clone(),
            )])),
            visitor_streams: Arc::new(StdRwLock::new(HashMap::new())),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            accepting_tunnel_connections: Arc::new(AtomicBool::new(true)),
            admitting_streams: Arc::new(AtomicBool::new(true)),
            tunnel_connection_admission,
            readiness: Arc::new(StdRwLock::new(None)),
            first_apply_completed: Arc::new(AtomicBool::new(false)),
        })
    }

    #[cfg(test)]
    pub(crate) fn configured(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        Self::from_authorization(ServerAuthorization::from_static_tunnels(
            server_hostname,
            tunnels,
        )?)
    }

    #[cfg(test)]
    pub(crate) fn configured_managed(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        Self::from_authorization(ServerAuthorization::from_managed_tunnels(
            server_hostname,
            tunnels,
        )?)
    }

    #[cfg(test)]
    pub(crate) fn empty_managed() -> Self {
        Self::from_authorization(ServerAuthorization::empty_managed())
            .expect("empty managed authorization always builds")
    }

    #[cfg(test)]
    pub(crate) fn from_authorization(authorization: ServerAuthorization) -> io::Result<Self> {
        Self::from_authorization_with_admission(
            authorization,
            TunnelConnectionAdmission::new(ServerAdmissionLimits::default()),
        )
    }

    pub(crate) fn from_authorization_with_admission(
        authorization: ServerAuthorization,
        tunnel_connection_admission: TunnelConnectionAdmission,
    ) -> io::Result<Self> {
        let tunnel_count = authorization.current_tunnel_count();
        let mut tunnel_pools = Vec::with_capacity(tunnel_count);
        for _ in 0..tunnel_count {
            tunnel_pools.push(ActiveClientPool::with_admission(
                tunnel_connection_admission.clone(),
            ));
        }
        Ok(Self {
            authorization: authorization.state().clone(),
            tunnel_pools: Arc::new(RwLock::new(tunnel_pools)),
            visitor_streams: Arc::new(StdRwLock::new(HashMap::new())),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            accepting_tunnel_connections: Arc::new(AtomicBool::new(true)),
            admitting_streams: Arc::new(AtomicBool::new(true)),
            tunnel_connection_admission,
            readiness: Arc::new(StdRwLock::new(None)),
            first_apply_completed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn set_readiness(&self, readiness: ReadinessGate) {
        *self
            .readiness
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(readiness);
    }

    #[cfg(test)]
    pub(crate) fn authorization(&self) -> Arc<AuthorizationState> {
        self.authorization.clone()
    }

    /// One Authorization replacement: validate beside the live snapshot, commit
    /// routing and handshake admission atomically, realign Tunnel pools, dispatch
    /// selective live-work revocation, and open readiness after first success.
    pub(crate) async fn replace_authorization(
        &self,
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<LiveWorkDispatch> {
        let prepared = self
            .authorization
            .prepare_managed_replacement(server_hostname, tunnels)?;
        let dispatch = self.commit_authorization(prepared).await;
        // Mark readiness only after atomic commit and local revocation dispatch.
        // Do not await peer acknowledgment or remote closure.
        if !self.first_apply_completed.swap(true, Ordering::SeqCst) {
            let readiness = self
                .readiness
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(readiness) = readiness {
                readiness.mark_ready();
            }
        }
        Ok(dispatch)
    }

    async fn commit_authorization(&self, prepared: PreparedAuthorization) -> LiveWorkDispatch {
        let previous = self.authorization.current();
        // Hold the pools write lock across snapshot commit and realignment so
        // concurrent route/register cannot observe new Tunnel indices against
        // the previous pool layout. Readers acquire this lock before reading
        // the authorization snapshot for the same reason.
        let mut pools = self.tunnel_pools.write().await;
        let next = self.authorization.commit(prepared);

        let removed_identities = previous
            .trusted_client_identities()
            .difference(next.trusted_client_identities())
            .cloned()
            .collect::<HashSet<_>>();
        let connections_closed = if removed_identities.is_empty() {
            0
        } else {
            let mut closed = 0;
            for pool in pools.iter() {
                closed += pool
                    .close_connections_for_identities(&removed_identities, b"authorization revoked")
                    .await;
            }
            closed
        };

        // Managed continuity rematches pools by Tunnel ID. Surviving members are
        // always rehomed by Client identity under the new snapshot.
        let mut taken = Vec::new();
        for pool in pools.iter() {
            taken.extend(pool.take_members().await);
        }

        match (previous.continuity(), next.continuity()) {
            (
                AuthorizationContinuity::Managed(previous_ids),
                AuthorizationContinuity::Managed(next_ids),
            ) => {
                let mut pools_by_id = std::collections::HashMap::new();
                for (index, id) in previous_ids.iter().enumerate() {
                    if index < pools.len() {
                        pools_by_id.insert(id.clone(), pools[index].clone());
                    }
                }
                let mut rebuilt = Vec::with_capacity(next_ids.len());
                for id in next_ids {
                    rebuilt.push(pools_by_id.remove(id).unwrap_or_else(|| {
                        ActiveClientPool::with_admission(self.tunnel_connection_admission.clone())
                    }));
                }
                *pools = rebuilt;
            }
            _ => {
                // prepare_managed_replacement only admits managed→managed commits.
                unreachable!("Authorization replacement requires managed continuity on both sides");
            }
        }

        for member in taken {
            let Some(tunnel_index) = next.tunnel_index_for_client_identity(&member.client_identity)
            else {
                // Identity was revoked; close already signaled above. Drop the
                // detached member and leave its prior close watcher to log
                // termination against the empty previous pool list. Admission
                // capacity remains charged until peer closure completes.
                member.release_admission_after_close();
                continue;
            };
            if let Some(pool) = pools.get(tunnel_index) {
                pool.adopt_member(member).await;
            }
        }
        drop(pools);

        let streams_reset = self.reset_streams_not_authorized_by(&next);

        LiveWorkDispatch {
            connections_closed,
            streams_reset,
        }
    }

    pub(crate) async fn route_tunnel_connection(
        &self,
        public_hostname: &PublicHostname,
    ) -> TunnelRouteOutcome {
        if !self.admitting_streams.load(Ordering::SeqCst) {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        }
        // Lock pools before reading authorization so the index→pool view stays
        // coherent with replace_authorization's write-locked swap+realign.
        let pools = self.tunnel_pools.read().await;
        let snapshot = self.authorization.current();
        let Some(tunnel_index) = snapshot.tunnel_index_for_public_hostname(public_hostname) else {
            return TunnelRouteOutcome::Unauthorized;
        };
        let Some(pool) = pools.get(tunnel_index).cloned() else {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        };
        drop(pools);
        let Some(connection) = pool.select_connection().await else {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        };
        TunnelRouteOutcome::Connected(connection)
    }

    pub(crate) async fn register(&self, connection: Connection) -> TunnelRegistrationOutcome {
        if !self.accepting_tunnel_connections.load(Ordering::SeqCst) {
            connection.close(0_u32.into(), b"server shutting down");
            return TunnelRegistrationOutcome::Closed;
        }
        // Same pools-before-authorization lock order as route_tunnel_connection.
        let pools = self.tunnel_pools.read().await;
        let Some((tunnel_index, client_identity)) = self.tunnel_registration_context(&connection)
        else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return TunnelRegistrationOutcome::Closed;
        };
        let Some(pool) = pools.get(tunnel_index).cloned() else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return TunnelRegistrationOutcome::Closed;
        };
        drop(pools);
        match pool.try_register(connection.clone(), client_identity).await {
            Ok(()) => TunnelRegistrationOutcome::Registered,
            Err(rejection) => {
                connection.close(0_u32.into(), b"server tunnel admission saturated");
                TunnelRegistrationOutcome::Rejected(rejection)
            }
        }
    }

    pub(crate) async fn close_all(&self, reason: &'static [u8]) -> usize {
        let pools = self.tunnel_pools.read().await.clone();
        let mut closed = 0;
        for pool in pools.iter() {
            closed += pool.close_all_connections(reason).await;
        }
        closed
    }

    pub(crate) fn track_visitor_stream(
        &self,
        public_hostname: PublicHostname,
        member_id: u64,
        client_identity: ClientIdentity,
        abort_handle: AbortHandle,
    ) -> u64 {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        self.visitor_streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                stream_id,
                ActiveVisitorStream {
                    public_hostname,
                    member_id,
                    client_identity,
                    abort_handle,
                },
            );
        stream_id
    }

    pub(crate) fn untrack_visitor_stream(&self, stream_id: u64) {
        self.visitor_streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&stream_id);
    }

    #[allow(dead_code)] // selective hostname revocation; also used by tests
    pub(crate) fn reset_streams_for_public_hostname(
        &self,
        public_hostname: &PublicHostname,
    ) -> usize {
        self.reset_streams_matching(|stream| &stream.public_hostname == public_hostname)
    }

    #[allow(dead_code)] // selective serving-connection revocation
    pub(crate) fn reset_streams_for_member(&self, member_id: u64) -> usize {
        self.reset_streams_matching(|stream| stream.member_id == member_id)
    }

    fn reset_streams_not_authorized_by(&self, snapshot: &AuthorizationSnapshot) -> usize {
        self.reset_streams_matching(|stream| !stream_remains_authorized(stream, snapshot))
    }

    fn reset_streams_matching(
        &self,
        mut should_reset: impl FnMut(&ActiveVisitorStream) -> bool,
    ) -> usize {
        let mut streams = self
            .visitor_streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut reset = 0;
        streams.retain(|_, stream| {
            if should_reset(stream) {
                stream.abort_handle.abort();
                reset += 1;
                false
            } else {
                true
            }
        });
        reset
    }

    #[cfg(test)]
    pub(crate) fn tracked_visitor_stream_count(&self) -> usize {
        self.visitor_streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(test)]
    pub(crate) fn tracked_visitor_hostnames(&self) -> Vec<PublicHostname> {
        self.visitor_streams
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|stream| stream.public_hostname.clone())
            .collect()
    }

    #[cfg(test)]
    pub(crate) async fn pool_count(&self) -> usize {
        self.tunnel_pools.read().await.len()
    }

    pub(crate) async fn active_connection_count(&self) -> usize {
        let pools = self.tunnel_pools.read().await.clone();
        let mut active = 0;
        for pool in pools.iter() {
            active += pool.connection_count().await;
        }
        active
    }

    pub(crate) async fn active_stream_count(&self) -> usize {
        let pools = self.tunnel_pools.read().await.clone();
        let mut active = 0;
        for pool in pools.iter() {
            active += pool.active_stream_count().await;
        }
        active
    }

    pub(crate) fn stop_accepting_new_work(&self) {
        self.accepting_tunnel_connections
            .store(false, Ordering::SeqCst);
        self.admitting_streams.store(false, Ordering::SeqCst);
    }

    fn tunnel_registration_context(
        &self,
        connection: &Connection,
    ) -> Option<(usize, ClientIdentity)> {
        let identity = client_identity_from_connection(connection)?;
        let tunnel_index = self
            .authorization
            .current()
            .tunnel_index_for_client_identity(&identity)?;
        Some((tunnel_index, identity))
    }
}

fn client_identity_from_connection(connection: &Connection) -> Option<ClientIdentity> {
    let identity = connection.peer_identity()?;
    let certificate_chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let certificate = certificate_chain.first()?;
    client_identity_from_certificate_der(certificate.as_ref()).ok()
}

fn stream_remains_authorized(
    stream: &ActiveVisitorStream,
    snapshot: &AuthorizationSnapshot,
) -> bool {
    match (
        snapshot.tunnel_index_for_public_hostname(&stream.public_hostname),
        snapshot.tunnel_index_for_client_identity(&stream.client_identity),
    ) {
        (Some(hostname_tunnel), Some(identity_tunnel)) => hostname_tunnel == identity_tunnel,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::pem::Error as PemError;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::time::timeout;

    use super::{TunnelRegistrationOutcome, TunnelRegistry, TunnelRouteOutcome};
    use crate::server::admission::{
        AdmissionLimit, AdmissionRejection, ServerAdmissionLimits, TunnelConnectionAdmission,
    };
    use crate::server::readiness::ReadinessGate;
    use crate::tls_material::{certificate_chain_from_pem, private_key_from_pem};
    use crate::{
        GeneratedClientIdentity, PublicHostname, ServerAuthorization, ServerHostname,
        ServerTunnelConfig, TunnelId, generate_client_identity,
        make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    };

    fn public_hostname(hostname: &str) -> PublicHostname {
        PublicHostname::try_from(hostname).unwrap()
    }

    fn server_hostname(hostname: &str) -> ServerHostname {
        ServerHostname::try_from(hostname).unwrap()
    }

    #[tokio::test]
    async fn returns_unauthorized_when_public_hostname_is_not_authorized() -> io::Result<()> {
        let registry = TunnelRegistry::single(vec![public_hostname("app.example.test")])?;

        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("other.example.test"))
                .await,
            TunnelRouteOutcome::Unauthorized
        ));
        Ok(())
    }

    #[tokio::test]
    async fn returns_no_active_tunnel_connection_for_authorized_public_hostname() -> io::Result<()>
    {
        let registry = TunnelRegistry::single(vec![public_hostname("app.example.test")])?;

        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::NoActiveTunnelConnection
        ));
        Ok(())
    }

    #[tokio::test]
    async fn returns_connected_tunnel_connection_for_authorized_public_hostname() -> io::Result<()>
    {
        let client_identity = generate_test_client_identity()?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let registry = TunnelRegistry::configured(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        registry.register(fixture.server_connection).await;

        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::Connected(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn stopped_registry_rejects_late_tunnel_registration() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let registry = TunnelRegistry::configured(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;

        registry.stop_accepting_new_work();
        registry.register(fixture.server_connection).await;

        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::NoActiveTunnelConnection
        ));
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_rehomes_surviving_connection_when_tunnel_index_shifts()
    -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-1").unwrap()),
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![first_identity.client_identity.clone()],
                },
                ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-2").unwrap()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                },
            ],
        )?;

        let first_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&second_identity).await?;
        registry.register(first_fixture.server_connection).await;
        registry
            .register(second_fixture.server_connection.clone())
            .await;
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("api.example.test"))
                .await,
            TunnelRouteOutcome::Connected(_)
        ));

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-3").unwrap()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                }],
            )
            .await?;
        assert_eq!(dispatch.connections_closed, 1);
        assert_eq!(registry.pool_count().await, 1);
        assert_eq!(
            registry
                .authorization()
                .current()
                .tunnel_index_for_client_identity(&second_identity.client_identity),
            Some(0)
        );

        let routed = registry
            .route_tunnel_connection(&public_hostname("api.example.test"))
            .await;
        assert!(
            matches!(routed, TunnelRouteOutcome::Connected(_)),
            "surviving Client identity must remain routable after lower Tunnel index is removed"
        );
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::Unauthorized
        ));
        Ok(())
    }

    #[tokio::test]
    async fn realignment_grandfathers_existing_connections_but_rejects_newest_over_limit()
    -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let initial_tunnels = [
            ServerTunnelConfig {
                id: Some(TunnelId::parse("tunnel-1").unwrap()),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![first_identity.client_identity.clone()],
            },
            ServerTunnelConfig {
                id: Some(TunnelId::parse("tunnel-2").unwrap()),
                public_hostnames: vec![public_hostname("api.example.test")],
                authorized_client_identities: vec![second_identity.client_identity.clone()],
            },
        ];
        let authorization = ServerAuthorization::from_managed_tunnels(
            &server_hostname("tunnel.example.test"),
            &initial_tunnels,
        )?;
        let limits = ServerAdmissionLimits {
            max_tunnel_connections: 4,
            max_tunnel_connections_per_tunnel: 1,
            max_tunnel_connections_per_identity: 4,
            ..ServerAdmissionLimits::for_test()
        };
        let registry = TunnelRegistry::from_authorization_with_admission(
            authorization,
            TunnelConnectionAdmission::new(limits),
        )?;

        let first_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&second_identity).await?;
        assert!(matches!(
            registry
                .register(first_fixture.server_connection.clone())
                .await,
            TunnelRegistrationOutcome::Registered
        ));
        assert!(matches!(
            registry
                .register(second_fixture.server_connection.clone())
                .await,
            TunnelRegistrationOutcome::Registered
        ));

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-3").unwrap()),
                    public_hostnames: vec![
                        public_hostname("app.example.test"),
                        public_hostname("api.example.test"),
                    ],
                    authorized_client_identities: vec![
                        first_identity.client_identity.clone(),
                        second_identity.client_identity.clone(),
                    ],
                }],
            )
            .await?;
        assert_eq!(dispatch.connections_closed, 0);
        assert_eq!(registry.active_connection_count().await, 2);
        let mut retained_identities = HashSet::new();
        for _ in 0..2 {
            let TunnelRouteOutcome::Connected(connection) = registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await
            else {
                panic!("grandfathered connection should remain routable");
            };
            retained_identities.insert(connection.client_identity().clone());
        }
        assert_eq!(
            retained_identities,
            HashSet::from([
                first_identity.client_identity.clone(),
                second_identity.client_identity.clone(),
            ])
        );

        let newest_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        assert!(matches!(
            registry.register(newest_fixture.server_connection).await,
            TunnelRegistrationOutcome::Rejected(AdmissionRejection {
                limit: AdmissionLimit::TunnelConnectionsPerTunnel,
                active_work: 2,
            })
        ));
        assert_eq!(registry.active_connection_count().await, 2);
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_reuses_pools_by_tunnel_id_when_order_changes() -> io::Result<()>
    {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let id_a = TunnelId::parse("tunnel-a").unwrap();
        let id_b = TunnelId::parse("tunnel-b").unwrap();
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    id: Some(id_a.clone()),
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![first_identity.client_identity.clone()],
                },
                ServerTunnelConfig {
                    id: Some(id_b.clone()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                },
            ],
        )?;

        let first_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&second_identity).await?;
        registry.register(first_fixture.server_connection).await;
        registry
            .register(second_fixture.server_connection.clone())
            .await;

        // Swap order only — same Tunnel IDs and identities.
        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[
                    ServerTunnelConfig {
                        id: Some(id_b.clone()),
                        public_hostnames: vec![public_hostname("api.example.test")],
                        authorized_client_identities: vec![second_identity.client_identity.clone()],
                    },
                    ServerTunnelConfig {
                        id: Some(id_a.clone()),
                        public_hostnames: vec![public_hostname("app.example.test")],
                        authorized_client_identities: vec![first_identity.client_identity.clone()],
                    },
                ],
            )
            .await?;
        assert_eq!(dispatch.connections_closed, 0);
        assert_eq!(registry.pool_count().await, 2);
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::Connected(_)
        ));
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("api.example.test"))
                .await,
            TunnelRouteOutcome::Connected(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_rehomes_identity_moving_between_tunnel_ids() -> io::Result<()> {
        let identity = generate_test_client_identity()?;
        let other = generate_test_client_identity()?;
        let id_a = TunnelId::parse("tunnel-a").unwrap();
        let id_b = TunnelId::parse("tunnel-b").unwrap();
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    id: Some(id_a.clone()),
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![identity.client_identity.clone()],
                },
                ServerTunnelConfig {
                    id: Some(id_b.clone()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![other.client_identity.clone()],
                },
            ],
        )?;

        let fixture = TunnelConnectionFixture::connect(&identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::Connected(_)
        ));

        // Move `identity` from Tunnel A to Tunnel B; swap `other` onto A.
        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[
                    ServerTunnelConfig {
                        id: Some(id_a.clone()),
                        public_hostnames: vec![public_hostname("app.example.test")],
                        authorized_client_identities: vec![other.client_identity.clone()],
                    },
                    ServerTunnelConfig {
                        id: Some(id_b.clone()),
                        public_hostnames: vec![public_hostname("api.example.test")],
                        authorized_client_identities: vec![identity.client_identity.clone()],
                    },
                ],
            )
            .await?;
        assert_eq!(
            dispatch.connections_closed, 0,
            "identity move between Tunnel IDs must rehome, not close"
        );
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("api.example.test"))
                .await,
            TunnelRouteOutcome::Connected(_)
        ));
        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::NoActiveTunnelConnection
        ));
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_grows_pools_and_revokes_removed_identities() -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(TunnelId::parse("tunnel-1").unwrap()),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![first_identity.client_identity.clone()],
            }],
        )?;
        assert_eq!(registry.pool_count().await, 1);

        let first_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        registry
            .register(first_fixture.server_connection.clone())
            .await;

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[
                    ServerTunnelConfig {
                        id: Some(TunnelId::parse("tunnel-2").unwrap()),
                        public_hostnames: vec![public_hostname("app.example.test")],
                        authorized_client_identities: vec![first_identity.client_identity.clone()],
                    },
                    ServerTunnelConfig {
                        id: Some(TunnelId::parse("tunnel-3").unwrap()),
                        public_hostnames: vec![public_hostname("api.example.test")],
                        authorized_client_identities: vec![second_identity.client_identity.clone()],
                    },
                ],
            )
            .await?;
        assert_eq!(dispatch.connections_closed, 0);
        assert_eq!(dispatch.streams_reset, 0);
        assert_eq!(registry.pool_count().await, 2);
        assert!(
            registry
                .authorization()
                .current()
                .authorizes_client_identity(&second_identity.client_identity)
        );

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-4").unwrap()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                }],
            )
            .await?;
        assert_eq!(dispatch.connections_closed, 1);
        assert_eq!(dispatch.streams_reset, 0);
        assert!(
            !registry
                .authorization()
                .current()
                .authorizes_client_identity(&first_identity.client_identity)
        );
        Ok(())
    }

    #[tokio::test]
    async fn reset_streams_for_public_hostname_aborts_only_matching_tracked_streams()
    -> io::Result<()> {
        let registry = TunnelRegistry::single(vec![
            public_hostname("app.example.test"),
            public_hostname("api.example.test"),
        ])?;
        let keep_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let app_keep = keep_running.clone();
        let api_keep = keep_running.clone();
        let app_task = tokio::spawn(async move {
            while app_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let api_task = tokio::spawn(async move {
            while api_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let app_identity = generate_test_client_identity()?.client_identity;
        let api_identity = generate_test_client_identity()?.client_identity;
        let app_stream_id = registry.track_visitor_stream(
            public_hostname("app.example.test"),
            1,
            app_identity,
            app_task.abort_handle(),
        );
        let api_stream_id = registry.track_visitor_stream(
            public_hostname("api.example.test"),
            2,
            api_identity,
            api_task.abort_handle(),
        );

        assert_eq!(
            registry.reset_streams_for_public_hostname(&public_hostname("app.example.test")),
            1
        );
        assert!(
            app_task
                .await
                .expect_err("app stream should abort")
                .is_cancelled()
        );
        assert_eq!(
            registry.tracked_visitor_hostnames(),
            vec![public_hostname("api.example.test")]
        );

        keep_running.store(false, std::sync::atomic::Ordering::Relaxed);
        api_task.await.expect("api stream should finish normally");
        registry.untrack_visitor_stream(api_stream_id);
        registry.untrack_visitor_stream(app_stream_id);
        assert_eq!(registry.tracked_visitor_stream_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_resets_streams_for_revoked_identities_and_remapped_hostnames()
    -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(TunnelId::parse("tunnel-1").unwrap()),
                public_hostnames: vec![
                    public_hostname("app.example.test"),
                    public_hostname("shared.example.test"),
                ],
                authorized_client_identities: vec![first_identity.client_identity.clone()],
            }],
        )?;

        let keep_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let remapped_keep = keep_running.clone();
        let surviving_keep = keep_running.clone();
        let revoked_keep = keep_running.clone();
        let remapped_task = tokio::spawn(async move {
            while remapped_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let surviving_task = tokio::spawn(async move {
            while surviving_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let revoked_task = tokio::spawn(async move {
            while revoked_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });

        registry.track_visitor_stream(
            public_hostname("shared.example.test"),
            1,
            first_identity.client_identity.clone(),
            remapped_task.abort_handle(),
        );
        registry.track_visitor_stream(
            public_hostname("app.example.test"),
            1,
            first_identity.client_identity.clone(),
            surviving_task.abort_handle(),
        );

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[
                    ServerTunnelConfig {
                        id: Some(TunnelId::parse("tunnel-2").unwrap()),
                        public_hostnames: vec![public_hostname("app.example.test")],
                        authorized_client_identities: vec![first_identity.client_identity.clone()],
                    },
                    ServerTunnelConfig {
                        id: Some(TunnelId::parse("tunnel-3").unwrap()),
                        public_hostnames: vec![public_hostname("shared.example.test")],
                        authorized_client_identities: vec![second_identity.client_identity.clone()],
                    },
                ],
            )
            .await?;
        assert_eq!(dispatch.streams_reset, 1);
        assert!(
            remapped_task
                .await
                .expect_err("hostname remapped away from serving identity should abort")
                .is_cancelled()
        );
        assert_eq!(
            registry.tracked_visitor_hostnames(),
            vec![public_hostname("app.example.test")]
        );

        registry.track_visitor_stream(
            public_hostname("app.example.test"),
            1,
            first_identity.client_identity.clone(),
            revoked_task.abort_handle(),
        );

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[
                    ServerTunnelConfig {
                        id: Some(TunnelId::parse("tunnel-4").unwrap()),
                        public_hostnames: vec![public_hostname("app.example.test")],
                        authorized_client_identities: vec![
                            generate_test_client_identity()?.client_identity,
                        ],
                    },
                    ServerTunnelConfig {
                        id: Some(TunnelId::parse("tunnel-5").unwrap()),
                        public_hostnames: vec![public_hostname("shared.example.test")],
                        authorized_client_identities: vec![second_identity.client_identity.clone()],
                    },
                ],
            )
            .await?;
        assert_eq!(dispatch.streams_reset, 2);
        assert!(
            surviving_task
                .await
                .expect_err("revoked Client identity stream should abort")
                .is_cancelled()
        );
        assert!(
            revoked_task
                .await
                .expect_err("later stream for revoked identity should abort")
                .is_cancelled()
        );
        assert_eq!(registry.tracked_visitor_stream_count(), 0);

        keep_running.store(false, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_resets_only_removed_hostname_streams() -> io::Result<()> {
        let identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(TunnelId::parse("tunnel-1").unwrap()),
                public_hostnames: vec![
                    public_hostname("app.example.test"),
                    public_hostname("api.example.test"),
                ],
                authorized_client_identities: vec![identity.client_identity.clone()],
            }],
        )?;

        let keep_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let app_keep = keep_running.clone();
        let api_keep = keep_running.clone();
        let app_task = tokio::spawn(async move {
            while app_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let api_task = tokio::spawn(async move {
            while api_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });

        registry.track_visitor_stream(
            public_hostname("app.example.test"),
            1,
            identity.client_identity.clone(),
            app_task.abort_handle(),
        );
        registry.track_visitor_stream(
            public_hostname("api.example.test"),
            1,
            identity.client_identity.clone(),
            api_task.abort_handle(),
        );

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-2").unwrap()),
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![identity.client_identity.clone()],
                }],
            )
            .await?;
        assert_eq!(dispatch.connections_closed, 0);
        assert_eq!(dispatch.streams_reset, 1);
        assert!(
            api_task
                .await
                .expect_err("removed Public hostname stream should abort")
                .is_cancelled()
        );
        assert_eq!(
            registry.tracked_visitor_hostnames(),
            vec![public_hostname("app.example.test")]
        );
        assert!(
            registry
                .authorization()
                .current()
                .authorizes_client_identity(&identity.client_identity)
        );

        keep_running.store(false, std::sync::atomic::Ordering::Relaxed);
        app_task
            .await
            .expect("surviving Public hostname stream should finish normally");
        Ok(())
    }

    #[tokio::test]
    async fn post_replace_prepare_failure_does_not_restore_revoked_authorization() -> io::Result<()>
    {
        let first = generate_test_client_identity()?;
        let second = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(TunnelId::parse("tunnel-1").unwrap()),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![first.client_identity.clone()],
            }],
        )?;

        let _ = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-2").unwrap()),
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![second.client_identity.clone()],
                }],
            )
            .await?;
        assert!(
            !registry
                .authorization()
                .current()
                .authorizes_client_identity(&first.client_identity)
        );

        let invalid = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-3").unwrap()),
                    public_hostnames: vec![],
                    authorized_client_identities: vec![first.client_identity.clone()],
                }],
            )
            .await;
        assert!(
            invalid.is_err(),
            "invalid candidate must fail before commit"
        );
        assert!(
            !registry
                .authorization()
                .current()
                .authorizes_client_identity(&first.client_identity),
            "failed prepare must never restore a revoked Client identity"
        );
        assert!(
            registry
                .authorization()
                .current()
                .authorizes_client_identity(&second.client_identity)
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_rejects_static_authorization() -> io::Result<()> {
        let identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![identity.client_identity.clone()],
            }],
        )?;

        let error = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-a").unwrap()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![identity.client_identity.clone()],
                }],
            )
            .await
            .expect_err("static authorization must reject live replacement");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("static Server authorization does not support live replacement")
        );
        assert!(
            registry
                .authorization()
                .current()
                .authorizes_client_identity(&identity.client_identity)
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_opens_readiness_only_after_first_success() -> io::Result<()> {
        let identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::empty_managed();
        let gate = ReadinessGate::new(false);
        registry.set_readiness(gate.clone());
        assert!(!gate.is_ready());

        let invalid = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-a").unwrap()),
                    public_hostnames: vec![],
                    authorized_client_identities: vec![identity.client_identity.clone()],
                }],
            )
            .await;
        assert!(invalid.is_err());
        assert!(
            !gate.is_ready(),
            "failed replace must leave readiness closed"
        );

        registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-a").unwrap()),
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![identity.client_identity.clone()],
                }],
            )
            .await?;
        assert!(
            gate.is_ready(),
            "first successful replace must open readiness"
        );

        let gate_stays = gate.is_ready();
        registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-a").unwrap()),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![identity.client_identity.clone()],
                }],
            )
            .await?;
        assert_eq!(gate.is_ready(), gate_stays);
        assert!(
            registry
                .authorization()
                .current()
                .tunnel_index_for_public_hostname(&public_hostname("api.example.test"))
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_empty_candidate_opens_readiness() -> io::Result<()> {
        let registry = TunnelRegistry::empty_managed();
        let gate = ReadinessGate::new(false);
        registry.set_readiness(gate.clone());

        registry
            .replace_authorization(&server_hostname("tunnel.example.test"), &[])
            .await?;
        assert!(
            gate.is_ready(),
            "valid empty authorization must open Server readiness on first success"
        );
        assert_eq!(registry.pool_count().await, 0);
        assert_eq!(registry.authorization().current().tunnel_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn replace_authorization_readers_observe_old_or_new_not_mixed() -> io::Result<()> {
        let old_identity = generate_test_client_identity()?;
        let new_identity = generate_test_client_identity()?;
        let tunnel_id = TunnelId::parse("tunnel-a").unwrap();
        let registry = Arc::new(TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(tunnel_id.clone()),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![old_identity.client_identity.clone()],
            }],
        )?);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mixed_views = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut readers = Vec::new();
        for _ in 0..8 {
            let registry = registry.clone();
            let stop = stop.clone();
            let observations = observations.clone();
            let mixed_views = mixed_views.clone();
            let old_identity = old_identity.client_identity.clone();
            let new_identity = new_identity.client_identity.clone();
            readers.push(tokio::spawn(async move {
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    let snapshot = registry.authorization().current();
                    let sees_old = snapshot
                        .tunnel_index_for_public_hostname(&public_hostname("app.example.test"))
                        .is_some();
                    let sees_new = snapshot
                        .tunnel_index_for_public_hostname(&public_hostname("api.example.test"))
                        .is_some();
                    let authorizes_old = snapshot.authorizes_client_identity(&old_identity);
                    let authorizes_new = snapshot.authorizes_client_identity(&new_identity);
                    let coherent_old = sees_old && !sees_new && authorizes_old && !authorizes_new;
                    let coherent_new = !sees_old && sees_new && !authorizes_old && authorizes_new;
                    if !(coherent_old || coherent_new) {
                        mixed_views.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    observations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }));
        }

        while observations.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        let before = observations.load(std::sync::atomic::Ordering::Relaxed);
        registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(tunnel_id),
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![new_identity.client_identity.clone()],
                }],
            )
            .await?;
        while observations.load(std::sync::atomic::Ordering::Relaxed) <= before {
            tokio::task::yield_now().await;
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        for reader in readers {
            reader.await.expect("reader task must not panic");
        }
        assert!(observations.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert_eq!(mixed_views.load(std::sync::atomic::Ordering::Relaxed), 0);
        Ok(())
    }

    #[tokio::test]
    async fn reset_streams_for_member_aborts_only_matching_serving_connection() -> io::Result<()> {
        let registry = TunnelRegistry::single(vec![public_hostname("app.example.test")])?;
        let keep_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let first_keep = keep_running.clone();
        let second_keep = keep_running.clone();
        let first_task = tokio::spawn(async move {
            while first_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let second_task = tokio::spawn(async move {
            while second_keep.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::task::yield_now().await;
            }
        });
        let identity = generate_test_client_identity()?.client_identity;
        registry.track_visitor_stream(
            public_hostname("app.example.test"),
            7,
            identity.clone(),
            first_task.abort_handle(),
        );
        registry.track_visitor_stream(
            public_hostname("app.example.test"),
            8,
            identity,
            second_task.abort_handle(),
        );

        assert_eq!(registry.reset_streams_for_member(7), 1);
        assert!(
            first_task
                .await
                .expect_err("member stream should abort")
                .is_cancelled()
        );
        assert_eq!(registry.tracked_visitor_stream_count(), 1);

        keep_running.store(false, std::sync::atomic::Ordering::Relaxed);
        second_task
            .await
            .expect("other member stream should finish normally");
        Ok(())
    }

    fn generate_test_client_identity() -> io::Result<GeneratedClientIdentity> {
        generate_client_identity().map_err(io::Error::other)
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn make_self_signed_cert(server_name: &str) -> io::Result<(CertificateDer<'static>, Vec<u8>)> {
        let certified_key =
            generate_simple_self_signed(vec![server_name.to_owned()]).map_err(io::Error::other)?;
        Ok((
            CertificateDer::from(certified_key.cert),
            certified_key.signing_key.serialize_der(),
        ))
    }

    fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn client_certificate_chain(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<Vec<CertificateDer<'static>>> {
        certificate_chain_from_pem(client_identity.certificate_pem.as_bytes())
            .map_err(io::Error::other)
    }

    fn client_private_key(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<PrivateKeyDer<'static>> {
        private_key_from_pem(client_identity.private_key_pem.as_bytes()).map_err(|source| {
            match source {
                PemError::NoItemsFound => {
                    io::Error::new(io::ErrorKind::InvalidData, "missing client private key")
                }
                other => io::Error::other(other),
            }
        })
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        _client_connection: Connection,
        server_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect(client_identity: &GeneratedClientIdentity) -> io::Result<Self> {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
            let server_endpoint = Endpoint::server(
                make_server_quic_config_with_client_auth(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                    std::slice::from_ref(&client_identity.client_identity),
                )
                .map_err(io::Error::other)?,
                localhost(0),
            )
            .map_err(io::Error::other)?;
            let server_addr = server_endpoint.local_addr()?;

            let mut client_endpoint = Endpoint::client(localhost(0)).map_err(io::Error::other)?;
            client_endpoint.set_default_client_config(
                make_client_quic_config_with_client_auth(
                    root_store_with(&certificate)?,
                    client_certificate_chain(client_identity)?,
                    client_private_key(client_identity)?,
                )
                .map_err(io::Error::other)?,
            );

            let accept_connection = async {
                let incoming = timeout(Duration::from_secs(1), server_endpoint.accept())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
                    })?;
                timeout(Duration::from_secs(1), incoming)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
                    .map_err(io::Error::other)
            };
            let connect_client = async {
                client_endpoint
                    .connect(server_addr, "tunnel.example.test")
                    .map_err(io::Error::other)?
                    .await
                    .map_err(io::Error::other)
            };
            let (server_connection, client_connection) =
                tokio::try_join!(accept_connection, connect_client)?;

            Ok(Self {
                _server_endpoint: server_endpoint,
                _client_endpoint: client_endpoint,
                _client_connection: client_connection,
                server_connection,
            })
        }
    }
}
