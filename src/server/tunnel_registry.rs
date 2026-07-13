use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use quinn::Connection;
use rustls::pki_types::CertificateDer;
use tokio::sync::RwLock;
use tokio::task::AbortHandle;

use crate::{ClientIdentity, PublicHostname, client_identity_from_certificate_der};
#[cfg(test)]
use crate::{ServerHostname, ServerTunnelConfig};

use super::active_client::{ActiveClientPool, SelectedTunnelConnection};
use super::authorization::{
    AuthorizationSnapshot, AuthorizationState, PreparedAuthorization, ServerAuthorization,
};

pub(crate) enum TunnelRouteOutcome {
    Unauthorized,
    NoActiveTunnelConnection,
    Connected(SelectedTunnelConnection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // returned by commit_authorization for managed authorization applies
pub(crate) struct LiveWorkDispatch {
    pub connections_closed: usize,
    pub streams_reset: usize,
}

struct ActiveVisitorStream {
    stream_id: u64,
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
    visitor_streams: Arc<StdRwLock<Vec<ActiveVisitorStream>>>,
    next_stream_id: Arc<AtomicU64>,
    accepting_tunnel_connections: Arc<AtomicBool>,
    admitting_streams: Arc<AtomicBool>,
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
        Ok(Self {
            authorization: Arc::new(AuthorizationState::from_snapshot_for_test(snapshot)),
            tunnel_pools: Arc::new(RwLock::new(vec![ActiveClientPool::new()])),
            visitor_streams: Arc::new(StdRwLock::new(Vec::new())),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            accepting_tunnel_connections: Arc::new(AtomicBool::new(true)),
            admitting_streams: Arc::new(AtomicBool::new(true)),
        })
    }

    #[cfg(test)]
    pub(crate) fn configured(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        Self::from_authorization(ServerAuthorization::from_tunnels(server_hostname, tunnels)?)
    }

    pub(crate) fn from_authorization(authorization: ServerAuthorization) -> io::Result<Self> {
        let tunnel_count = authorization.current_tunnel_count();
        let mut tunnel_pools = Vec::with_capacity(tunnel_count);
        for _ in 0..tunnel_count {
            tunnel_pools.push(ActiveClientPool::new());
        }
        Ok(Self {
            authorization: authorization.state().clone(),
            tunnel_pools: Arc::new(RwLock::new(tunnel_pools)),
            visitor_streams: Arc::new(StdRwLock::new(Vec::new())),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            accepting_tunnel_connections: Arc::new(AtomicBool::new(true)),
            admitting_streams: Arc::new(AtomicBool::new(true)),
        })
    }

    #[allow(dead_code)] // shared handle for managed authorization commit and tests
    pub(crate) fn authorization(&self) -> Arc<AuthorizationState> {
        self.authorization.clone()
    }

    #[allow(dead_code)] // managed authorization apply path; exercised in unit tests today
    pub(crate) async fn commit_authorization(
        &self,
        prepared: PreparedAuthorization,
    ) -> LiveWorkDispatch {
        let previous = self.authorization.current();
        let next = self.authorization.commit(prepared);
        self.ensure_pool_capacity(next.tunnel_count()).await;

        let removed_identities = previous
            .trusted_client_identities()
            .difference(next.trusted_client_identities())
            .cloned()
            .collect::<HashSet<_>>();
        let connections_closed = if removed_identities.is_empty() {
            0
        } else {
            self.close_connections_for_identities(&removed_identities, b"authorization revoked")
                .await
        };

        let streams_reset = self.reset_streams_not_authorized_by(&next);

        LiveWorkDispatch {
            connections_closed,
            streams_reset,
        }
    }

    #[allow(dead_code)] // called from commit_authorization
    async fn ensure_pool_capacity(&self, tunnel_count: usize) {
        let mut pools = self.tunnel_pools.write().await;
        while pools.len() < tunnel_count {
            pools.push(ActiveClientPool::new());
        }
    }

    async fn pool_at(&self, tunnel_index: usize) -> Option<ActiveClientPool> {
        self.tunnel_pools.read().await.get(tunnel_index).cloned()
    }

    pub(crate) async fn route_tunnel_connection(
        &self,
        public_hostname: &PublicHostname,
    ) -> TunnelRouteOutcome {
        if !self.admitting_streams.load(Ordering::SeqCst) {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        }
        let snapshot = self.authorization.current();
        let Some(tunnel_index) = snapshot.tunnel_index_for_public_hostname(public_hostname) else {
            return TunnelRouteOutcome::Unauthorized;
        };
        let Some(pool) = self.pool_at(tunnel_index).await else {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        };
        let Some(connection) = pool.select_connection().await else {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        };
        TunnelRouteOutcome::Connected(connection)
    }

    pub(crate) async fn register(&self, connection: Connection) {
        if !self.accepting_tunnel_connections.load(Ordering::SeqCst) {
            connection.close(0_u32.into(), b"server shutting down");
            return;
        }
        let Some((tunnel_index, client_identity)) = self.tunnel_registration_context(&connection)
        else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return;
        };
        let Some(pool) = self.pool_at(tunnel_index).await else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return;
        };
        pool.register(connection, client_identity).await;
    }

    pub(crate) async fn close_all(&self, reason: &'static [u8]) -> usize {
        let pools = self.tunnel_pools.read().await.clone();
        let mut closed = 0;
        for pool in pools.iter() {
            closed += pool.close_all_connections(reason).await;
        }
        closed
    }

    #[allow(dead_code)] // called from commit_authorization
    pub(crate) async fn close_connections_for_identities(
        &self,
        identities: &HashSet<ClientIdentity>,
        reason: &'static [u8],
    ) -> usize {
        let pools = self.tunnel_pools.read().await.clone();
        let mut closed = 0;
        for pool in pools.iter() {
            closed += pool
                .close_connections_for_identities(identities, reason)
                .await;
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
            .push(ActiveVisitorStream {
                stream_id,
                public_hostname,
                member_id,
                client_identity,
                abort_handle,
            });
        stream_id
    }

    pub(crate) fn untrack_visitor_stream(&self, stream_id: u64) {
        self.visitor_streams
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|stream| stream.stream_id != stream_id);
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
        streams.retain(|stream| {
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
            .iter()
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
    use std::io::{self, Cursor};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::time::timeout;

    use super::{TunnelRegistry, TunnelRouteOutcome};
    use crate::{
        GeneratedClientIdentity, PublicHostname, ServerHostname, ServerTunnelConfig,
        generate_client_identity, make_client_quic_config_with_client_auth,
        make_server_quic_config_with_client_auth,
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
    async fn commit_authorization_grows_pools_and_revokes_removed_identities() -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![first_identity.client_identity.clone()],
            }],
        )?;
        assert_eq!(registry.pool_count().await, 1);

        let first_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        registry
            .register(first_fixture.server_connection.clone())
            .await;

        let prepared = registry.authorization().prepare(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![first_identity.client_identity.clone()],
                },
                ServerTunnelConfig {
                    public_hostnames: vec![public_hostname("api.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                },
            ],
        )?;
        let dispatch = registry.commit_authorization(prepared).await;
        assert_eq!(dispatch.connections_closed, 0);
        assert_eq!(dispatch.streams_reset, 0);
        assert_eq!(registry.pool_count().await, 2);
        assert!(
            registry
                .authorization()
                .current()
                .authorizes_client_identity(&second_identity.client_identity)
        );

        let revoke = registry.authorization().prepare(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                public_hostnames: vec![public_hostname("api.example.test")],
                authorized_client_identities: vec![second_identity.client_identity.clone()],
            }],
        )?;
        let dispatch = registry.commit_authorization(revoke).await;
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
    async fn commit_authorization_resets_streams_for_revoked_identities_and_remapped_hostnames()
    -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
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

        let remapped = registry.authorization().prepare(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![first_identity.client_identity.clone()],
                },
                ServerTunnelConfig {
                    public_hostnames: vec![public_hostname("shared.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                },
            ],
        )?;
        let dispatch = registry.commit_authorization(remapped).await;
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

        let revoke_first = registry.authorization().prepare(
            &server_hostname("tunnel.example.test"),
            &[
                ServerTunnelConfig {
                    public_hostnames: vec![public_hostname("app.example.test")],
                    authorized_client_identities: vec![
                        generate_test_client_identity()?.client_identity,
                    ],
                },
                ServerTunnelConfig {
                    public_hostnames: vec![public_hostname("shared.example.test")],
                    authorized_client_identities: vec![second_identity.client_identity.clone()],
                },
            ],
        )?;
        let dispatch = registry.commit_authorization(revoke_first).await;
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
        rustls_pemfile::certs(&mut Cursor::new(client_identity.certificate_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)
    }

    fn client_private_key(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut Cursor::new(client_identity.private_key_pem.as_bytes()))
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing client private key"))
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
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
            let (server_connection, _client_connection) =
                tokio::try_join!(accept_connection, connect_client)?;

            Ok(Self {
                _server_endpoint: server_endpoint,
                _client_endpoint: client_endpoint,
                server_connection,
            })
        }
    }
}
