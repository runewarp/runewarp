use std::collections::HashSet;
use std::io;
use std::sync::Arc;
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
use super::authorization::{AuthorizationState, ServerAuthorization};

pub(crate) enum TunnelRouteOutcome {
    Unauthorized,
    NoActiveTunnelConnection,
    Connected(SelectedTunnelConnection),
}

struct ActiveVisitorStream {
    stream_id: u64,
    #[allow(dead_code)] // read by selective Public-hostname stream reset dispatch
    public_hostname: PublicHostname,
    #[allow(dead_code)] // retained for selective revocation against the serving connection
    member_id: u64,
    #[allow(dead_code)] // read by selective Public-hostname stream reset dispatch
    abort_handle: AbortHandle,
}

#[derive(Clone)]
pub(crate) struct TunnelRegistry {
    authorization: Arc<AuthorizationState>,
    tunnel_pools: Arc<Vec<ActiveClientPool>>,
    visitor_streams: Arc<RwLock<Vec<ActiveVisitorStream>>>,
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
            tunnel_pools: Arc::new(vec![ActiveClientPool::new()]),
            visitor_streams: Arc::new(RwLock::new(Vec::new())),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            accepting_tunnel_connections: Arc::new(AtomicBool::new(true)),
            admitting_streams: Arc::new(AtomicBool::new(true)),
        })
    }

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
            tunnel_pools: Arc::new(tunnel_pools),
            visitor_streams: Arc::new(RwLock::new(Vec::new())),
            next_stream_id: Arc::new(AtomicU64::new(1)),
            accepting_tunnel_connections: Arc::new(AtomicBool::new(true)),
            admitting_streams: Arc::new(AtomicBool::new(true)),
        })
    }

    #[allow(dead_code)] // shared authorization handle for managed commit and verifier wiring
    pub(crate) fn authorization(&self) -> Arc<AuthorizationState> {
        self.authorization.clone()
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
        let Some(pool) = self.tunnel_pools.get(tunnel_index) else {
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
        let Some(pool) = self.tunnel_pools.get(tunnel_index) else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return;
        };
        pool.register(connection, client_identity).await;
    }

    pub(crate) async fn close_all(&self, reason: &'static [u8]) -> usize {
        let mut closed = 0;
        for pool in self.tunnel_pools.iter() {
            closed += pool.close_all_connections(reason).await;
        }
        closed
    }

    #[allow(dead_code)] // selective connection close dispatch for managed authorization commits
    pub(crate) async fn close_connections_for_identities(
        &self,
        identities: &HashSet<ClientIdentity>,
        reason: &'static [u8],
    ) -> usize {
        let mut closed = 0;
        for pool in self.tunnel_pools.iter() {
            closed += pool
                .close_connections_for_identities(identities, reason)
                .await;
        }
        closed
    }

    pub(crate) async fn track_visitor_stream(
        &self,
        public_hostname: PublicHostname,
        member_id: u64,
        abort_handle: AbortHandle,
    ) -> u64 {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        self.visitor_streams
            .write()
            .await
            .push(ActiveVisitorStream {
                stream_id,
                public_hostname,
                member_id,
                abort_handle,
            });
        stream_id
    }

    pub(crate) async fn untrack_visitor_stream(&self, stream_id: u64) {
        self.visitor_streams
            .write()
            .await
            .retain(|stream| stream.stream_id != stream_id);
    }

    #[allow(dead_code)] // selective Visitor stream reset dispatch for managed authorization commits
    pub(crate) async fn reset_streams_for_public_hostname(
        &self,
        public_hostname: &PublicHostname,
    ) -> usize {
        let mut streams = self.visitor_streams.write().await;
        let mut reset = 0;
        streams.retain(|stream| {
            if &stream.public_hostname == public_hostname {
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
    pub(crate) async fn tracked_visitor_stream_count(&self) -> usize {
        self.visitor_streams.read().await.len()
    }

    #[cfg(test)]
    pub(crate) async fn tracked_visitor_hostnames(&self) -> Vec<PublicHostname> {
        self.visitor_streams
            .read()
            .await
            .iter()
            .map(|stream| stream.public_hostname.clone())
            .collect()
    }

    pub(crate) async fn active_connection_count(&self) -> usize {
        let mut active = 0;
        for pool in self.tunnel_pools.iter() {
            active += pool.connection_count().await;
        }
        active
    }

    pub(crate) async fn active_stream_count(&self) -> usize {
        let mut active = 0;
        for pool in self.tunnel_pools.iter() {
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
        let app_stream_id = registry
            .track_visitor_stream(
                public_hostname("app.example.test"),
                1,
                app_task.abort_handle(),
            )
            .await;
        let api_stream_id = registry
            .track_visitor_stream(
                public_hostname("api.example.test"),
                2,
                api_task.abort_handle(),
            )
            .await;

        assert_eq!(
            registry
                .reset_streams_for_public_hostname(&public_hostname("app.example.test"))
                .await,
            1
        );
        assert!(
            app_task
                .await
                .expect_err("app stream should abort")
                .is_cancelled()
        );
        assert_eq!(
            registry.tracked_visitor_hostnames().await,
            vec![public_hostname("api.example.test")]
        );

        keep_running.store(false, std::sync::atomic::Ordering::Relaxed);
        api_task.await.expect("api stream should finish normally");
        registry.untrack_visitor_stream(api_stream_id).await;
        registry.untrack_visitor_stream(app_stream_id).await;
        assert_eq!(registry.tracked_visitor_stream_count().await, 0);
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
