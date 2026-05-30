use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use quinn::Connection;
use rustls::pki_types::CertificateDer;

use crate::{
    ClientIdentity, PublicHostname, ServerHostname, ServerTunnelConfig,
    client_identity_from_certificate_der,
};

use super::active_client::ActiveClientSlot;

pub(crate) enum TunnelRouteOutcome {
    Unauthorized,
    NoActiveTunnelConnection,
    Connected(Connection),
}

#[derive(Clone)]
pub(crate) struct TunnelRegistry {
    client_identity_to_tunnel: Arc<HashMap<ClientIdentity, usize>>,
    public_hostname_to_tunnel: Arc<HashMap<PublicHostname, usize>>,
    tunnel_slots: Arc<Vec<ActiveClientSlot>>,
    accepting: Arc<AtomicBool>,
}

impl TunnelRegistry {
    #[cfg(test)]
    pub(crate) fn single(public_hostnames: Vec<PublicHostname>) -> io::Result<Self> {
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
        Ok(Self {
            client_identity_to_tunnel: Arc::new(HashMap::new()),
            public_hostname_to_tunnel: Arc::new(public_hostname_to_tunnel),
            tunnel_slots: Arc::new(vec![ActiveClientSlot::new()]),
            accepting: Arc::new(AtomicBool::new(true)),
        })
    }
    pub(crate) fn configured(
        server_hostname: &ServerHostname,
        tunnels: &[ServerTunnelConfig],
    ) -> io::Result<Self> {
        let mut client_identity_to_tunnel = HashMap::new();
        let mut public_hostname_to_tunnel = HashMap::new();
        let mut seen_client_identities = HashSet::new();
        let mut seen_public_hostnames = HashSet::new();
        let mut tunnel_slots = Vec::with_capacity(tunnels.len());
        for (index, tunnel) in tunnels.iter().enumerate() {
            if !seen_client_identities.insert(tunnel.client_identity.clone()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "server.tunnels[].client-identity must be unique: {}",
                        tunnel.client_identity
                    ),
                ));
            }
            if tunnel.public_hostnames.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "server.tunnels[].public-hostnames must not be empty",
                ));
            }
            client_identity_to_tunnel.insert(tunnel.client_identity.clone(), index);
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
            tunnel_slots.push(ActiveClientSlot::new());
        }
        Ok(Self {
            client_identity_to_tunnel: Arc::new(client_identity_to_tunnel),
            public_hostname_to_tunnel: Arc::new(public_hostname_to_tunnel),
            tunnel_slots: Arc::new(tunnel_slots),
            accepting: Arc::new(AtomicBool::new(true)),
        })
    }

    pub(crate) async fn route_tunnel_connection(
        &self,
        public_hostname: &PublicHostname,
    ) -> TunnelRouteOutcome {
        let Some(tunnel_index) = self.public_hostname_to_tunnel.get(public_hostname).copied()
        else {
            return TunnelRouteOutcome::Unauthorized;
        };
        let Some(connection) = self.tunnel_slots[tunnel_index].current_connection().await else {
            return TunnelRouteOutcome::NoActiveTunnelConnection;
        };
        TunnelRouteOutcome::Connected(connection)
    }

    pub(crate) async fn register(&self, connection: Connection) {
        if !self.accepting.load(Ordering::SeqCst) {
            connection.close(0_u32.into(), b"server shutting down");
            return;
        }
        let Some((tunnel_index, client_identity)) = self.tunnel_registration_context(&connection)
        else {
            connection.close(0_u32.into(), b"unmapped client identity");
            return;
        };
        self.tunnel_slots[tunnel_index]
            .register(connection, client_identity)
            .await;
    }

    pub(crate) async fn close_all(&self, reason: &'static [u8]) -> usize {
        let mut closed = 0;
        for slot in self.tunnel_slots.iter() {
            if slot.close_active_connection(reason).await {
                closed += 1;
            }
        }
        closed
    }

    pub(crate) async fn active_connection_count(&self) -> usize {
        let mut active = 0;
        for slot in self.tunnel_slots.iter() {
            if slot.current_connection().await.is_some() {
                active += 1;
            }
        }
        active
    }

    pub(crate) fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::SeqCst);
    }

    fn tunnel_registration_context(
        &self,
        connection: &Connection,
    ) -> Option<(usize, ClientIdentity)> {
        let identity = client_identity_from_connection(connection)?;
        let tunnel_index = self.client_identity_to_tunnel.get(&identity).copied()?;
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
                client_identity: client_identity.client_identity.clone(),
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
                client_identity: client_identity.client_identity.clone(),
            }],
        )?;

        registry.stop_accepting();
        registry.register(fixture.server_connection).await;

        assert!(matches!(
            registry
                .route_tunnel_connection(&public_hostname("app.example.test"))
                .await,
            TunnelRouteOutcome::NoActiveTunnelConnection
        ));
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
