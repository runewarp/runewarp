mod service;
mod settings_resolution;
mod tunnel_stream;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint};

use self::tunnel_stream::TunnelConnectionStreamHandler;
use crate::{
    ClientServiceSettings, ClientTlsMode, HANDSHAKE_TIMEOUT, quic::with_handshake_timeout,
};

pub(crate) use service::validate_services;
pub use settings_resolution::{
    ClientRuntimeArgs, ClientSettingsResolutionDefaults, ClientSettingsResolutionError,
    SelectedClientConfig, resolve_client_settings_from_cli, resolve_selected_client_settings,
    select_client_config,
};

#[derive(Clone)]
pub struct ClientConfig {
    pub local_bind_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub backend_address: String,
    pub quic_client_config: quinn::ClientConfig,
}

#[derive(Clone)]
pub(crate) struct RoutedClientConfig {
    pub(crate) local_bind_addr: SocketAddr,
    pub(crate) server_addr: SocketAddr,
    pub(crate) server_name: String,
    pub(crate) services: Vec<ClientServiceSettings>,
    pub(crate) quic_client_config: quinn::ClientConfig,
    pub(crate) hostname_tls_configs: HashMap<String, Arc<rustls::ServerConfig>>,
}

enum ClientRouteMode {
    CatchAll {
        backend_address: String,
    },
    Routed {
        services: Vec<ClientServiceSettings>,
        hostname_tls_configs: HashMap<String, Arc<rustls::ServerConfig>>,
    },
}

pub struct Client {
    endpoint: Endpoint,
    connection: Connection,
    tunnel_stream_handler: TunnelConnectionStreamHandler,
}

#[derive(Debug)]
pub enum ClientConnectError {
    Bind(io::Error),
    Connect(quinn::ConnectError),
    Handshake(quinn::ConnectionError),
}

impl fmt::Display for ClientConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(_) => formatter.write_str("failed to bind the client endpoint"),
            Self::Connect(_) => formatter.write_str("failed to start the client connection"),
            Self::Handshake(_) => formatter.write_str("client QUIC handshake failed"),
        }
    }
}

impl std::error::Error for ClientConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::Handshake(error) => Some(error),
        }
    }
}

impl ClientConnectError {
    pub fn is_unauthorized_client_identity(&self) -> bool {
        matches!(self, Self::Handshake(error) if error.to_string().contains("ApplicationVerificationFailure"))
    }
}

impl Client {
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientConnectError> {
        Self::connect_internal(
            config.local_bind_addr,
            config.server_addr,
            config.server_name,
            config.quic_client_config,
            ClientRouteMode::CatchAll {
                backend_address: config.backend_address,
            },
        )
        .await
    }

    pub(crate) async fn connect_with_services(
        config: RoutedClientConfig,
    ) -> Result<Self, ClientConnectError> {
        Self::connect_internal(
            config.local_bind_addr,
            config.server_addr,
            config.server_name,
            config.quic_client_config,
            ClientRouteMode::Routed {
                services: config.services,
                hostname_tls_configs: config.hostname_tls_configs,
            },
        )
        .await
    }

    async fn connect_internal(
        local_bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: String,
        quic_client_config: quinn::ClientConfig,
        route_mode: ClientRouteMode,
    ) -> Result<Self, ClientConnectError> {
        let mut endpoint = Endpoint::client(local_bind_addr).map_err(ClientConnectError::Bind)?;
        endpoint.set_default_client_config(quic_client_config);

        let connection = with_handshake_timeout(
            endpoint
                .connect(server_addr, &server_name)
                .map_err(ClientConnectError::Connect)?,
            HANDSHAKE_TIMEOUT,
            || quinn::ConnectionError::TimedOut,
        )
        .await
        .map_err(ClientConnectError::Handshake)?;
        let (services, hostname_tls_configs) = services_and_configs_for_route_mode(route_mode);
        let tunnel_stream_handler =
            TunnelConnectionStreamHandler::new(services, hostname_tls_configs);

        Ok(Self {
            endpoint,
            connection,
            tunnel_stream_handler,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        loop {
            match self.connection.accept_bi().await {
                Ok((send, recv)) => {
                    let tunnel_stream_handler = self.tunnel_stream_handler.clone();
                    tokio::spawn(async move {
                        let _ = tunnel_stream_handler.handle(send, recv).await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }
}

fn services_and_configs_for_route_mode(
    route_mode: ClientRouteMode,
) -> (
    Vec<ClientServiceSettings>,
    HashMap<String, Arc<rustls::ServerConfig>>,
) {
    match route_mode {
        ClientRouteMode::CatchAll { backend_address } => (
            vec![ClientServiceSettings {
                public_hostnames: None,
                backend_address,
                tls_mode: ClientTlsMode::Passthrough,
            }],
            HashMap::new(),
        ),
        ClientRouteMode::Routed {
            services,
            hostname_tls_configs,
        } => (services, hostname_tls_configs),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Cursor;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::time::timeout;

    use super::{Client, ClientConfig, ClientConnectError};
    use crate::{
        GeneratedClientIdentity, generate_client_identity,
        make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    };

    #[test]
    fn client_connect_error_display_omits_nested_transport_detail() {
        assert_eq!(
            ClientConnectError::Bind(io::Error::other("address already in use")).to_string(),
            "failed to bind the client endpoint"
        );
        assert_eq!(
            ClientConnectError::Handshake(quinn::ConnectionError::TimedOut).to_string(),
            "client QUIC handshake failed"
        );
    }

    #[tokio::test]
    async fn handshake_errors_detect_unauthorized_client_identity() -> io::Result<()> {
        let authorized_client_identity = generate_test_client_identity()?;
        let unauthorized_client_identity = generate_test_client_identity()?;
        let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
        let server_endpoint = Endpoint::server(
            make_server_quic_config_with_client_auth(
                vec![certificate.clone()],
                private_key_from_der(&private_key),
                std::slice::from_ref(&authorized_client_identity.client_identity),
            )
            .map_err(io::Error::other)?,
            localhost(0),
        )
        .map_err(io::Error::other)?;

        let client_config = ClientConfig {
            local_bind_addr: localhost(0),
            server_addr: server_endpoint.local_addr()?,
            server_name: "tunnel.example.test".to_owned(),
            backend_address: "127.0.0.1:443".to_owned(),
            quic_client_config: make_client_quic_config_with_client_auth(
                root_store_with(&certificate)?,
                client_certificate_chain(&unauthorized_client_identity)?,
                client_private_key(&unauthorized_client_identity)?,
            )
            .map_err(io::Error::other)?,
        };

        let accept_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(1), server_endpoint.accept())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
                })?;
            let _ = timeout(Duration::from_secs(1), incoming)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?;
            Ok::<(), io::Error>(())
        });

        match Client::connect(client_config).await {
            Err(error) => {
                assert!(error.is_unauthorized_client_identity());
            }
            Ok(client) => {
                let run_error = timeout(Duration::from_secs(1), client.run())
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "unauthorized connection should close quickly",
                        )
                    })?
                    .expect_err("unauthorized connection should not stay open");
                assert!(
                    run_error
                        .to_string()
                        .contains("ApplicationVerificationFailure")
                );
            }
        }
        accept_task.await.map_err(|join_error| {
            io::Error::other(format!("accept task failed: {join_error}"))
        })??;
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
}
