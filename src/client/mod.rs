mod address_controller;
mod assignment_convergence;
mod managed_adapter;
mod service;
mod stream_limits;
mod termination_tls;
mod tunnel_stream;

pub use address_controller::{
    AddressController, AddressControllerShutdown, AddressControllerView, AddressWorkerControl,
    AddressWorkerFactory, MaintenanceIntent,
};
pub use assignment_convergence::AssignmentConvergence;
pub use managed_adapter::ClientAssignmentAdapter;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint};

pub(crate) use self::stream_limits::{ClientStreamBudget, ClientStreamLimits};
pub(crate) use self::termination_tls::TerminationTlsConfigs;
use self::tunnel_stream::TunnelConnectionStreamHandler;
use crate::{
    ClientTlsMode, HANDSHAKE_TIMEOUT, ServiceConfig,
    quic::with_handshake_timeout,
    shutdown::{OrderlyShutdown, ShutdownMode},
};

pub use crate::config::client::{
    ClientConfigResolutionDefaults, ClientConfigResolutionError, ClientRuntimeArgs,
    SelectedClientConfig, resolve_client_config_from_cli, resolve_selected_client_config,
    select_client_config,
};
pub(crate) use service::{ServiceSelector, validate_services};

#[derive(Clone)]
pub struct ClientConnectConfig {
    pub local_bind_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub backend_address: String,
    pub quic_client_config: quinn::ClientConfig,
}

#[derive(Clone)]
pub(crate) struct RoutedClientConnectConfig {
    pub(crate) local_bind_addr: SocketAddr,
    pub(crate) server_addr: SocketAddr,
    pub(crate) server_name: String,
    pub(crate) services: Vec<ServiceConfig>,
    pub(crate) quic_client_config: quinn::ClientConfig,
    pub(crate) termination_tls_configs: TerminationTlsConfigs,
    pub(crate) stream_budget: Arc<ClientStreamBudget>,
}

enum ClientRouteMode {
    CatchAll {
        backend_address: String,
    },
    Routed {
        services: Vec<ServiceConfig>,
        termination_tls_configs: TerminationTlsConfigs,
        stream_budget: Arc<ClientStreamBudget>,
    },
}

pub struct Client {
    endpoint: Endpoint,
    connection: Connection,
    tunnel_stream_handler: TunnelConnectionStreamHandler,
    stream_budget: Arc<ClientStreamBudget>,
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
    pub async fn connect(config: ClientConnectConfig) -> Result<Self, ClientConnectError> {
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
        config: RoutedClientConnectConfig,
    ) -> Result<Self, ClientConnectError> {
        Self::connect_internal(
            config.local_bind_addr,
            config.server_addr,
            config.server_name,
            config.quic_client_config,
            ClientRouteMode::Routed {
                services: config.services,
                termination_tls_configs: config.termination_tls_configs,
                stream_budget: config.stream_budget,
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
        let (services, termination_tls_configs, stream_budget) =
            services_and_configs_for_route_mode(route_mode);
        let tunnel_stream_handler = TunnelConnectionStreamHandler::new(
            services,
            termination_tls_configs,
            stream_budget.limits(),
        );

        Ok(Self {
            endpoint,
            connection,
            tunnel_stream_handler,
            stream_budget,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        loop {
            match self.connection.accept_bi().await {
                Ok((send, recv)) => {
                    self.spawn_stream_handler(send, recv);
                }
                Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn run_until_shutdown<Shutdown>(
        self,
        shutdown_signal: Shutdown,
    ) -> Result<(), quinn::ConnectionError>
    where
        Shutdown: Future<Output = ShutdownMode> + Send + 'static,
    {
        let shutdown = OrderlyShutdown::new(
            std::time::Duration::from_secs(0),
            crate::server::QUIC_CLOSE_FLUSH_DURATION,
        );
        let shutdown_trigger = shutdown.clone();
        tokio::spawn(async move {
            match shutdown_signal.await {
                ShutdownMode::Graceful => {
                    let _ = shutdown_trigger.begin_graceful();
                }
                ShutdownMode::Fast => {
                    let _ = shutdown_trigger.begin_fast();
                }
            }
        });
        self.run_with_shutdown(&shutdown).await
    }

    pub(crate) async fn run_with_shutdown(
        self,
        shutdown: &OrderlyShutdown,
    ) -> Result<(), quinn::ConnectionError> {
        loop {
            tokio::select! {
                _ = shutdown.wait_started() => {
                    crate::runtime_log::client_graceful_shutdown_closing_tunnel_connection();
                    self.connection.close(0_u32.into(), b"graceful shutdown");
                    tokio::time::sleep(shutdown.quic_close_flush_duration()).await;
                    return Ok(());
                }
                accept_result = self.connection.accept_bi() => match accept_result {
                    Ok((send, recv)) => {
                        self.spawn_stream_handler(send, recv);
                    }
                    Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }
    }

    fn spawn_stream_handler(&self, send: quinn::SendStream, recv: quinn::RecvStream) {
        let Ok(permit) = self.stream_budget.try_admit_handler() else {
            crate::client::tunnel_stream::reject_stream(send, recv);
            return;
        };
        let tunnel_stream_handler = self.tunnel_stream_handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tunnel_stream_handler.handle(send, recv).await;
        });
    }
}

fn services_and_configs_for_route_mode(
    route_mode: ClientRouteMode,
) -> (
    Vec<ServiceConfig>,
    TerminationTlsConfigs,
    Arc<ClientStreamBudget>,
) {
    match route_mode {
        ClientRouteMode::CatchAll { backend_address } => (
            vec![ServiceConfig {
                public_hostnames: None,
                backend_address,
                tls_mode: ClientTlsMode::Passthrough,
            }],
            TerminationTlsConfigs::empty(),
            Arc::new(ClientStreamBudget::new(ClientStreamLimits::default())),
        ),
        ClientRouteMode::Routed {
            services,
            termination_tls_configs,
            stream_budget,
        } => (services, termination_tls_configs, stream_budget),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::pem::Error as PemError;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::time::timeout;

    use super::{Client, ClientConnectConfig, ClientConnectError};
    use crate::tls_material::{certificate_chain_from_pem, private_key_from_pem};
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

        let client_config = ClientConnectConfig {
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
}
