mod backend;
mod service;

use std::fmt;
use std::io;
use std::net::SocketAddr;

use quinn::{Connection, Endpoint};

use crate::ClientServiceSettings;

pub(crate) use service::validate_services;

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
    pub(crate) logs: bool,
    pub(crate) quic_client_config: quinn::ClientConfig,
}

#[derive(Clone)]
enum ClientRouteMode {
    CatchAll {
        backend_address: String,
    },
    Routed {
        services: Vec<ClientServiceSettings>,
    },
}

pub struct Client {
    logs: bool,
    route_mode: ClientRouteMode,
    endpoint: Endpoint,
    connection: Connection,
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
            Self::Bind(error) => write!(formatter, "failed to bind the client endpoint: {error}"),
            Self::Connect(error) => {
                write!(formatter, "failed to start the client connection: {error}")
            }
            Self::Handshake(error) => write!(formatter, "client QUIC handshake failed: {error}"),
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

impl Client {
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientConnectError> {
        Self::connect_internal(
            config.local_bind_addr,
            config.server_addr,
            config.server_name,
            config.quic_client_config,
            true,
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
            config.logs,
            ClientRouteMode::Routed {
                services: config.services,
            },
        )
        .await
    }

    async fn connect_internal(
        local_bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: String,
        quic_client_config: quinn::ClientConfig,
        logs: bool,
        route_mode: ClientRouteMode,
    ) -> Result<Self, ClientConnectError> {
        let mut endpoint = Endpoint::client(local_bind_addr).map_err(ClientConnectError::Bind)?;
        endpoint.set_default_client_config(quic_client_config);

        let connection = endpoint
            .connect(server_addr, &server_name)
            .map_err(ClientConnectError::Connect)?
            .await
            .map_err(ClientConnectError::Handshake)?;

        Ok(Self {
            logs,
            route_mode,
            endpoint,
            connection,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        loop {
            match self.connection.accept_bi().await {
                Ok((send, recv)) => {
                    let services = self.services_for_stream();
                    let logs = self.logs;
                    tokio::spawn(async move {
                        let _ = backend::handle_tunnel_stream(send, recv, services, logs).await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    fn services_for_stream(&self) -> Vec<ClientServiceSettings> {
        match &self.route_mode {
            ClientRouteMode::CatchAll { backend_address } => vec![ClientServiceSettings {
                public_hostnames: None,
                backend_address: backend_address.clone(),
            }],
            ClientRouteMode::Routed { services } => services.clone(),
        }
    }
}
