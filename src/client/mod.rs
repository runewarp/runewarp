mod backend;

use std::fmt;
use std::io;
use std::net::SocketAddr;

use quinn::{Connection, Endpoint};

#[derive(Clone)]
pub struct ClientConfig {
    pub local_bind_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub backend_addr: SocketAddr,
    pub quic_client_config: quinn::ClientConfig,
}

pub struct Client {
    backend_addr: SocketAddr,
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
        let mut endpoint =
            Endpoint::client(config.local_bind_addr).map_err(ClientConnectError::Bind)?;
        endpoint.set_default_client_config(config.quic_client_config);

        let connection = endpoint
            .connect(config.server_addr, &config.server_name)
            .map_err(ClientConnectError::Connect)?
            .await
            .map_err(ClientConnectError::Handshake)?;

        Ok(Self {
            backend_addr: config.backend_addr,
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
                    let backend_addr = self.backend_addr;
                    tokio::spawn(async move {
                        let _ = backend::handle_tunnel_stream(send, recv, backend_addr).await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }
}
