mod active_client;
mod tunnel_registry;
mod visitor_stream;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Endpoint;
use tokio::net::TcpListener;

use crate::ServerTunnelSettings;

use self::tunnel_registry::TunnelRegistry;
use self::visitor_stream::VisitorStreamHandler;

pub struct ServerConfig {
    pub public_bind_addr: SocketAddr,
    pub tunnel_connection_bind_addr: SocketAddr,
    pub server_hostname: String,
    pub configured_tunnels: Vec<ServerTunnelSettings>,
    pub logs: bool,
    pub public_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub quic_server_config: quinn::ServerConfig,
}

pub struct Server {
    public_listener: TcpListener,
    tunnel_endpoint: Endpoint,
    tunnel_registry: TunnelRegistry,
    visitor_stream_handler: VisitorStreamHandler,
}

impl Server {
    pub async fn bind(config: ServerConfig) -> io::Result<Self> {
        if config.configured_tunnels.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server bind requires at least one configured Tunnel",
            ));
        }
        let tunnel_registry =
            TunnelRegistry::configured(&config.server_hostname, &config.configured_tunnels)?;
        let visitor_stream_handler = VisitorStreamHandler::new(
            config.server_hostname.clone(),
            tunnel_registry.clone(),
            config.logs,
            config.public_tls_config.clone(),
        )?;
        let public_listener = TcpListener::bind(config.public_bind_addr).await?;
        let tunnel_endpoint = Endpoint::server(
            config.quic_server_config,
            config.tunnel_connection_bind_addr,
        )?;

        Ok(Self {
            public_listener,
            tunnel_endpoint,
            tunnel_registry,
            visitor_stream_handler,
        })
    }

    pub fn public_addr(&self) -> io::Result<SocketAddr> {
        self.public_listener.local_addr()
    }

    pub fn tunnel_addr(&self) -> io::Result<SocketAddr> {
        self.tunnel_endpoint.local_addr()
    }

    pub async fn run(self) -> io::Result<()> {
        loop {
            tokio::select! {
                accept_result = self.public_listener.accept() => {
                    let (visitor_stream, _) = accept_result?;
                    let visitor_stream_handler = self.visitor_stream_handler.clone();
                    tokio::spawn(async move {
                        let _ = visitor_stream_handler.handle(visitor_stream).await;
                    });
                }
                incoming = self.tunnel_endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };

                    let tunnel_registry = self.tunnel_registry.clone();
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            tunnel_registry.register(connection).await;
                        }
                    });
                }
            }
        }
    }
}
