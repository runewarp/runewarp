mod active_client;
mod ingress;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Endpoint;
use tokio::net::TcpListener;

use self::active_client::ActiveClientSlot;

pub struct ServerConfig {
    pub public_bind_addr: SocketAddr,
    pub tunnel_bind_addr: SocketAddr,
    pub server_hostname: String,
    pub public_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub quic_server_config: quinn::ServerConfig,
}

pub struct Server {
    public_listener: TcpListener,
    public_tls_config: Option<Arc<rustls::ServerConfig>>,
    server_hostname: String,
    tunnel_endpoint: Endpoint,
    active_client_slot: ActiveClientSlot,
}

impl Server {
    pub async fn bind(config: ServerConfig) -> io::Result<Self> {
        let public_listener = TcpListener::bind(config.public_bind_addr).await?;
        let tunnel_endpoint = Endpoint::server(config.quic_server_config, config.tunnel_bind_addr)?;

        Ok(Self {
            public_listener,
            public_tls_config: config.public_tls_config,
            server_hostname: config.server_hostname,
            tunnel_endpoint,
            active_client_slot: ActiveClientSlot::new(),
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
                    let active_client_slot = self.active_client_slot.clone();
                    let public_tls_config = self.public_tls_config.clone();
                    let server_hostname = self.server_hostname.clone();
                    tokio::spawn(async move {
                        let _ = ingress::handle_visitor_connection(
                            visitor_stream,
                            active_client_slot,
                            server_hostname,
                            public_tls_config,
                        ).await;
                    });
                }
                incoming = self.tunnel_endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };

                    let active_client_slot = self.active_client_slot.clone();
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            active_client_slot.register(connection).await;
                        }
                    });
                }
            }
        }
    }
}
