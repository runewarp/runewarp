mod active_client;
mod tunnel_registry;
mod visitor_stream;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Endpoint;
use tokio::net::TcpListener;

use std::future::Future;

use crate::{
    HANDSHAKE_TIMEOUT, ServerTunnelSettings, quic::with_handshake_timeout, runtime_log,
    shutdown::GracefulShutdown,
};

use self::tunnel_registry::TunnelRegistry;
use self::visitor_stream::VisitorStreamHandler;

pub struct ServerConfig {
    pub public_bind_addr: SocketAddr,
    pub tunnel_connection_bind_addr: SocketAddr,
    pub server_hostname: String,
    pub configured_tunnels: Vec<ServerTunnelSettings>,
    pub public_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub quic_server_config: quinn::ServerConfig,
}

pub struct Server {
    public_listener: TcpListener,
    tunnel_endpoint: Endpoint,
    tunnel_registry: TunnelRegistry,
    visitor_stream_handler: VisitorStreamHandler,
}

enum NextServerEvent<VisitorAccept, TunnelAccept> {
    Shutdown,
    Visitor(VisitorAccept),
    Tunnel(TunnelAccept),
}

async fn next_server_event<Shutdown, VisitorAccept, TunnelAccept>(
    shutdown: Shutdown,
    public_accept: VisitorAccept,
    tunnel_accept: TunnelAccept,
) -> NextServerEvent<VisitorAccept::Output, TunnelAccept::Output>
where
    Shutdown: Future<Output = ()>,
    VisitorAccept: Future,
    TunnelAccept: Future,
{
    tokio::select! {
        biased;
        _ = shutdown => NextServerEvent::Shutdown,
        accept_result = public_accept => NextServerEvent::Visitor(accept_result),
        incoming = tunnel_accept => NextServerEvent::Tunnel(incoming),
    }
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
            config.public_tls_config.clone(),
        )?;
        let public_listener =
            TcpListener::bind(config.public_bind_addr)
                .await
                .map_err(|source| {
                    io::Error::new(
                        source.kind(),
                        format!(
                            "failed to bind server.public-bind-address {}: {}",
                            config.public_bind_addr, source
                        ),
                    )
                })?;
        let tunnel_endpoint = Endpoint::server(
            config.quic_server_config,
            config.tunnel_connection_bind_addr,
        )
        .map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "failed to bind server.tunnel-bind-address {}: {}",
                    config.tunnel_connection_bind_addr, source
                ),
            )
        })?;

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
                        let remote_addr = incoming.remote_address();
                        let connecting = match incoming.accept() {
                            Ok(connecting) => connecting,
                            Err(error) => {
                                runtime_log::server_tunnel_connection_failed(
                                    remote_addr,
                                    &error.to_string(),
                                );
                                return;
                            }
                        };
                        match with_handshake_timeout(
                            connecting,
                            HANDSHAKE_TIMEOUT,
                            || quinn::ConnectionError::TimedOut,
                        )
                        .await
                        {
                            Ok(connection) => tunnel_registry.register(connection).await,
                            Err(error) => runtime_log::server_tunnel_connection_failed(
                                remote_addr,
                                &error.to_string(),
                            ),
                        }
                    });
                }
            }
        }
    }

    pub async fn run_until_shutdown<Shutdown>(self, shutdown_signal: Shutdown) -> io::Result<()>
    where
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let shutdown = GracefulShutdown::new(std::time::Duration::from_millis(100));
        let shutdown_trigger = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal.await;
            shutdown_trigger.begin();
        });
        self.run_with_shutdown(&shutdown).await
    }

    pub(crate) async fn run_with_shutdown(self, shutdown: &GracefulShutdown) -> io::Result<()> {
        let Self {
            public_listener,
            tunnel_endpoint,
            tunnel_registry,
            visitor_stream_handler,
        } = self;
        loop {
            match next_server_event(
                shutdown.wait(),
                public_listener.accept(),
                tunnel_endpoint.accept(),
            )
            .await
            {
                NextServerEvent::Shutdown => break,
                NextServerEvent::Visitor(accept_result) => {
                    let (visitor_stream, _) = accept_result?;
                    let visitor_stream_handler = visitor_stream_handler.clone();
                    tokio::spawn(async move {
                        let _ = visitor_stream_handler.handle(visitor_stream).await;
                    });
                }
                NextServerEvent::Tunnel(incoming) => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };

                    let tunnel_registry = tunnel_registry.clone();
                    tokio::spawn(async move {
                        let remote_addr = incoming.remote_address();
                        let connecting = match incoming.accept() {
                            Ok(connecting) => connecting,
                            Err(error) => {
                                runtime_log::server_tunnel_connection_failed(
                                    remote_addr,
                                    &error.to_string(),
                                );
                                return;
                            }
                        };
                        match with_handshake_timeout(connecting, HANDSHAKE_TIMEOUT, || {
                            quinn::ConnectionError::TimedOut
                        })
                        .await
                        {
                            Ok(connection) => tunnel_registry.register(connection).await,
                            Err(error) => runtime_log::server_tunnel_connection_failed(
                                remote_addr,
                                &error.to_string(),
                            ),
                        }
                    });
                }
            }
        }

        tunnel_registry.stop_accepting();
        drop(public_listener);
        drop(tunnel_endpoint);
        let active_connections = tunnel_registry.active_connection_count().await;
        runtime_log::server_graceful_shutdown_closing_tunnel_connections(active_connections);
        let _ = tunnel_registry.close_all(b"graceful shutdown").await;
        tokio::time::sleep(shutdown.grace_period()).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::future::ready;

    use super::{NextServerEvent, next_server_event};

    #[tokio::test]
    async fn shutdown_wins_when_accepts_are_also_ready() {
        let event = next_server_event(ready(()), ready("visitor"), ready("tunnel")).await;

        assert!(matches!(event, NextServerEvent::Shutdown));
    }
}
