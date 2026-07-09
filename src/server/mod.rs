mod active_client;
mod tunnel_registry;
mod visitor_stream;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;
use tokio::net::TcpListener;

use crate::{
    HANDSHAKE_TIMEOUT, ServerHostname, ServerTunnelConfig,
    quic::with_handshake_timeout,
    runtime_log,
    shutdown::{OrderlyShutdown, ShutdownMode},
};

use self::tunnel_registry::TunnelRegistry;
use self::visitor_stream::VisitorStreamHandler;

pub const QUIC_CLOSE_FLUSH_DURATION: Duration = Duration::from_millis(100);

pub struct ServerBindConfig {
    pub public_bind_addr: SocketAddr,
    pub tunnel_connection_bind_addr: SocketAddr,
    pub readiness_bind_addr: Option<SocketAddr>,
    pub server_hostname: ServerHostname,
    pub configured_tunnels: Vec<ServerTunnelConfig>,
    pub public_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub quic_server_config: quinn::ServerConfig,
}

pub struct Server {
    public_listener: TcpListener,
    tunnel_endpoint: Endpoint,
    readiness_probe: Option<ReadinessProbe>,
    tunnel_registry: TunnelRegistry,
    visitor_stream_handler: VisitorStreamHandler,
}

struct ReadinessProbe {
    bind_address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
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

impl ReadinessProbe {
    async fn bind(bind_addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(bind_addr).await.map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "failed to bind server.readiness-bind-address {}: {}",
                    bind_addr, source
                ),
            )
        })?;
        let bind_address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        Ok(Self { bind_address, task })
    }

    fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    fn close(self) {
        self.task.abort();
    }
}

impl Server {
    pub async fn bind(config: ServerBindConfig) -> io::Result<Self> {
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
        let readiness_probe = match config.readiness_bind_addr {
            Some(bind_addr) => Some(ReadinessProbe::bind(bind_addr).await?),
            None => None,
        };
        if let Some(readiness_probe) = readiness_probe.as_ref() {
            runtime_log::server_readiness_listener_enabled(readiness_probe.bind_address());
            runtime_log::server_readiness_gained(readiness_probe.bind_address());
        }

        Ok(Self {
            public_listener,
            tunnel_endpoint,
            readiness_probe,
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

    pub fn readiness_addr(&self) -> Option<SocketAddr> {
        self.readiness_probe
            .as_ref()
            .map(ReadinessProbe::bind_address)
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
                        register_tunnel_connection(tunnel_registry, incoming).await;
                    });
                }
            }
        }
    }

    pub async fn run_until_shutdown<Shutdown>(self, shutdown_signal: Shutdown) -> io::Result<()>
    where
        Shutdown: Future<Output = ShutdownMode> + Send + 'static,
    {
        let shutdown = OrderlyShutdown::new(Duration::from_secs(60), QUIC_CLOSE_FLUSH_DURATION);
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

    pub async fn run_with_shutdown(self, shutdown: &OrderlyShutdown) -> io::Result<()> {
        let Self {
            public_listener,
            tunnel_endpoint,
            readiness_probe,
            tunnel_registry,
            visitor_stream_handler,
        } = self;
        loop {
            match next_server_event(
                async {
                    let _ = shutdown.wait_started().await;
                },
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
                        register_tunnel_connection(tunnel_registry, incoming).await;
                    });
                }
            }
        }

        let mode = shutdown
            .mode()
            .expect("shutdown must be started before the server leaves the accept loop");
        tunnel_registry.stop_accepting_new_work();
        if let Some(readiness_probe) = readiness_probe {
            runtime_log::server_readiness_lost(readiness_probe.bind_address());
            readiness_probe.close();
        }
        drop(public_listener);
        drop(tunnel_endpoint);

        if mode == ShutdownMode::Graceful && shutdown.graceful_shutdown_duration() > Duration::ZERO
        {
            tokio::select! {
                _ = wait_for_no_active_streams(&tunnel_registry) => {}
                _ = tokio::time::sleep(shutdown.graceful_shutdown_duration()) => {
                    let active_streams = tunnel_registry.active_stream_count().await;
                    if active_streams > 0 {
                        runtime_log::server_graceful_shutdown_deadline_expired(
                            tunnel_registry.active_connection_count().await,
                        );
                    }
                }
                _ = shutdown.wait_for_fast() => {}
            }
        }

        let active_connections = tunnel_registry.active_connection_count().await;
        runtime_log::server_orderly_shutdown_closing_tunnel_connections(mode, active_connections);
        let _ = tunnel_registry.close_all(b"graceful shutdown").await;
        tokio::time::sleep(shutdown.quic_close_flush_duration()).await;
        Ok(())
    }
}

async fn wait_for_no_active_streams(tunnel_registry: &TunnelRegistry) {
    loop {
        if tunnel_registry.active_stream_count().await == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn register_tunnel_connection(tunnel_registry: TunnelRegistry, incoming: quinn::Incoming) {
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(error) => {
            runtime_log::server_tunnel_connection_failed(&error.to_string());
            return;
        }
    };
    match with_handshake_timeout(connecting, HANDSHAKE_TIMEOUT, || {
        quinn::ConnectionError::TimedOut
    })
    .await
    {
        Ok(connection) => tunnel_registry.register(connection).await,
        Err(error) => runtime_log::server_tunnel_connection_failed(&error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::future::ready;
    use std::time::Duration;

    use super::{NextServerEvent, QUIC_CLOSE_FLUSH_DURATION, next_server_event};
    use crate::shutdown::{OrderlyShutdown, ShutdownMode, ShutdownTransition};

    #[tokio::test]
    async fn shutdown_wins_when_accepts_are_also_ready() {
        let event = next_server_event(ready(()), ready("visitor"), ready("tunnel")).await;

        assert!(matches!(event, NextServerEvent::Shutdown));
    }

    #[test]
    fn orderly_shutdown_starts_and_escalates() {
        let shutdown = OrderlyShutdown::new(Duration::from_secs(60), QUIC_CLOSE_FLUSH_DURATION);

        assert_eq!(
            shutdown.begin_graceful(),
            ShutdownTransition::Started(ShutdownMode::Graceful)
        );
        assert_eq!(shutdown.begin_fast(), ShutdownTransition::EscalatedToFast);
    }
}
