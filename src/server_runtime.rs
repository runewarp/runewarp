use std::error::Error;
use std::io;
use std::net::SocketAddr;

use tokio::sync::oneshot;

use crate::{
    ControlClientIdentityMaterial, ManagedSession, ManagedSessionRole, OrderlyShutdown,
    PreparedServer, QUIC_CLOSE_FLUSH_DURATION, ServerAuthorizationAdapter, ServerConfig,
    SessionMaterial, ShutdownMode,
};

enum ServerRuntimeMode {
    Static,
    Managed {
        session: Box<ManagedSession>,
        adapter: Box<ServerAuthorizationAdapter>,
    },
}

pub struct ServerRuntime {
    server: PreparedServer,
    shutdown: OrderlyShutdown,
    mode: ServerRuntimeMode,
}

impl ServerRuntime {
    pub async fn prepare(
        config: &ServerConfig,
        public_bind_addr: SocketAddr,
        tunnel_bind_addr: SocketAddr,
    ) -> Result<Self, Box<dyn Error>> {
        Self::prepare_listeners(config, vec![public_bind_addr], vec![tunnel_bind_addr]).await
    }

    /// Prepare all listeners as one Server runtime with shared admission and shutdown.
    pub async fn prepare_listeners(
        config: &ServerConfig,
        public_bind_addrs: Vec<SocketAddr>,
        tunnel_bind_addrs: Vec<SocketAddr>,
    ) -> Result<Self, Box<dyn Error>> {
        Self::prepare_with_certificate_options(config, public_bind_addrs, tunnel_bind_addrs, None)
            .await
    }

    /// Prepare the process runtime with an external consumed-route observer and explicit
    /// certificate lifetime/recovery policy. The returned controller uses these listeners.
    pub async fn prepare_listeners_with_acme(
        config: &ServerConfig,
        public_bind_addrs: Vec<SocketAddr>,
        tunnel_bind_addrs: Vec<SocketAddr>,
        options: crate::server_certificate::ServerAcmeOptions,
    ) -> Result<Self, Box<dyn Error>> {
        Self::prepare_with_certificate_options(
            config,
            public_bind_addrs,
            tunnel_bind_addrs,
            Some(options),
        )
        .await
    }

    async fn prepare_with_certificate_options(
        config: &ServerConfig,
        public_bind_addrs: Vec<SocketAddr>,
        tunnel_bind_addrs: Vec<SocketAddr>,
        options: Option<crate::server_certificate::ServerAcmeOptions>,
    ) -> Result<Self, Box<dyn Error>> {
        let session = if let Some(control) = config.control.as_ref() {
            let identity = config.identity.as_ref().ok_or_else(|| {
                io::Error::other("managed Server admission requires Server identity")
            })?;
            let material = SessionMaterial {
                control_hostname: control.address.hostname().as_str().to_owned(),
                trust: control.trust.clone(),
                identity: ControlClientIdentityMaterial::from_server_identity_dir(
                    &identity.directory,
                ),
            };
            Some(Box::new(ManagedSession::new(
                control.address.clone(),
                ManagedSessionRole::Server,
                material,
            )?))
        } else {
            None
        };

        let server = match options {
            Some(options) => {
                PreparedServer::bind_listeners_with_acme(
                    config,
                    public_bind_addrs,
                    tunnel_bind_addrs,
                    options,
                )
                .await?
            }
            None => {
                PreparedServer::bind_listeners(config, public_bind_addrs, tunnel_bind_addrs).await?
            }
        };
        for address in server.public_addrs()? {
            crate::runtime_log::server_public_listener_ready(address);
        }
        for address in server.tunnel_addrs()? {
            crate::runtime_log::server_tunnel_listener_ready(address);
        }

        let mode = if let Some(session) = session {
            let adapter = server
                .authorization_adapter()
                .expect("managed Server preparation constructs an authorization adapter");
            ServerRuntimeMode::Managed {
                session,
                adapter: Box::new(adapter),
            }
        } else {
            ServerRuntimeMode::Static
        };

        Ok(Self {
            server,
            shutdown: OrderlyShutdown::new(
                config.graceful_shutdown_duration,
                QUIC_CLOSE_FLUSH_DURATION,
            ),
            mode,
        })
    }

    pub fn public_addr(&self) -> io::Result<SocketAddr> {
        self.server.public_addr()
    }

    pub fn tunnel_addr(&self) -> io::Result<SocketAddr> {
        self.server.tunnel_addr()
    }

    pub fn public_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.server.public_addrs()
    }

    pub fn tunnel_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.server.tunnel_addrs()
    }

    pub fn readiness_addr(&self) -> Option<SocketAddr> {
        self.server.readiness_addr()
    }

    pub fn shutdown(&self) -> OrderlyShutdown {
        self.shutdown.clone()
    }

    pub fn certificate_controller(
        &self,
    ) -> Option<crate::server_certificate::ServerCertificateController> {
        self.server.certificate_controller()
    }

    pub async fn run(self) -> io::Result<()> {
        let Self {
            server,
            shutdown,
            mode,
        } = self;
        match mode {
            ServerRuntimeMode::Static => server.run_with_shutdown(&shutdown).await,
            ServerRuntimeMode::Managed {
                mut session,
                mut adapter,
            } => run_managed(server, shutdown, session.as_mut(), adapter.as_mut()).await,
        }
    }
}

async fn run_managed(
    server: PreparedServer,
    shutdown: OrderlyShutdown,
    session: &mut ManagedSession,
    adapter: &mut ServerAuthorizationAdapter,
) -> io::Result<()> {
    let (session_stop_tx, session_stop_rx) = oneshot::channel::<()>();
    let shutdown_for_session = shutdown.clone();
    let session_runtime = session.run(
        adapter,
        |event| async move {
            crate::runtime_log::managed_session_event(ManagedSessionRole::Server, &event);
        },
        async move {
            tokio::select! {
                biased;
                _ = session_stop_rx => {}
                _ = async {
                    match shutdown_for_session.wait_started().await {
                        ShutdownMode::Fast => {}
                        ShutdownMode::Graceful => shutdown_for_session.wait_for_fast().await,
                    }
                } => {}
            }
        },
    );
    let server_runtime = server.run_with_shutdown(&shutdown);
    coordinate_managed_server(server_runtime, session_runtime, &shutdown, session_stop_tx).await
}

async fn coordinate_managed_server<ServerFuture, SessionFuture>(
    server: ServerFuture,
    session: SessionFuture,
    shutdown: &OrderlyShutdown,
    session_stop: oneshot::Sender<()>,
) -> io::Result<()>
where
    ServerFuture: std::future::Future<Output = io::Result<()>>,
    SessionFuture: std::future::Future<Output = ()>,
{
    tokio::pin!(server);
    tokio::pin!(session);

    let mut session_finished = false;
    let result = tokio::select! {
        server_result = &mut server => {
            // A completed Managed drain returns Ok before process shutdown: keep applying input
            // and reporting state until the process is terminated.
            if server_result.is_ok() && shutdown.mode().is_none() {
                tokio::select! {
                    _ = shutdown.wait_started() => server_result,
                    _ = &mut session => {
                        session_finished = true;
                        Err(io::Error::other("managed session stopped unexpectedly"))
                    }
                }
            } else {
                server_result
            }
        }
        _ = &mut session => {
            session_finished = true;
            if matches!(shutdown.mode(), Some(ShutdownMode::Fast)) {
                server.await
            } else {
                let original = io::Error::other("managed session stopped unexpectedly");
                let _ = shutdown.begin_fast();
                let _ = server.await;
                Err(original)
            }
        }
    };
    if !session_finished {
        let _ = session_stop.send(());
        let _ = session.await;
    }
    result
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::coordinate_managed_server;
    use crate::OrderlyShutdown;

    #[tokio::test]
    async fn server_failure_stops_and_awaits_managed_session_before_returning() {
        let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
        let (stop_tx, stop_rx) = oneshot::channel();
        let session_finished = Arc::new(AtomicBool::new(false));
        let observed_finished = Arc::clone(&session_finished);

        let result = coordinate_managed_server(
            async { Err(io::Error::other("server failed")) },
            async move {
                let _ = stop_rx.await;
                observed_finished.store(true, Ordering::SeqCst);
            },
            &shutdown,
            stop_tx,
        )
        .await;

        assert_eq!(result.unwrap_err().to_string(), "server failed");
        assert!(session_finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_drained_server_keeps_its_managed_session_until_process_shutdown() {
        let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
        let (stop_tx, stop_rx) = oneshot::channel();
        let session_finished = Arc::new(AtomicBool::new(false));
        let observed_finished = Arc::clone(&session_finished);
        let coordinated = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                coordinate_managed_server(
                    async { Ok(()) },
                    async move {
                        let _ = stop_rx.await;
                        observed_finished.store(true, Ordering::SeqCst);
                    },
                    &shutdown,
                    stop_tx,
                )
                .await
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !coordinated.is_finished(),
            "drain keeps the runtime and session alive"
        );
        assert!(!session_finished.load(Ordering::SeqCst));

        let _ = shutdown.begin_graceful();
        coordinated.await.unwrap().unwrap();
        assert!(session_finished.load(Ordering::SeqCst));
    }
}
