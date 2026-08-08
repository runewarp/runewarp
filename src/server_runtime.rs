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
        adapter: ServerAuthorizationAdapter,
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

        let server = PreparedServer::bind(config, public_bind_addr, tunnel_bind_addr).await?;
        crate::runtime_log::server_public_listener_ready(server.public_addr()?);
        crate::runtime_log::server_tunnel_listener_ready(server.tunnel_addr()?);

        let mode = if let Some(session) = session {
            let adapter = server
                .authorization_adapter()
                .expect("managed Server preparation constructs an authorization adapter");
            ServerRuntimeMode::Managed { session, adapter }
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

    pub fn readiness_addr(&self) -> Option<SocketAddr> {
        self.server.readiness_addr()
    }

    pub fn shutdown(&self) -> OrderlyShutdown {
        self.shutdown.clone()
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
            } => run_managed(server, shutdown, session.as_mut(), &mut adapter).await,
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

    let result = tokio::select! {
        server_result = &mut server => server_result,
        _ = &mut session => {
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
    let _ = session_stop.send(());
    let _ = session.await;
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
}
