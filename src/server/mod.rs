mod active_client;
mod admission;
mod authorization;
mod managed_adapter;
mod tunnel_registry;
mod visitor_stream;

pub use self::authorization::{AuthorizationSnapshot, PreparedAuthorization, ServerAuthorization};
pub use self::managed_adapter::ServerAuthorizationAdapter;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use quinn::Endpoint;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Notify;

use crate::{
    HANDSHAKE_TIMEOUT, ServerHostname,
    quic::with_handshake_timeout,
    runtime_log,
    shutdown::{OrderlyShutdown, ShutdownMode},
};

use self::admission::{
    AcceptBackoff, AdmissionLimit, AdmissionRejection, ServerAdmissionLimits, ServerAdmissionPolicy,
};
use self::managed_adapter::ReadinessGate;
use self::tunnel_registry::{TunnelRegistrationOutcome, TunnelRegistry};
use self::visitor_stream::VisitorStreamHandler;

pub const QUIC_CLOSE_FLUSH_DURATION: Duration = Duration::from_millis(100);

/// Signals an unrecoverable Server failure that must exit nonzero.
///
/// After an authorization commit begins, Core never restores revoked
/// authorization. Fatal local failures drop readiness and stop the runtime so
/// an external supervisor can restart into a clean Unready state.
#[derive(Clone, Debug, Default)]
pub(crate) struct FatalSignal {
    fired: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl FatalSignal {
    fn fire(&self) {
        self.fired.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn has_fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.has_fired() {
                return;
            }
            notified.await;
        }
    }
}

/// How the Server admits authorization and readiness at bind time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServerAdmission {
    /// Static mode: requires at least one Tunnel and gains readiness immediately.
    #[default]
    Static,
    /// Managed mode: empty authorization is allowed; readiness stays deferred
    /// until the first successful Managed-session apply.
    Managed,
}

pub struct ServerBindConfig {
    pub public_bind_addr: SocketAddr,
    pub tunnel_connection_bind_addr: SocketAddr,
    pub readiness_bind_addr: Option<SocketAddr>,
    pub server_hostname: ServerHostname,
    /// Shared authorization snapshot consulted by Public-hostname routing.
    /// Pass the same handle to the QUIC Client-identity admission builder.
    pub authorization: ServerAuthorization,
    pub public_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub quic_server_config: quinn::ServerConfig,
    pub admission: ServerAdmission,
}

pub struct Server {
    public_listener: TcpListener,
    tunnel_endpoint: Endpoint,
    readiness_probe: Option<ReadinessProbe>,
    tunnel_registry: TunnelRegistry,
    visitor_stream_handler: VisitorStreamHandler,
    authorization_adapter: ServerAuthorizationAdapter,
    fatal: FatalSignal,
    admission_policy: ServerAdmissionPolicy,
}

struct ReadinessProbe {
    bind_address: SocketAddr,
    gate: ReadinessGate,
    task: tokio::task::JoinHandle<()>,
}

enum NextServerEvent<VisitorAccept, TunnelAccept> {
    Fatal,
    Shutdown,
    Visitor(VisitorAccept),
    Tunnel(TunnelAccept),
}

async fn next_server_event<Fatal, Shutdown, VisitorAccept, TunnelAccept>(
    fatal: Fatal,
    shutdown: Shutdown,
    public_accept: VisitorAccept,
    tunnel_accept: TunnelAccept,
) -> NextServerEvent<VisitorAccept::Output, TunnelAccept::Output>
where
    Fatal: Future<Output = ()>,
    Shutdown: Future<Output = ()>,
    VisitorAccept: Future,
    TunnelAccept: Future,
{
    tokio::select! {
        biased;
        _ = fatal => NextServerEvent::Fatal,
        _ = shutdown => NextServerEvent::Shutdown,
        accept_result = public_accept => NextServerEvent::Visitor(accept_result),
        incoming = tunnel_accept => NextServerEvent::Tunnel(incoming),
    }
}

impl ReadinessProbe {
    async fn bind(
        bind_addr: SocketAddr,
        initially_ready: bool,
        fatal: FatalSignal,
    ) -> io::Result<Self> {
        // Reserve the readiness port at startup. For managed admission, keep the
        // socket bound without listen() so probes stay Unready and no other
        // process can claim the port, then listen only after the first apply.
        let socket = tcp_socket_for(bind_addr)?;
        socket.bind(bind_addr).map_err(|source| {
            io::Error::new(
                source.kind(),
                format!(
                    "failed to bind server.readiness-bind-address {}: {}",
                    bind_addr, source
                ),
            )
        })?;
        let bind_address = socket.local_addr()?;
        let gate = ReadinessGate::new(initially_ready);
        let task = if initially_ready {
            let listener = socket.listen(128).map_err(|source| {
                io::Error::new(
                    source.kind(),
                    format!(
                        "failed to listen on server.readiness-bind-address {}: {}",
                        bind_address, source
                    ),
                )
            })?;
            tokio::spawn(async move {
                accept_readiness_connections(listener).await;
            })
        } else {
            let accept_gate = gate.clone();
            tokio::spawn(async move {
                accept_gate.wait_until_ready().await;
                match socket.listen(128) {
                    Ok(listener) => {
                        // Emit gained only after listen succeeds so a failed
                        // listen cannot leave operators thinking readiness is up.
                        runtime_log::server_readiness_gained(bind_address);
                        accept_readiness_connections(listener).await;
                    }
                    Err(error) => {
                        // Authorization already committed when mark_ready ran.
                        // Never restore revoked authorization: drop readiness
                        // intent and fail the process for supervisor restart.
                        runtime_log::emit(
                            runtime_log::EventLevel::Error,
                            &format!(
                                "failed to listen on server readiness address {bind_address}: {error}"
                            ),
                        );
                        accept_gate.mark_not_ready();
                        fatal.fire();
                    }
                }
            })
        };
        Ok(Self {
            bind_address,
            gate,
            task,
        })
    }

    fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    fn gate(&self) -> ReadinessGate {
        self.gate.clone()
    }

    fn close(self) {
        self.task.abort();
    }
}

fn tcp_socket_for(bind_addr: SocketAddr) -> io::Result<TcpSocket> {
    match bind_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
}

async fn accept_readiness_connections(listener: TcpListener) {
    while let Ok((stream, _)) = listener.accept().await {
        drop(stream);
    }
}

impl Server {
    pub async fn bind(config: ServerBindConfig) -> io::Result<Self> {
        Self::bind_with_admission_limits(config, ServerAdmissionLimits::default()).await
    }

    pub(crate) async fn bind_with_admission_limits(
        config: ServerBindConfig,
        admission_limits: ServerAdmissionLimits,
    ) -> io::Result<Self> {
        if config.admission == ServerAdmission::Static
            && config.authorization.current_tunnel_count() == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server bind requires at least one configured Tunnel",
            ));
        }
        let admission_policy = ServerAdmissionPolicy::new(admission_limits);
        let tunnel_registry = TunnelRegistry::from_authorization_with_admission(
            config.authorization,
            admission_policy.tunnel_connections(),
        )?;
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
        let initially_ready = config.admission == ServerAdmission::Static;
        let fatal = FatalSignal::default();
        let readiness_probe = match config.readiness_bind_addr {
            Some(bind_addr) => {
                Some(ReadinessProbe::bind(bind_addr, initially_ready, fatal.clone()).await?)
            }
            None => None,
        };
        if let Some(readiness_probe) = readiness_probe.as_ref() {
            runtime_log::server_readiness_listener_enabled(readiness_probe.bind_address());
            if initially_ready {
                runtime_log::server_readiness_gained(readiness_probe.bind_address());
            }
        }
        let readiness_gate = readiness_probe.as_ref().map(ReadinessProbe::gate);
        let authorization_adapter = ServerAuthorizationAdapter::new(
            config.server_hostname,
            tunnel_registry.clone(),
            readiness_gate,
        );

        Ok(Self {
            public_listener,
            tunnel_endpoint,
            readiness_probe,
            tunnel_registry,
            visitor_stream_handler,
            authorization_adapter,
            fatal,
            admission_policy,
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

    /// Shared Managed-session role adapter for atomic authorization applies.
    pub fn authorization_adapter(&self) -> ServerAuthorizationAdapter {
        self.authorization_adapter.clone()
    }

    pub async fn run(self) -> io::Result<()> {
        let Self {
            public_listener,
            tunnel_endpoint,
            readiness_probe,
            tunnel_registry,
            visitor_stream_handler,
            authorization_adapter: _,
            fatal,
            admission_policy,
        } = self;
        let mut accept_backoff = AcceptBackoff::default();
        let mut public_accept_not_before = None;
        loop {
            match next_server_event(
                async {
                    fatal.wait().await;
                },
                std::future::pending::<()>(),
                accept_public_connection(&public_listener, public_accept_not_before),
                tunnel_endpoint.accept(),
            )
            .await
            {
                NextServerEvent::Fatal => {
                    if let Some(readiness_probe) = readiness_probe {
                        runtime_log::server_readiness_lost(readiness_probe.bind_address());
                        readiness_probe.close();
                    }
                    return Err(io::Error::other(
                        "unrecoverable server failure after authorization commit",
                    ));
                }
                NextServerEvent::Shutdown => return Ok(()),
                NextServerEvent::Visitor(accept_result) => {
                    match process_public_accept(
                        accept_result,
                        &mut accept_backoff,
                        &admission_policy,
                        &visitor_stream_handler,
                        None,
                    ) {
                        Ok(not_before) => public_accept_not_before = not_before,
                        Err(error) => {
                            if let Some(readiness_probe) = readiness_probe {
                                runtime_log::server_readiness_lost(readiness_probe.bind_address());
                                readiness_probe.close();
                            }
                            return Err(error);
                        }
                    }
                }
                NextServerEvent::Tunnel(incoming) => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };

                    admit_tunnel_handshake(&admission_policy, tunnel_registry.clone(), incoming);
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
            authorization_adapter: _,
            fatal,
            admission_policy,
        } = self;
        let mut accept_backoff = AcceptBackoff::default();
        let mut public_accept_not_before = None;
        loop {
            match next_server_event(
                async {
                    fatal.wait().await;
                },
                async {
                    let _ = shutdown.wait_started().await;
                },
                accept_public_connection(&public_listener, public_accept_not_before),
                tunnel_endpoint.accept(),
            )
            .await
            {
                NextServerEvent::Fatal => {
                    if let Some(readiness_probe) = readiness_probe {
                        runtime_log::server_readiness_lost(readiness_probe.bind_address());
                        readiness_probe.close();
                    }
                    drop(public_listener);
                    drop(tunnel_endpoint);
                    return Err(io::Error::other(
                        "unrecoverable server failure after authorization commit",
                    ));
                }
                NextServerEvent::Shutdown => break,
                NextServerEvent::Visitor(accept_result) => {
                    match process_public_accept(
                        accept_result,
                        &mut accept_backoff,
                        &admission_policy,
                        &visitor_stream_handler,
                        Some(shutdown.clone()),
                    ) {
                        Ok(not_before) => public_accept_not_before = not_before,
                        Err(error) => {
                            if let Some(readiness_probe) = readiness_probe {
                                runtime_log::server_readiness_lost(readiness_probe.bind_address());
                                readiness_probe.close();
                            }
                            drop(public_listener);
                            drop(tunnel_endpoint);
                            return Err(error);
                        }
                    }
                }
                NextServerEvent::Tunnel(incoming) => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };

                    admit_tunnel_handshake(&admission_policy, tunnel_registry.clone(), incoming);
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

async fn accept_public_connection(
    listener: &TcpListener,
    not_before: Option<tokio::time::Instant>,
) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
    wait_before_public_accept(not_before).await;
    listener.accept().await
}

async fn wait_before_public_accept(not_before: Option<tokio::time::Instant>) {
    if let Some(not_before) = not_before {
        tokio::time::sleep_until(not_before).await;
    }
}

fn process_public_accept(
    accept_result: io::Result<(tokio::net::TcpStream, SocketAddr)>,
    accept_backoff: &mut AcceptBackoff,
    admission_policy: &ServerAdmissionPolicy,
    visitor_stream_handler: &VisitorStreamHandler,
    shutdown: Option<OrderlyShutdown>,
) -> io::Result<Option<tokio::time::Instant>> {
    match accept_result {
        Ok((visitor_stream, peer_address)) => {
            if accept_backoff.on_success() {
                runtime_log::server_public_listener_accept_recovered();
            }
            admit_visitor_connection(
                admission_policy,
                visitor_stream_handler,
                visitor_stream,
                peer_address,
                shutdown,
            );
            Ok(None)
        }
        Err(error) => {
            let Some(delay) = accept_backoff.on_error(&error) else {
                return Err(error);
            };
            if admission_policy.should_log_public_accept_retry() {
                runtime_log::server_public_listener_accept_retry(&error, delay);
            }
            Ok(Some(tokio::time::Instant::now() + delay))
        }
    }
}

fn admit_visitor_connection(
    admission_policy: &ServerAdmissionPolicy,
    visitor_stream_handler: &VisitorStreamHandler,
    visitor_stream: tokio::net::TcpStream,
    peer_address: SocketAddr,
    shutdown: Option<OrderlyShutdown>,
) {
    let permit = match admission_policy.try_admit_visitor(peer_address.ip()) {
        Ok(permit) => permit,
        Err(rejection) => {
            drop(visitor_stream);
            report_admission_saturation(admission_policy, rejection);
            return;
        }
    };
    report_admission_recovery(
        admission_policy,
        &[
            AdmissionLimit::VisitorsGlobal,
            AdmissionLimit::VisitorSource,
        ],
    );
    let visitor_stream_handler = visitor_stream_handler.clone();
    let client_hello_timeout = admission_policy.limits().client_hello_timeout;
    match shutdown {
        Some(shutdown) => {
            tokio::spawn(async move {
                let _ = visitor_stream_handler
                    .handle_admitted_until(
                        visitor_stream,
                        client_hello_timeout,
                        permit,
                        async move {
                            let _ = shutdown.wait_started().await;
                        },
                    )
                    .await;
            });
        }
        None => {
            tokio::spawn(async move {
                let _ = visitor_stream_handler
                    .handle_admitted(visitor_stream, client_hello_timeout, permit)
                    .await;
            });
        }
    }
}

fn admit_tunnel_handshake(
    admission_policy: &ServerAdmissionPolicy,
    tunnel_registry: TunnelRegistry,
    incoming: quinn::Incoming,
) {
    let handshake_permit = match admission_policy.try_admit_handshake() {
        Ok(permit) => permit,
        Err(rejection) => {
            incoming.refuse();
            report_admission_saturation(admission_policy, rejection);
            return;
        }
    };
    report_admission_recovery(admission_policy, &[AdmissionLimit::Handshakes]);
    let admission_policy = admission_policy.clone();
    tokio::spawn(async move {
        register_tunnel_connection(
            tunnel_registry,
            incoming,
            handshake_permit,
            admission_policy,
        )
        .await;
    });
}

fn report_admission_saturation(
    admission_policy: &ServerAdmissionPolicy,
    rejection: AdmissionRejection,
) {
    if let Some(limit_value) = admission_policy.limit_value(rejection.limit)
        && admission_policy.should_log_saturation(rejection.limit)
    {
        runtime_log::server_admission_saturated(
            admission_limit_name(rejection.limit),
            rejection.active_work,
            limit_value,
        );
    }
}

fn report_admission_recovery(admission_policy: &ServerAdmissionPolicy, limits: &[AdmissionLimit]) {
    for limit in limits {
        if admission_policy.take_recovered(*limit) {
            runtime_log::server_admission_recovered(admission_limit_name(*limit));
        }
    }
}

fn admission_limit_name(limit: AdmissionLimit) -> &'static str {
    match limit {
        AdmissionLimit::VisitorsGlobal => "visitor-global",
        AdmissionLimit::VisitorSource => "visitor-source",
        AdmissionLimit::Handshakes => "quic-handshake-global",
        AdmissionLimit::TunnelConnectionsGlobal => "tunnel-connection-global",
        AdmissionLimit::TunnelConnectionsPerTunnel => "tunnel-connection-per-tunnel",
        AdmissionLimit::TunnelConnectionsPerIdentity => "tunnel-connection-per-client-identity",
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

async fn register_tunnel_connection(
    tunnel_registry: TunnelRegistry,
    incoming: quinn::Incoming,
    handshake_permit: tokio::sync::OwnedSemaphorePermit,
    admission_policy: ServerAdmissionPolicy,
) {
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(error) => {
            report_tunnel_handshake_failure(&admission_policy, &error.to_string());
            return;
        }
    };
    let handshake = with_handshake_timeout(connecting, HANDSHAKE_TIMEOUT, || {
        quinn::ConnectionError::TimedOut
    })
    .await;
    drop(handshake_permit);
    match handshake {
        Ok(connection) => {
            if admission_policy.take_tunnel_handshake_failure_recovered() {
                runtime_log::server_admission_recovered("quic-handshake-failure");
            }
            match tunnel_registry.register(connection).await {
                TunnelRegistrationOutcome::Rejected(rejection) => {
                    report_admission_saturation(&admission_policy, rejection);
                }
                TunnelRegistrationOutcome::Registered => report_admission_recovery(
                    &admission_policy,
                    &[
                        AdmissionLimit::TunnelConnectionsGlobal,
                        AdmissionLimit::TunnelConnectionsPerTunnel,
                        AdmissionLimit::TunnelConnectionsPerIdentity,
                    ],
                ),
                TunnelRegistrationOutcome::Closed => {}
            }
        }
        Err(error) => report_tunnel_handshake_failure(&admission_policy, &error.to_string()),
    }
}

fn report_tunnel_handshake_failure(admission_policy: &ServerAdmissionPolicy, error: &str) {
    if admission_policy.should_log_tunnel_handshake_failure() {
        runtime_log::server_tunnel_connection_failed(error);
    }
}

#[cfg(test)]
mod tests {
    use std::future::ready;
    use std::time::Duration;

    use super::{
        FatalSignal, NextServerEvent, QUIC_CLOSE_FLUSH_DURATION, next_server_event,
        wait_before_public_accept,
    };
    use crate::shutdown::{OrderlyShutdown, ShutdownMode, ShutdownTransition};

    #[tokio::test]
    async fn shutdown_wins_when_accepts_are_also_ready() {
        let event = next_server_event(
            std::future::pending::<()>(),
            ready(()),
            ready("visitor"),
            ready("tunnel"),
        )
        .await;

        assert!(matches!(event, NextServerEvent::Shutdown));
    }

    #[tokio::test]
    async fn fatal_wins_over_shutdown_and_accepts() {
        let fatal = FatalSignal::default();
        fatal.fire();
        let event =
            next_server_event(fatal.wait(), ready(()), ready("visitor"), ready("tunnel")).await;

        assert!(matches!(event, NextServerEvent::Fatal));
    }

    #[tokio::test(start_paused = true)]
    async fn tunnel_events_do_not_restart_public_accept_backoff() {
        let not_before = tokio::time::Instant::now() + Duration::from_millis(10);
        let event = next_server_event(
            std::future::pending::<()>(),
            std::future::pending::<()>(),
            wait_before_public_accept(Some(not_before)),
            ready(()),
        )
        .await;
        assert!(matches!(event, NextServerEvent::Tunnel(())));

        tokio::time::advance(Duration::from_millis(9)).await;
        let retry = tokio::spawn(wait_before_public_accept(Some(not_before)));
        tokio::task::yield_now().await;
        assert!(!retry.is_finished());

        tokio::time::advance(Duration::from_millis(1)).await;
        retry
            .await
            .expect("retry wait should finish at original deadline");
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
