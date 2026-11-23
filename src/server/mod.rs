#[cfg(test)]
mod listener_tests;

mod active_client;
mod admission;
mod authorization;
mod drain;
mod managed_adapter;
mod readiness;
mod tunnel_registry;
mod visitor_stream;

pub use self::authorization::{AuthorizationSnapshot, ServerAuthorization};
pub use self::managed_adapter::ServerAuthorizationAdapter;
pub use crate::server_admission::ServerAdmission;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use self::drain::ServerDrain;
use crate::metrics::{LabelValue as _, MetricsEndpoint, ServerMetrics, TunnelRejectReason};
use crate::trace_export::TracedStage;
use crate::tunnel::{ServerRuntimeGeneration, ServerTunnel, ServerTunnelEvents};
use quinn::Endpoint;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::{
    HANDSHAKE_TIMEOUT, ServerHostname,
    quic::with_handshake_timeout,
    runtime_log,
    shutdown::{OrderlyShutdown, ShutdownMode},
};

use self::admission::{
    AcceptBackoff, AdmissionLimit, ServerAdmissionLimits, ServerAdmissionPolicy,
};
use self::readiness::ReadinessGate;
use self::tunnel_registry::{TunnelRegistrationOutcome, TunnelRegistry};
use self::visitor_stream::VisitorIntake;

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

pub struct ServerBindConfig {
    /// One to eight distinct Visitor TCP addresses, sharing all runtime limits.
    pub public_bind_addrs: Vec<SocketAddr>,
    /// One to eight distinct Tunnel UDP addresses, sharing authorization and pools.
    pub tunnel_connection_bind_addrs: Vec<SocketAddr>,
    pub readiness_bind_addr: Option<SocketAddr>,
    /// Optional Prometheus scrape listener. A bind failure logs and leaves metrics disabled.
    pub metrics_bind_addr: Option<SocketAddr>,
    pub server_hostname: ServerHostname,
    /// Shared authorization snapshot consulted by Public-hostname routing.
    /// Pass the same handle to the QUIC Client-identity admission builder.
    pub authorization: ServerAuthorization,
    pub public_tls_config: Option<Arc<rustls::ServerConfig>>,
    pub quic_server_config: quinn::ServerConfig,
    pub admission: ServerAdmission,
}

pub struct Server {
    public_listeners: Vec<TcpListener>,
    tunnel_endpoints: Vec<Endpoint>,
    readiness_probe: Option<ReadinessProbe>,
    tunnel_registry: TunnelRegistry,
    visitor_intake: VisitorIntake,
    authorization_adapter: ServerAuthorizationAdapter,
    fatal: FatalSignal,
    admission_policy: ServerAdmissionPolicy,
    server_hostname: ServerHostname,
    tunnel_events: ServerTunnelEvents,
    drain: ServerDrain,
    metrics: ServerMetrics,
    metrics_endpoint: Option<MetricsEndpoint>,
    readiness_metric: AbortOnDrop,
}

/// Owns a background task that must not outlive its Server, even when `run` never starts or
/// is cancelled.
struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl AbortOnDrop {
    /// Abort and wait, so no write the task already started can land afterwards.
    async fn stop(mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
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
        gate: ReadinessGate,
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
        let task = if gate.is_ready() {
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

    async fn close(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Mirror the readiness gate into `runewarp_server_ready` until the Server stops accepting.
async fn track_readiness(gate: ReadinessGate, metrics: ServerMetrics) {
    gate.watch(|ready| metrics.set_ready(ready)).await;
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
    /// Bind a Server and prepare process descriptor capacity. On Unix this may raise the
    /// process-wide soft RLIMIT_NOFILE to the hard limit, then clamp Visitor admission to fit.
    /// Embedders must account for other socket/file owners in the same process.
    pub async fn bind(config: ServerBindConfig) -> io::Result<Self> {
        Self::bind_with_proxy(config, None, Vec::new()).await
    }

    /// Like `bind`, including its process-wide Unix fd-limit preparation, with trusted PROXY ingress.
    pub async fn bind_with_proxy(
        config: ServerBindConfig,
        visitor_proxy_protocol: Option<crate::ProxyProtocolVersion>,
        visitor_proxy_trusted_networks: Vec<crate::TrustedNetwork>,
    ) -> io::Result<Self> {
        Self::bind_with_proxy_and_certificate(
            config,
            visitor_proxy_protocol,
            visitor_proxy_trusted_networks,
            None,
            ServerRuntimeGeneration::generate(),
        )
        .await
    }

    pub(crate) async fn bind_with_proxy_and_certificate(
        config: ServerBindConfig,
        visitor_proxy_protocol: Option<crate::ProxyProtocolVersion>,
        visitor_proxy_trusted_networks: Vec<crate::TrustedNetwork>,
        certificate: Option<crate::server_certificate::ServerCertificateController>,
        generation: ServerRuntimeGeneration,
    ) -> io::Result<Self> {
        let mut limits = ServerAdmissionLimits::default();
        let effective = crate::fd_capacity::server([
            limits.max_pending_visitors,
            limits.max_pending_stream_opens,
            limits.max_active_routed_streams,
        ]);
        [
            limits.max_pending_visitors,
            limits.max_pending_stream_opens,
            limits.max_active_routed_streams,
        ] = effective;
        Self::bind_with_admission_limits_and_proxy(
            config,
            limits,
            visitor_proxy_protocol,
            visitor_proxy_trusted_networks,
            certificate,
            generation,
        )
        .await
    }

    async fn bind_with_admission_limits_and_proxy(
        config: ServerBindConfig,
        admission_limits: ServerAdmissionLimits,
        visitor_proxy_protocol: Option<crate::ProxyProtocolVersion>,
        visitor_proxy_trusted_networks: Vec<crate::TrustedNetwork>,
        certificate: Option<crate::server_certificate::ServerCertificateController>,
        generation: ServerRuntimeGeneration,
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
        let metrics = ServerMetrics::new(
            generation,
            config.admission == ServerAdmission::Managed,
            admission_policy.metrics_gauges(),
        );
        let tunnel_registry = TunnelRegistry::from_authorization_with_admission(
            config.authorization,
            admission_policy.tunnel_connections(),
            metrics.clone(),
        )?;
        let visitor_intake = VisitorIntake::new_with_proxy(
            config.server_hostname.clone(),
            tunnel_registry.clone(),
            config.public_tls_config.clone(),
            admission_policy.clone(),
            visitor_proxy_protocol,
            visitor_proxy_trusted_networks,
        )?
        .with_certificate(certificate.clone());
        crate::config::validate_bind_addresses(
            "server.public-bind-address",
            &config.public_bind_addrs,
        )
        .and_then(|()| {
            crate::config::validate_bind_addresses(
                "server.tunnel-bind-address",
                &config.tunnel_connection_bind_addrs,
            )
        })
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
        // Bind everything before starting readiness or accepting any work. Dropping these
        // collections on an error releases every earlier socket reservation.
        let mut public_listeners = Vec::new();
        for address in config.public_bind_addrs {
            let listener = TcpListener::bind(address).await.map_err(|source| {
                io::Error::new(
                    source.kind(),
                    format!("failed to bind server.public-bind-address {address}: {source}"),
                )
            })?;
            public_listeners.push(listener);
        }
        let mut tunnel_sockets = Vec::new();
        for address in config.tunnel_connection_bind_addrs {
            let socket = std::net::UdpSocket::bind(address)
                .and_then(|socket| {
                    socket.set_nonblocking(true)?;
                    Ok(socket)
                })
                .map_err(|source| {
                    io::Error::new(
                        source.kind(),
                        format!("failed to bind server.tunnel-bind-address {address}: {source}"),
                    )
                })?;
            tunnel_sockets.push(socket);
        }
        // Static Servers never publish a replacement hint; only the Managed adapter does.
        // Mint and announce once before readiness can emit from its background task.
        let tunnel_events = ServerTunnelEvents::new(generation);
        runtime_log::server_runtime_started(tunnel_events.server_generation());
        let initially_ready = config.admission == ServerAdmission::Static;
        let fatal = FatalSignal::default();
        // One gate drives the optional probe and the readiness metric alike.
        let readiness_gate = ReadinessGate::with_certificate(
            initially_ready,
            certificate
                .as_ref()
                .map(crate::server_certificate::ServerCertificateController::readiness),
        );
        let readiness_probe = match config.readiness_bind_addr {
            Some(bind_addr) => {
                Some(ReadinessProbe::bind(bind_addr, readiness_gate.clone(), fatal.clone()).await?)
            }
            None => None,
        };
        // No QUIC driver starts until every TCP, UDP and readiness bind succeeded.
        let mut tunnel_endpoints = Vec::new();
        for socket in tunnel_sockets {
            match Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(config.quic_server_config.clone()),
                socket,
                Arc::new(crate::server_connection_log::ServerQuicRuntime),
            ) {
                Ok(endpoint) => tunnel_endpoints.push(endpoint),
                Err(error) => {
                    if let Some(probe) = readiness_probe {
                        probe.close().await;
                    }
                    return Err(error);
                }
            }
        }
        if let Some(readiness_probe) = readiness_probe.as_ref() {
            runtime_log::server_readiness_listener_enabled(readiness_probe.bind_address());
            if readiness_probe.gate().is_ready() {
                runtime_log::server_readiness_gained(readiness_probe.bind_address());
            }
        }
        tunnel_registry.set_readiness(readiness_gate.clone());
        let readiness_metric = AbortOnDrop(Some(tokio::spawn(track_readiness(
            readiness_gate,
            metrics.clone(),
        ))));
        if let Some(certificate) = certificate.as_ref() {
            certificate.attach_metrics(metrics.clone());
        }
        // Last, so no other bind failure can leave a scrape listener behind. Never fatal.
        let metrics_endpoint = match config.metrics_bind_addr {
            Some(bind_addr) => {
                MetricsEndpoint::bind(
                    "server",
                    "server.metrics-bind-address",
                    bind_addr,
                    metrics.collector(),
                )
                .await
            }
            None => None,
        };
        let drain = ServerDrain::new();
        let authorization_adapter = ServerAuthorizationAdapter::new(
            config.server_hostname.clone(),
            tunnel_registry.clone(),
            tunnel_events.clone(),
            drain.clone(),
        );

        Ok(Self {
            public_listeners,
            tunnel_endpoints,
            readiness_probe,
            tunnel_registry,
            visitor_intake,
            authorization_adapter,
            fatal,
            admission_policy,
            server_hostname: config.server_hostname,
            tunnel_events,
            drain,
            metrics,
            metrics_endpoint,
            readiness_metric,
        })
    }

    pub fn public_addr(&self) -> io::Result<SocketAddr> {
        self.public_listeners[0].local_addr()
    }

    pub fn tunnel_addr(&self) -> io::Result<SocketAddr> {
        self.tunnel_endpoints[0].local_addr()
    }

    /// Bound Visitor addresses in configuration order. `public_addr` returns the first.
    pub fn public_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.public_listeners
            .iter()
            .map(TcpListener::local_addr)
            .collect()
    }

    /// Bound Tunnel addresses in configuration order. `tunnel_addr` returns the first.
    pub fn tunnel_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.tunnel_endpoints
            .iter()
            .map(Endpoint::local_addr)
            .collect()
    }

    pub fn readiness_addr(&self) -> Option<SocketAddr> {
        self.readiness_probe
            .as_ref()
            .map(ReadinessProbe::bind_address)
    }

    /// Bound scrape address, or `None` when metrics are off or the bind failed.
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics_endpoint
            .as_ref()
            .map(MetricsEndpoint::local_addr)
    }

    pub(crate) fn metrics(&self) -> ServerMetrics {
        self.metrics.clone()
    }

    /// Move the scrape listener to a caller that outlives `run`, such as a Managed runtime
    /// that keeps reporting after a drain completes.
    pub(crate) fn take_metrics_endpoint(&mut self) -> Option<MetricsEndpoint> {
        self.metrics_endpoint.take()
    }

    /// Shared Managed-session role adapter for atomic authorization applies.
    pub fn authorization_adapter(&self) -> ServerAuthorizationAdapter {
        self.authorization_adapter.clone()
    }

    pub async fn run(self) -> io::Result<()> {
        let shutdown = OrderlyShutdown::new(Duration::ZERO, QUIC_CLOSE_FLUSH_DURATION);
        self.run_with_shutdown(&shutdown).await
    }

    pub async fn run_until_shutdown<Shutdown>(self, shutdown_signal: Shutdown) -> io::Result<()>
    where
        Shutdown: Future<Output = ShutdownMode> + Send + 'static,
    {
        let shutdown = OrderlyShutdown::new(Duration::from_secs(60), QUIC_CLOSE_FLUSH_DURATION);
        let runtime = self.run_with_shutdown(&shutdown);
        tokio::pin!(runtime);
        tokio::pin!(shutdown_signal);
        tokio::select! {
            result = &mut runtime => result,
            mode = &mut shutdown_signal => {
                match mode {
                    ShutdownMode::Graceful => { let _ = shutdown.begin_graceful(); }
                    ShutdownMode::Fast => { let _ = shutdown.begin_fast(); }
                }
                runtime.await
            }
        }
    }

    /// Serve until `shutdown` completes, or until a Managed drain completes.
    ///
    /// Drain runs the same bounded graceful path as process shutdown, starting when Control
    /// requests it, then returns `Ok` without the process exiting. Process shutdown during a drain
    /// joins it under the drain's original deadline; Fast still escalates.
    pub async fn run_with_shutdown(self, shutdown: &OrderlyShutdown) -> io::Result<()> {
        let local = OrderlyShutdown::new(
            shutdown.graceful_shutdown_duration(),
            shutdown.quic_close_flush_duration(),
        );
        let drain = self.drain.clone();
        let follow = async {
            let mode = tokio::select! {
                mode = shutdown.wait_started() => mode,
                () = drain.wait() => {
                    runtime_log::server_drain_started();
                    ShutdownMode::Graceful
                }
            };
            match mode {
                ShutdownMode::Fast => {
                    let _ = local.begin_fast();
                }
                ShutdownMode::Graceful => {
                    let _ = local.begin_graceful();
                    shutdown.wait_for_fast().await;
                    let _ = local.begin_fast();
                }
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            biased;
            result = self.serve(&local) => result,
            () = follow => unreachable!("shutdown following never completes"),
        }
    }

    async fn serve(self, shutdown: &OrderlyShutdown) -> io::Result<()> {
        let Self {
            public_listeners,
            tunnel_endpoints,
            readiness_probe,
            tunnel_registry,
            visitor_intake,
            authorization_adapter: _,
            fatal,
            admission_policy,
            server_hostname,
            tunnel_events,
            drain: _,
            metrics,
            metrics_endpoint,
            readiness_metric,
        } = self;
        let mut public_cursor = 0;
        let mut tunnel_cursor = 0;
        let mut accept_backoff = AcceptBackoff::default();
        let mut public_accept_not_before = None;
        let mut handshakes = JoinSet::new();
        let mut visitor_intakes = JoinSet::new();
        let mut terminal_error = None;
        loop {
            match next_server_event(
                async {
                    fatal.wait().await;
                },
                async {
                    let _ = shutdown.wait_started().await;
                },
                accept_public_connections(
                    &public_listeners,
                    &mut public_cursor,
                    public_accept_not_before,
                ),
                accept_tunnel_connections(&tunnel_endpoints, &mut tunnel_cursor),
            )
            .await
            {
                NextServerEvent::Fatal => {
                    terminal_error = Some(io::Error::other(
                        "unrecoverable server failure after authorization commit",
                    ));
                    let _ = shutdown.begin_fast();
                    break;
                }
                NextServerEvent::Shutdown => break,
                NextServerEvent::Visitor(accept_result) => {
                    match process_public_accept(
                        accept_result,
                        &mut accept_backoff,
                        &admission_policy,
                        &visitor_intake,
                        shutdown.clone(),
                        &mut visitor_intakes,
                        tunnel_events.server_generation(),
                    ) {
                        Ok(not_before) => public_accept_not_before = not_before,
                        Err(error) => {
                            terminal_error = Some(error);
                            let _ = shutdown.begin_fast();
                            break;
                        }
                    }
                }
                NextServerEvent::Tunnel(incoming) => {
                    let Some(incoming) = incoming else {
                        let _ = shutdown.begin_fast();
                        break;
                    };

                    let context = match crate::server_connection_log::ConnectionLogContext::allocate(
                        tunnel_events.server_generation(),
                    ) {
                        Ok(context) => context,
                        Err(error) => {
                            incoming.refuse();
                            terminal_error = Some(error);
                            let _ = shutdown.begin_fast();
                            break;
                        }
                    };
                    crate::server_connection_log::CONNECTION_LOG.sync_scope(context, || {
                        admit_tunnel_handshake(
                            &admission_policy,
                            tunnel_registry.clone(),
                            incoming,
                            &mut handshakes,
                            server_hostname.clone(),
                            tunnel_events.clone(),
                            metrics.clone(),
                        )
                    });
                }
            }
        }

        let mode = shutdown
            .mode()
            .expect("shutdown must be started before the server leaves the accept loop");
        tunnel_registry.stop_accepting_new_work();
        readiness_metric.stop().await;
        metrics.set_ready(false);
        metrics.set_draining();
        if let Some(readiness_probe) = readiness_probe {
            runtime_log::server_readiness_lost(readiness_probe.bind_address());
            readiness_probe.close().await;
        }
        drop(public_listeners);
        drop(tunnel_endpoints);
        handshakes.abort_all();
        while let Some(result) = handshakes.join_next().await {
            // A handshake cut short by shutdown records no outcome of its own.
            if result.is_err() {
                metrics.tunnel_connection_rejected(TunnelRejectReason::Shutdown);
            }
        }

        if mode == ShutdownMode::Graceful && shutdown.graceful_shutdown_duration() > Duration::ZERO
        {
            tokio::select! {
                _ = async {
                    tokio::join!(
                        tunnel_registry.shutdown_connections(shutdown.graceful_shutdown_duration()),
                        tunnel_registry.wait_quiescent(),
                    );
                } => {}
                _ = tokio::time::sleep(shutdown.graceful_shutdown_duration()) => {
                    if tunnel_registry.has_outstanding_visitor_work() {
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
        visitor_intakes.abort_all();
        while visitor_intakes.join_next().await.is_some() {}
        tokio::time::sleep(shutdown.quic_close_flush_duration()).await;
        // Scrapes stay available through the whole drain.
        drop(metrics_endpoint);
        terminal_error.map_or(Ok(()), Err)
    }
}

// Poll every listener without spawning accept tasks or buffering accepted work ahead
// of admission. Rotate after each accept so a busy address cannot starve its siblings.
async fn accept_public_connections(
    listeners: &[TcpListener],
    cursor: &mut usize,
    not_before: Option<tokio::time::Instant>,
) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
    wait_before_public_accept(not_before).await;
    std::future::poll_fn(|cx| {
        for offset in 0..listeners.len() {
            let index = (*cursor + offset) % listeners.len();
            if let std::task::Poll::Ready(result) = listeners[index].poll_accept(cx) {
                *cursor = (index + 1) % listeners.len();
                return std::task::Poll::Ready(result);
            }
        }
        std::task::Poll::Pending
    })
    .await
}

async fn accept_tunnel_connections(
    endpoints: &[Endpoint],
    cursor: &mut usize,
) -> Option<quinn::Incoming> {
    // Quinn's accept future owns a Notify registration. Keep the futures alive
    // across Pending polls so incoming packets can wake this accept loop.
    let accepts = endpoints
        .iter()
        .cycle()
        .skip(*cursor)
        .take(endpoints.len())
        .map(|endpoint| Box::pin(endpoint.accept()));
    let (incoming, index, _) = futures_util::future::select_all(accepts).await;
    *cursor = (*cursor + index + 1) % endpoints.len();
    incoming
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
    visitor_intake: &VisitorIntake,
    shutdown: OrderlyShutdown,
    visitor_intakes: &mut JoinSet<()>,
    generation: ServerRuntimeGeneration,
) -> io::Result<Option<tokio::time::Instant>> {
    match accept_result {
        Ok((visitor_stream, _peer_address)) => {
            if accept_backoff.on_success() {
                runtime_log::server_public_listener_accept_recovered();
            }
            let context = crate::server_connection_log::ConnectionLogContext::allocate(generation)?;
            crate::server_connection_log::CONNECTION_LOG.sync_scope(context, || {
                visitor_intake.accept_scoped(visitor_stream, shutdown, visitor_intakes);
            });
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

fn admit_tunnel_handshake(
    admission_policy: &ServerAdmissionPolicy,
    tunnel_registry: TunnelRegistry,
    incoming: quinn::Incoming,
    handshakes: &mut JoinSet<()>,
    server_hostname: ServerHostname,
    tunnel_events: ServerTunnelEvents,
    metrics: ServerMetrics,
) {
    let handshake = handshake_span();
    let handshake_permit = match admission_policy.try_admit_handshake() {
        Ok(permit) => permit,
        Err(rejection) => {
            incoming.refuse();
            metrics.tunnel_connection_rejected(TunnelRejectReason::HandshakeFailed);
            admission_policy.report_saturation(rejection);
            handshake.finish(TunnelRejectReason::HandshakeFailed.as_str());
            return;
        }
    };
    admission_policy.report_recovery(&[AdmissionLimit::Handshakes]);
    let admission_policy = admission_policy.clone();
    handshakes.spawn(crate::server_connection_log::inherit(async move {
        let outcome = register_tunnel_connection(
            tunnel_registry,
            incoming,
            handshake_permit,
            admission_policy,
            server_hostname,
            tunnel_events,
            metrics,
        )
        .await;
        handshake.finish(outcome);
    }));
}

/// Root span for one Tunnel connection handshake, ending at registration or rejection.
fn handshake_span() -> TracedStage {
    let span = tracing::info_span!(
        target: crate::trace_export::TARGET,
        parent: None,
        "tunnel_connection.handshake",
        runewarp.outcome = tracing::field::Empty,
        runewarp.server_generation = tracing::field::Empty,
    );
    if !span.is_disabled()
        && let Some(context) = crate::server_connection_log::current()
    {
        span.record(
            "runewarp.server_generation",
            tracing::field::display(context.generation),
        );
    }
    TracedStage::new(span)
}

async fn register_tunnel_connection(
    tunnel_registry: TunnelRegistry,
    incoming: quinn::Incoming,
    handshake_permit: tokio::sync::OwnedSemaphorePermit,
    admission_policy: ServerAdmissionPolicy,
    server_hostname: ServerHostname,
    tunnel_events: ServerTunnelEvents,
    metrics: ServerMetrics,
) -> &'static str {
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(error) => {
            metrics.tunnel_connection_rejected(TunnelRejectReason::HandshakeFailed);
            report_tunnel_handshake_failure(&admission_policy, &error.to_string());
            return TunnelRejectReason::HandshakeFailed.as_str();
        }
    };
    let handshake = with_handshake_timeout(
        async {
            let connection = connecting.await.map_err(|error| {
                // The pinned-identity verifier refuses unknown Clients with access_denied.
                let reason = if crate::quic::is_tls_access_denied(&error) {
                    TunnelRejectReason::Unauthorized
                } else {
                    TunnelRejectReason::HandshakeFailed
                };
                (reason, error.to_string())
            })?;
            ServerTunnel::establish(connection, server_hostname, tunnel_events)
                .await
                .map(Arc::new)
                .map_err(|error| (TunnelRejectReason::HandshakeFailed, error.to_string()))
        },
        HANDSHAKE_TIMEOUT,
        || {
            (
                TunnelRejectReason::HandshakeFailed,
                "tunnel handshake timed out".to_owned(),
            )
        },
    )
    .await;
    drop(handshake_permit);
    match handshake {
        Ok(connection) => {
            if admission_policy.take_tunnel_handshake_failure_recovered() {
                runtime_log::server_admission_recovered("quic-handshake-failure");
            }
            let rejected = match tunnel_registry.register(connection).await {
                TunnelRegistrationOutcome::Rejected(rejection) => {
                    admission_policy.report_saturation(rejection);
                    TunnelRejectReason::PoolFull
                }
                TunnelRegistrationOutcome::Registered => {
                    admission_policy.report_recovery(&[
                        AdmissionLimit::TunnelConnectionsGlobal,
                        AdmissionLimit::TunnelConnectionsPerTunnel,
                        AdmissionLimit::TunnelConnectionsPerIdentity,
                    ]);
                    return "accepted";
                }
                TunnelRegistrationOutcome::Closed => TunnelRejectReason::Shutdown,
                TunnelRegistrationOutcome::Unmapped => TunnelRejectReason::Unauthorized,
            };
            metrics.tunnel_connection_rejected(rejected);
            rejected.as_str()
        }
        Err((reason, error)) => {
            metrics.tunnel_connection_rejected(reason);
            report_tunnel_handshake_failure(&admission_policy, &error);
            reason.as_str()
        }
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
