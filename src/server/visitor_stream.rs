use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::admission::{AdmissionLimit, ServerAdmissionPolicy, VisitorAdmissionPermit};
use super::tunnel_registry::{
    TunnelRegistry, TunnelRouteOutcome, VisitorRoute, VisitorWorkRejection,
};
use crate::acme::ACME_TLS_ALPN;
use crate::client_hello::ParsedClientHello;
use crate::client_hello::read_client_hello;
use crate::metrics::{
    AcmeMetricEvent, CountedIo, VisitorCloseOutcome, VisitorDirection, VisitorRejectReason,
    VisitorTracker,
};
use crate::proxy::{TcpByteCounters, proxy_tcp_over_tunnel};
use crate::proxy_protocol::read_proxy_v2;
use crate::runtime_log;
use crate::runtime_log::{AcmeEvent, AcmeRole, ServerRouteOutcome};
use crate::trace_export::{TARGET, TracedStage};
use crate::tunnel_framing::encode_tunnel_stream;
use crate::{
    ProxyProtocolVersion, PublicHostname, ServerHostname, TrustedNetwork, VisitorTcpAddresses,
};

#[derive(Clone)]
pub(crate) struct VisitorIntake {
    server_hostname: ServerHostname,
    tunnel_registry: TunnelRegistry,
    public_tls_config: Option<Arc<rustls::ServerConfig>>,
    admission_policy: ServerAdmissionPolicy,
    visitor_proxy_protocol: Option<ProxyProtocolVersion>,
    visitor_proxy_trusted_networks: Vec<TrustedNetwork>,
    certificate: Option<crate::server_certificate::ServerCertificateController>,
}

impl VisitorIntake {
    #[cfg(test)]
    pub(crate) fn new(
        server_hostname: ServerHostname,
        tunnel_registry: TunnelRegistry,
        public_tls_config: Option<Arc<rustls::ServerConfig>>,
        admission_policy: ServerAdmissionPolicy,
    ) -> io::Result<Self> {
        Self::new_with_proxy(
            server_hostname,
            tunnel_registry,
            public_tls_config,
            admission_policy,
            None,
            Vec::new(),
        )
    }

    pub(crate) fn new_with_proxy(
        server_hostname: ServerHostname,
        tunnel_registry: TunnelRegistry,
        public_tls_config: Option<Arc<rustls::ServerConfig>>,
        admission_policy: ServerAdmissionPolicy,
        visitor_proxy_protocol: Option<ProxyProtocolVersion>,
        visitor_proxy_trusted_networks: Vec<TrustedNetwork>,
    ) -> io::Result<Self> {
        Ok(Self {
            server_hostname,
            tunnel_registry,
            public_tls_config,
            admission_policy,
            visitor_proxy_protocol,
            visitor_proxy_trusted_networks,
            certificate: None,
        })
    }

    pub(crate) fn with_certificate(
        mut self,
        certificate: Option<crate::server_certificate::ServerCertificateController>,
    ) -> Self {
        self.certificate = certificate;
        self
    }

    #[cfg(test)]
    pub(crate) fn accept(
        &self,
        visitor_stream: TcpStream,
        shutdown: Option<crate::shutdown::OrderlyShutdown>,
    ) {
        if let Some(task) = self.accepted_task(visitor_stream, shutdown) {
            tokio::spawn(crate::server_connection_log::inherit(task));
        }
    }

    pub(crate) fn accept_scoped(
        &self,
        visitor_stream: TcpStream,
        shutdown: crate::shutdown::OrderlyShutdown,
        tasks: &mut tokio::task::JoinSet<()>,
    ) {
        if let Some(task) = self.accepted_task(visitor_stream, Some(shutdown)) {
            tasks.spawn(crate::server_connection_log::inherit(task));
        }
    }

    fn accepted_task(
        &self,
        visitor_stream: TcpStream,
        shutdown: Option<crate::shutdown::OrderlyShutdown>,
    ) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
        // The task owns the tracker, so an abort during shutdown still records an outcome.
        let visitor = self.tunnel_registry.metrics().visitor_accepted();
        let trace = visitor_span();
        let permit = match self.admission_policy.try_admit_visitor_global() {
            Ok(permit) => permit,
            Err(rejection) => {
                drop(visitor_stream);
                self.admission_policy.report_saturation(rejection);
                visitor.reject(VisitorRejectReason::AdmissionVisitorGlobal);
                trace.finish("rejected");
                return None;
            }
        };
        self.admission_policy.report_recovery(&[
            AdmissionLimit::VisitorsGlobal,
            AdmissionLimit::VisitorSource,
        ]);
        let intake = self.clone();
        let timeout = self.admission_policy.limits().client_hello_timeout;
        Some(async move {
            match shutdown {
                Some(shutdown) => {
                    intake
                        .intake_until(
                            visitor_stream,
                            timeout,
                            permit,
                            visitor,
                            trace,
                            async move {
                                let _ = shutdown.wait_started().await;
                            },
                        )
                        .await;
                }
                None => {
                    intake
                        .intake_until(
                            visitor_stream,
                            timeout,
                            permit,
                            visitor,
                            trace,
                            std::future::pending(),
                        )
                        .await;
                }
            }
        })
    }

    async fn intake_until<Shutdown>(
        &self,
        mut visitor_stream: TcpStream,
        timeout: std::time::Duration,
        mut admission_permit: VisitorAdmissionPermit,
        visitor: VisitorTracker,
        trace: TracedStage,
        shutdown: Shutdown,
    ) where
        Shutdown: std::future::Future<Output = ()>,
    {
        let direct_addresses = match VisitorTcpAddresses::from_socket(&visitor_stream) {
            Ok(addresses) => addresses,
            Err(error) => {
                runtime_log::warning("server", &format!("rejected Visitor stream: {error}"));
                visitor.reject(VisitorRejectReason::ParseFailed);
                trace.finish("rejected");
                return;
            }
        };
        let peer_ip = direct_addresses.source.ip();
        let intake_span = tracing::info_span!(target: TARGET, parent: trace.span(), "intake");
        let parsed_client_hello = tokio::select! {
            parsed = tokio::time::timeout(timeout, async {
                let addresses = if self.visitor_proxy_protocol.is_some() {
                    if !self.visitor_proxy_trusted_networks.iter()
                        .any(|network| network.contains(peer_ip))
                    {
                        return Err(IntakeRejection::logged(
                            VisitorRejectReason::ParseFailed,
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "visitor PROXY protocol peer is not trusted",
                            ),
                        ));
                    }
                    read_proxy_v2(&mut visitor_stream).await.map_err(|error| {
                        IntakeRejection::logged(
                            VisitorRejectReason::ParseFailed,
                            io::Error::other(error),
                        )
                    })?
                } else {
                    direct_addresses
                };
                if let Err(rejection) = admission_permit.use_canonical_source(
                    addresses.source.ip(),
                    self.admission_policy
                        .limits()
                        .max_pending_visitors_per_source,
                ) {
                    self.admission_policy.report_saturation(rejection);
                    return Err(IntakeRejection {
                        reason: VisitorRejectReason::AdmissionVisitorSource,
                        error: None,
                    });
                }
                let hello = read_client_hello(&mut visitor_stream).await.map_err(|error| {
                    IntakeRejection::logged(
                        VisitorRejectReason::ParseFailed,
                        io::Error::other(error),
                    )
                })?;
                Ok((hello, addresses))
            }) => match parsed {
                Ok(result) => result,
                Err(_) => Err(IntakeRejection::logged(
                    VisitorRejectReason::IntakeTimeout,
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Visitor pre-routing intake timed out",
                    ),
                )),
            },
            _ = shutdown => {
                drop(intake_span);
                visitor.reject(VisitorRejectReason::Shutdown);
                trace.finish("shutdown");
                return;
            }
        };
        drop(intake_span);
        // Pre-routing capacity protects ClientHello completion only. Existing routed
        // Visitor traffic must remain independent from admission saturation.
        drop(admission_permit);
        let (parsed_client_hello, addresses) = match parsed_client_hello {
            Ok(parsed) => parsed,
            Err(rejection) => {
                if let Some(error) = rejection.error {
                    runtime_log::warning("server", &format!("rejected Visitor stream: {error}"));
                }
                visitor.reject(rejection.reason);
                trace.finish("rejected");
                return;
            }
        };
        self.handle_parsed(
            visitor_stream,
            parsed_client_hello,
            addresses,
            visitor,
            trace,
        )
        .await;
    }

    async fn handle_parsed(
        &self,
        visitor_stream: TcpStream,
        parsed_client_hello: ParsedClientHello,
        addresses: VisitorTcpAddresses,
        visitor: VisitorTracker,
        trace: TracedStage,
    ) {
        let serves_acme_tls_alpn_01 = parsed_client_hello.offers_alpn_protocol(ACME_TLS_ALPN);
        let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();

        if public_hostname.as_str() == self.server_hostname.as_str() {
            if serves_acme_tls_alpn_01 {
                self.serve_acme_tls_alpn_01(
                    visitor_stream,
                    public_hostname,
                    buffered_bytes,
                    visitor,
                    trace,
                )
                .await;
            } else {
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::RejectedServerHostname,
                );
                visitor.reject(VisitorRejectReason::UnknownServerHostname);
                trace.finish("rejected");
            }
            return;
        }

        if self
            .certificate
            .as_ref()
            .is_some_and(|certificate| !certificate.is_serving())
        {
            visitor.reject(VisitorRejectReason::CertificateNotServing);
            trace.finish("rejected");
            return;
        }

        let route_span = tracing::info_span!(target: TARGET, parent: trace.span(), "route");
        let route = self
            .tunnel_registry
            .route_tunnel_connection(&public_hostname)
            .await;
        drop(route_span);
        let selected_tunnel_connection = match route {
            TunnelRouteOutcome::Unauthorized => {
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::RejectedUnauthorized,
                );
                visitor.reject(VisitorRejectReason::UnauthorizedHostname);
                trace.finish("rejected");
                return;
            }
            outcome @ (TunnelRouteOutcome::NoActiveTunnelConnection
            | TunnelRouteOutcome::ShuttingDown) => {
                #[cfg(test)]
                crate::capacity_benchmark::NO_ACTIVE_ROUTE
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::NoActiveTunnelConnection,
                );
                visitor.reject(match outcome {
                    TunnelRouteOutcome::ShuttingDown => VisitorRejectReason::Shutdown,
                    _ => VisitorRejectReason::NoTunnelConnection,
                });
                trace.finish("rejected");
                return;
            }
            TunnelRouteOutcome::Connected(tunnel_connection) => tunnel_connection,
        };

        self.forward_to_tunnel(
            visitor_stream,
            public_hostname,
            buffered_bytes,
            selected_tunnel_connection,
            addresses,
            VisitorRecord {
                metrics: visitor,
                trace,
            },
        )
        .await;
    }

    async fn serve_acme_tls_alpn_01(
        &self,
        visitor_stream: TcpStream,
        server_hostname: PublicHostname,
        buffered_bytes: Vec<u8>,
        visitor: VisitorTracker,
        trace: TracedStage,
    ) {
        if let Some(public_tls_config) = self.public_tls_config.clone() {
            visitor.acme_challenge();
            trace.finish("acme_challenge");
            self.tunnel_registry
                .metrics()
                .acme_event(AcmeMetricEvent::ChallengeHandled);
            runtime_log::acme(
                AcmeRole::Server {
                    server_hostname: server_hostname.as_str(),
                },
                AcmeEvent::ChallengeHandled,
            );
            let acceptor = TlsAcceptor::from(public_tls_config);
            if let Ok(mut tls_stream) = acceptor
                .accept(PrefixedStream::new(buffered_bytes, visitor_stream))
                .await
            {
                let _ = tls_stream.shutdown().await;
            }
        } else {
            runtime_log::server_route(
                server_hostname.as_str(),
                ServerRouteOutcome::MissingAcmeTlsConfig,
            );
            visitor.reject(VisitorRejectReason::UnknownServerHostname);
            trace.finish("rejected");
        }
    }

    async fn forward_to_tunnel(
        &self,
        visitor_stream: TcpStream,
        public_hostname: PublicHostname,
        buffered_bytes: Vec<u8>,
        tunnel_connection: VisitorRoute,
        addresses: VisitorTcpAddresses,
        record: VisitorRecord,
    ) {
        let VisitorRecord {
            metrics: mut visitor,
            trace,
        } = record;
        let pending_open_permit = match self.admission_policy.try_admit_pending_stream_open() {
            Ok(permit) => permit,
            Err(rejection) => {
                self.admission_policy.report_saturation(rejection);
                visitor.reject(VisitorRejectReason::AdmissionPendingStreamOpen);
                trace.finish("rejected");
                return;
            }
        };
        self.admission_policy
            .report_recovery(&[AdmissionLimit::PendingStreamOpens]);

        let stream_open_span =
            tracing::info_span!(target: TARGET, parent: trace.span(), "stream_open");
        let open_started = std::time::Instant::now();
        let open_result = tunnel_connection
            .connection()
            .open_tunnel_stream(self.admission_policy.limits().stream_open_timeout)
            .await;
        let stream_open = open_started.elapsed();
        drop(stream_open_span);
        let stream = match open_result {
            Ok(stream) => stream,
            Err(_) => {
                drop(pending_open_permit);
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::NoActiveTunnelConnection,
                );
                visitor.reject(VisitorRejectReason::StreamOpenFailed);
                trace.finish("rejected");
                return;
            }
        };

        let active_stream_permit = match self.admission_policy.try_admit_active_routed_stream() {
            Ok(permit) => permit,
            Err(rejection) => {
                drop(pending_open_permit);
                drop(stream);
                self.admission_policy.report_saturation(rejection);
                visitor.reject(VisitorRejectReason::AdmissionActiveRoutedStream);
                trace.finish("rejected");
                return;
            }
        };
        drop(pending_open_permit);
        self.admission_policy
            .report_recovery(&[AdmissionLimit::ActiveRoutedStreams]);

        let registry = self.tunnel_registry.clone();
        // Registration is synchronous and precedes proxy progress, so a concurrent
        // Authorization replacement cannot miss already-admitted Visitor work.
        let work = match registry.register_active_visitor_work(
            &public_hostname,
            tunnel_connection,
            active_stream_permit,
        ) {
            Ok(work) => work,
            Err(rejection) => {
                drop(stream);
                visitor.reject(match rejection {
                    VisitorWorkRejection::ShuttingDown => VisitorRejectReason::Shutdown,
                    VisitorWorkRejection::Unauthorized => VisitorRejectReason::UnauthorizedHostname,
                });
                trace.finish("rejected");
                return;
            }
        };
        runtime_log::server_route(public_hostname.as_str(), ServerRouteOutcome::Forwarded);
        // The Visitor span ends at placement, not when the proxied stream closes.
        trace.finish("placed");
        visitor.placed(stream_open);
        let metrics = registry.metrics();
        let outcome = work
            .run(async move {
                let initial_bytes = encode_tunnel_stream(addresses, &buffered_bytes);
                // Count Visitor stream bytes only: the framing prefix ahead of the
                // ClientHello is Runewarp's, not the Visitor's.
                let framing_len = initial_bytes.len() - buffered_bytes.len();
                let (recv, send) = stream.into_split();
                let send =
                    CountedIo::writer(send, metrics.visitor_bytes(VisitorDirection::FromVisitor))
                        .skipping_written_prefix(framing_len);
                // `from_visitor` is counted at the Tunnel writer, not the Visitor socket.
                let tcp_bytes = TcpByteCounters {
                    read: None,
                    written: Some(metrics.visitor_bytes(VisitorDirection::ToVisitor)),
                };
                proxy_tcp_over_tunnel(visitor_stream, initial_bytes, send, recv, tcp_bytes).await
            })
            .await;
        visitor.closed(match outcome {
            Ok(Ok(())) => VisitorCloseOutcome::Ok,
            // Shutdown closing the Tunnel connection under the Visitor is a cancellation.
            Ok(Err(_)) if registry.is_closing_all() => VisitorCloseOutcome::Cancelled,
            Ok(Err(_)) => VisitorCloseOutcome::Error,
            Err(_) => VisitorCloseOutcome::Cancelled,
        });
    }
}

/// One Visitor's metrics tracker and trace span. The span ends at placement; the tracker
/// lasts until the Visitor closes.
struct VisitorRecord {
    metrics: VisitorTracker,
    trace: TracedStage,
}

/// A Visitor dropped during intake, with the error to log when the drop is not already
/// reported by admission saturation logging.
struct IntakeRejection {
    reason: VisitorRejectReason,
    error: Option<io::Error>,
}

impl IntakeRejection {
    fn logged(reason: VisitorRejectReason, error: io::Error) -> Self {
        Self {
            reason,
            error: Some(error),
        }
    }
}

/// Root span for one Server Visitor, from accept to placement or rejection.
fn visitor_span() -> TracedStage {
    let span = tracing::info_span!(
        target: TARGET,
        parent: None,
        "visitor",
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

struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let prefix_len = self.prefix.get_ref().len() as u64;
        if self.prefix.position() < prefix_len {
            let offset = self.prefix.position() as usize;
            let remaining = &self.prefix.get_ref()[offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            let position = self.prefix.position();
            self.prefix.set_position(position + to_copy as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::tunnel::{
        ServerTunnel,
        test_support::{
            ClientPeer, ServerStreams, establish_peers, read_to_end, test_server_h3_config,
        },
    };
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::pem::Error as PemError;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConnection, RootCertStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};
    use tokio_rustls::TlsConnector;
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::fmt::writer::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use crate::LogLevel;
    use crate::acme::ACME_TLS_ALPN;
    use crate::metrics::test_support::sample;
    use crate::metrics::{LabelValue, ServerMetrics, VisitorRejectReason};
    use crate::server::admission::{AdmissionLimit, ServerAdmissionLimits, ServerAdmissionPolicy};
    use crate::tls_material::{certificate_chain_from_pem, private_key_from_pem};
    use crate::{
        CLIENT_HELLO_BUFFER_LIMIT, GeneratedClientIdentity, PublicHostname, ServerHostname,
        ServerTunnelConfig, generate_client_identity, make_client_tunnel_h3_config,
    };

    fn public_hostname(hostname: &str) -> PublicHostname {
        PublicHostname::try_from(hostname).unwrap()
    }

    fn server_hostname(hostname: &str) -> ServerHostname {
        ServerHostname::try_from(hostname).unwrap()
    }

    fn test_admission_policy() -> ServerAdmissionPolicy {
        ServerAdmissionPolicy::new(ServerAdmissionLimits::for_test())
    }

    static LOG_CAPTURE_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(SharedBuffer);

    impl SharedBuffer {
        fn read(&self) -> String {
            String::from_utf8(self.0.lock().expect("buffer mutex poisoned").clone())
                .expect("runtime log output must be valid UTF-8")
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .0
                .lock()
                .expect("buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedBuffer {
        type Writer = BufferWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            BufferWriter(self.clone())
        }
    }

    async fn capture_logs_with_wait<Fut>(
        level: LogLevel,
        needle: &str,
        action: Fut,
    ) -> io::Result<String>
    where
        Fut: std::future::Future<Output = io::Result<()>>,
    {
        let _lock = LOG_CAPTURE_LOCK.lock().await;
        let _ = crate::runtime_log::install(level, crate::LogFormat::Text);
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry()
            .with(level_filter(level))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(buffer.clone())
                    .with_ansi(false)
                    .without_time()
                    .with_target(false),
            );
        let _guard = tracing::subscriber::set_default(subscriber);
        action.await?;
        timeout(Duration::from_secs(5), async {
            loop {
                if buffer.read().contains(needle) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| timeout_error("expected log line to be emitted within timeout"))?;
        Ok(buffer.read())
    }

    fn level_filter(level: LogLevel) -> LevelFilter {
        match level {
            LogLevel::Off => LevelFilter::OFF,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
        }
    }

    #[tokio::test]
    async fn forwards_authorized_public_hostname_through_active_tunnel_connection() -> io::Result<()>
    {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            test_admission_policy(),
        )?;

        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        let visitor_source = visitor.local_addr()?;
        let client_hello = build_client_hello("app.example.test")?;
        visitor.write_all(&client_hello).await?;
        visitor.shutdown().await?;

        let (mut tunnel_send, mut tunnel_recv) = timeout(
            Duration::from_secs(1),
            fixture.client_connection.accept_stream(),
        )
        .await
        .map_err(|_| timeout_error("intake should open a tunnel stream"))?
        .map_err(io::Error::other)?;
        let addresses = crate::proxy_protocol::read_proxy_v2(&mut tunnel_recv)
            .await
            .map_err(io::Error::other)?;
        assert_eq!(addresses.source, visitor_source);
        assert_eq!(addresses.destination, visitor_addr);
        tunnel_send.shutdown().await?;
        let forwarded = timeout(
            Duration::from_secs(1),
            read_to_end(&mut tunnel_recv, client_hello.len() + 1),
        )
        .await
        .map_err(|_| timeout_error("tunnel should receive forwarded bytes"))?
        .map_err(io::Error::other)?;

        assert_eq!(forwarded, client_hello);

        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        Ok(())
    }

    #[cfg(feature = "otel")]
    async fn wait_for_span(
        captured: &crate::trace_export::test_support::CapturedSpans,
        name: &str,
    ) -> io::Result<crate::trace_export::test_support::SpanData> {
        timeout(Duration::from_secs(1), async {
            loop {
                if let Some(span) = captured.span(name) {
                    return span;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| timeout_error("span should be exported"))
    }

    #[cfg(feature = "otel")]
    #[tokio::test]
    async fn visitor_span_ends_at_placement_with_stage_children() -> io::Result<()> {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "visitor_span_ends_at_placement_with_stage_children",
        ) {
            return Ok(());
        }
        use crate::trace_export::test_support::{CapturedSpans, assert_safe_attributes, attribute};
        let captured = CapturedSpans::new(1.0);
        let _trace = captured.set_default();
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor
            .write_all(&build_client_hello("app.example.test")?)
            .await?;
        let (_tunnel_send, _tunnel_recv) =
            timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
                .await
                .map_err(|_| timeout_error("intake should open a tunnel stream"))?
                .map_err(io::Error::other)?;

        // The Visitor stream is still open: the span ends at placement, not at close.
        let root = wait_for_span(&captured, "visitor").await?;
        assert_eq!(
            attribute(&root, crate::trace_export::OUTCOME).as_deref(),
            Some("placed")
        );
        for stage in ["intake", "route", "stream_open"] {
            let child = captured.span(stage).expect("stage span");
            assert_eq!(child.parent_span_id, root.span_context.span_id(), "{stage}");
            assert_eq!(child.span_context.trace_id(), root.span_context.trace_id());
        }
        assert_safe_attributes(
            &captured.finished(),
            &[
                "app.example.test",
                "127.0.0.1",
                &visitor_addr.port().to_string(),
            ],
        );
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        drop(visitor);
        Ok(())
    }

    #[cfg(feature = "otel")]
    #[tokio::test]
    async fn visitor_span_records_rejection() -> io::Result<()> {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "visitor_span_records_rejection",
        ) {
            return Ok(());
        }
        let captured = crate::trace_export::test_support::CapturedSpans::new(1.0);
        let _trace = captured.set_default();
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        assert_admitted_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello("other.example.test")?,
            tunnel_connection,
            VisitorRejectReason::UnauthorizedHostname,
        )
        .await?;

        let root = wait_for_span(&captured, "visitor").await?;
        assert_eq!(
            crate::trace_export::test_support::attribute(&root, crate::trace_export::OUTCOME)
                .as_deref(),
            Some("rejected")
        );
        assert!(captured.span("stream_open").is_none());
        Ok(())
    }

    #[cfg(feature = "otel")]
    #[tokio::test]
    async fn visitor_span_records_rejection_when_no_acme_config_serves_the_challenge()
    -> io::Result<()> {
        if !crate::trace_export::test_support::isolated(
            module_path!(),
            "visitor_span_records_rejection_when_no_acme_config_serves_the_challenge",
        ) {
            return Ok(());
        }
        let captured = crate::trace_export::test_support::CapturedSpans::new(1.0);
        let _trace = captured.set_default();
        // The fixture has no public TLS config, as with a manual Server certificate.
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let client_hello = build_client_hello_with_alpn(
            ServerName::try_from("tunnel.example.test").map_err(io::Error::other)?,
            vec![ACME_TLS_ALPN.to_vec()],
        )?;
        assert_drop_without_opening_a_tunnel_stream(
            intake,
            client_hello,
            Some(tunnel_connection),
            VisitorRejectReason::UnknownServerHostname,
        )
        .await?;

        let root = wait_for_span(&captured, "visitor").await?;
        assert_eq!(
            crate::trace_export::test_support::attribute(&root, crate::trace_export::OUTCOME)
                .as_deref(),
            Some("rejected")
        );
        Ok(())
    }

    #[tokio::test]
    async fn strict_proxy_intake_forwards_only_the_canonical_tuple_and_tls() -> io::Result<()> {
        let (intake, tunnel_connection) =
            configured_proxy_intake_with_active_tunnel_connection("127.0.0.0/8").await?;
        let addresses = VisitorTcpAddresses {
            source: "203.0.113.9:54321".parse().unwrap(),
            destination: "198.51.100.10:443".parse().unwrap(),
        };
        let client_hello = build_client_hello("app.example.test")?;
        let mut ingress = addresses.encode_proxy_v2();
        let address_length = u16::from_be_bytes([ingress[14], ingress[15]]);
        let ingress_only_tlv = [0xe0, 0x00, 0x03, b'r', b'a', b'w'];
        ingress[14..16]
            .copy_from_slice(&(address_length + ingress_only_tlv.len() as u16).to_be_bytes());
        ingress.extend_from_slice(&ingress_only_tlv);
        ingress.extend_from_slice(&client_hello);

        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&ingress).await?;
        visitor.shutdown().await?;

        let (_send, mut recv) = timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
            .await
            .map_err(|_| timeout_error("strict PROXY Visitor should reach the Tunnel"))?
            .map_err(io::Error::other)?;
        let forwarded_addresses = crate::proxy_protocol::read_proxy_v2(&mut recv)
            .await
            .map_err(io::Error::other)?;
        assert_eq!(forwarded_addresses, addresses);
        let forwarded_tls = timeout(
            Duration::from_secs(1),
            read_to_end(&mut recv, client_hello.len() + 1),
        )
        .await
        .map_err(|_| timeout_error("Tunnel should receive the Visitor ClientHello"))?
        .map_err(io::Error::other)?;
        assert_eq!(forwarded_tls, client_hello);
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        Ok(())
    }

    #[tokio::test]
    async fn releases_pre_routing_capacity_before_forwarded_visitor_finishes() -> io::Result<()> {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_visitors: 1,
            max_pending_visitors_per_source: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let (intake, tunnel_connection) =
            configured_intake_with_active_tunnel_connection_and_policy(policy.clone()).await?;
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        let source = visitor.local_addr()?.ip();
        visitor
            .write_all(&build_client_hello("app.example.test")?)
            .await?;
        let (send, recv) = timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
            .await
            .map_err(|_| timeout_error("visitor should reach the Tunnel connection"))?
            .map_err(io::Error::other)?;

        assert!(policy.try_admit_visitor(source).is_ok());
        visitor.shutdown().await?;
        drop(send);
        drop(recv);
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        Ok(())
    }

    #[tokio::test]
    async fn proxy_source_admission_starts_before_client_hello_intake() -> io::Result<()> {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_visitors: 2,
            max_pending_visitors_per_source: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let intake = VisitorIntake::new_with_proxy(
            server_hostname("tunnel.example.test"),
            TunnelRegistry::single(vec![public_hostname("app.example.test")])?,
            None,
            policy.clone(),
            Some(ProxyProtocolVersion::V2),
            vec!["127.0.0.0/8".parse().unwrap()],
        )?;
        let metrics = intake.tunnel_registry.metrics();
        let canonical_source = "203.0.113.9:54321".parse().unwrap();
        let addresses = VisitorTcpAddresses {
            source: canonical_source,
            destination: "198.51.100.10:443".parse().unwrap(),
        };
        let first_listener = TcpListener::bind(localhost(0)).await?;
        let first_addr = first_listener.local_addr()?;
        let first_task = spawn_intake_task(first_listener, intake.clone());

        let mut first_visitor = TcpStream::connect(first_addr).await?;
        let mut partial_intake = addresses.encode_proxy_v2();
        partial_intake.push(0x16);
        first_visitor.write_all(&partial_intake).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let second_listener = TcpListener::bind(localhost(0)).await?;
        let second_addr = second_listener.local_addr()?;
        let second_task = spawn_intake_task(second_listener, intake);
        let mut second_visitor = TcpStream::connect(second_addr).await?;
        second_visitor.write_all(&partial_intake).await?;
        let mut byte = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), second_visitor.read(&mut byte))
            .await
            .map_err(|_| timeout_error("duplicate canonical source should be rejected"))?;
        match read {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected rejected connection, got {other:?}"),
        }

        eventually_metric(
            &metrics,
            r#"runewarp_server_visitors_rejected_total{reason="admission_visitor_source"}"#,
            1.0,
        )
        .await?;
        drop(first_visitor);
        first_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        second_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        Ok(())
    }

    #[tokio::test]
    async fn established_forwarded_stream_survives_active_saturation_and_recovers() -> io::Result<()>
    {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_active_routed_streams: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry.clone(),
            None,
            policy.clone(),
        )?;

        let first_listener = TcpListener::bind(localhost(0)).await?;
        let first_addr = first_listener.local_addr()?;
        let first_task = spawn_intake_task(first_listener, intake.clone());

        let mut established = TcpStream::connect(first_addr).await?;
        let client_hello = build_client_hello("app.example.test")?;
        established.write_all(&client_hello).await?;

        let (mut tunnel_send, mut tunnel_recv) = timeout(
            Duration::from_secs(1),
            fixture.client_connection.accept_stream(),
        )
        .await
        .map_err(|_| timeout_error("established visitor should open a tunnel stream"))?
        .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut tunnel_recv)
            .await
            .map_err(io::Error::other)?;
        let mut forwarded = vec![0_u8; client_hello.len()];
        timeout(
            Duration::from_secs(1),
            tunnel_recv.read_exact(&mut forwarded),
        )
        .await
        .map_err(|_| timeout_error("established stream should receive ClientHello"))?
        .map_err(io::Error::other)?;
        assert_eq!(forwarded, client_hello);
        assert_eq!(registry.tracked_visitor_stream_count(), 1);
        assert_eq!(
            policy.try_admit_active_routed_stream().unwrap_err().limit,
            AdmissionLimit::ActiveRoutedStreams
        );

        // Established traffic still works under saturation.
        tunnel_send
            .write_all(b"alive")
            .await
            .map_err(io::Error::other)?;
        let mut alive = [0_u8; 5];
        timeout(Duration::from_secs(1), established.read_exact(&mut alive))
            .await
            .map_err(|_| timeout_error("established visitor should still receive bytes"))??;
        assert_eq!(&alive, b"alive");

        drop(tunnel_send);
        drop(tunnel_recv);
        established.shutdown().await?;
        first_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        timeout(Duration::from_secs(1), async {
            while registry.tracked_visitor_stream_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| timeout_error("finished Visitor should be untracked"))?;
        assert_eq!(registry.tracked_visitor_stream_count(), 0);
        assert!(policy.try_admit_active_routed_stream().is_ok());

        // Recovery: a new Visitor can be admitted after the established stream exits.
        let recovery_listener = TcpListener::bind(localhost(0)).await?;
        let recovery_addr = recovery_listener.local_addr()?;
        let recovery_task = spawn_intake_task(recovery_listener, intake);
        let mut recovered = TcpStream::connect(recovery_addr).await?;
        recovered.write_all(&client_hello).await?;
        recovered.shutdown().await?;
        let (_send, mut recv) = timeout(
            Duration::from_secs(1),
            fixture.client_connection.accept_stream(),
        )
        .await
        .map_err(|_| timeout_error("recovery visitor should open a tunnel stream"))?
        .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut recv)
            .await
            .map_err(io::Error::other)?;
        let recovered_bytes = timeout(
            Duration::from_secs(1),
            read_to_end(&mut recv, client_hello.len() + 1),
        )
        .await
        .map_err(|_| timeout_error("recovery stream should receive ClientHello"))?
        .map_err(io::Error::other)?;
        assert_eq!(recovered_bytes, client_hello);
        let _ = timeout(Duration::from_secs(1), recovery_task).await;
        Ok(())
    }

    #[tokio::test]
    async fn pending_stream_open_saturation_rejects_new_visitors_then_recovers() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_stream_opens: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let held_pending = policy
            .try_admit_pending_stream_open()
            .expect("pending open should fit");
        let metrics = registry.metrics();
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            policy.clone(),
        )?;

        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor
            .write_all(&build_client_hello("app.example.test")?)
            .await?;
        visitor.shutdown().await?;

        match timeout(
            Duration::from_millis(200),
            fixture.client_connection.accept_stream(),
        )
        .await
        {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("saturated pending opens must not open a tunnel stream"),
        }

        let mut read_buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut read_buffer))
            .await
            .map_err(|_| timeout_error("visitor should observe a dropped connection"))??;
        assert_eq!(read, 0);
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        assert_only_rejection(&metrics, VisitorRejectReason::AdmissionPendingStreamOpen).await?;
        drop(held_pending);
        assert!(policy.try_admit_pending_stream_open().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn active_routed_stream_saturation_resets_opened_stream_then_recovers() -> io::Result<()>
    {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_active_routed_streams: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let held_active = policy
            .try_admit_active_routed_stream()
            .expect("active stream should fit");
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry.clone(),
            None,
            policy.clone(),
        )?;

        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor
            .write_all(&build_client_hello("app.example.test")?)
            .await?;
        visitor.shutdown().await?;

        let _ = timeout(
            Duration::from_millis(200),
            fixture.client_connection.accept_stream(),
        )
        .await;

        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        assert_eq!(registry.tracked_visitor_stream_count(), 0);
        assert_only_rejection(
            &registry.metrics(),
            VisitorRejectReason::AdmissionActiveRoutedStream,
        )
        .await?;

        drop(held_active);
        assert!(policy.try_admit_active_routed_stream().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn stream_open_deadline_drops_visitor_and_releases_pending_capacity() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture =
            TunnelConnectionFixture::connect_with_stream_budget(&client_identity, 1).await?;
        registry.register(fixture.server_connection.clone()).await;
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            stream_open_timeout: Duration::from_millis(50),
            max_pending_stream_opens: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let metrics = registry.metrics();
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            policy.clone(),
        )?;

        // Open the only Visitor credit and leave its permit held.
        let (_held_send, _held_recv) = timeout(
            Duration::from_secs(1),
            fixture.server_connection.open_stream(),
        )
        .await
        .map_err(|_| timeout_error("first stream open should succeed"))?
        .map_err(io::Error::other)?;

        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor
            .write_all(&build_client_hello("app.example.test")?)
            .await?;
        visitor.shutdown().await?;

        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        let mut byte = [0_u8; 1];
        let dropped = timeout(Duration::from_secs(1), visitor.read(&mut byte))
            .await
            .map_err(|_| timeout_error("stream-open deadline must drop the Visitor"))?;
        assert!(
            matches!(dropped, Ok(0))
                || matches!(
                    dropped,
                    Err(ref error) if error.kind() == io::ErrorKind::ConnectionReset
                )
        );

        // Pending-open capacity must recover after the deadline rejects the waiter.
        let recovered = timeout(Duration::from_secs(1), async {
            loop {
                if policy.try_admit_pending_stream_open().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            recovered.is_ok(),
            "stream open timeout must release pending-open capacity"
        );
        assert_only_rejection(&metrics, VisitorRejectReason::StreamOpenFailed).await
    }

    #[tokio::test]
    async fn client_hello_deadline_releases_intake_capacity() -> io::Result<()> {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            client_hello_timeout: Duration::from_millis(50),
            max_pending_visitors: 1,
            max_pending_visitors_per_source: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let intake = VisitorIntake::new(
            server_hostname("tunnel.example.test"),
            TunnelRegistry::single(vec![public_hostname("app.example.test")])?,
            None,
            policy.clone(),
        )?;
        let metrics = intake.tunnel_registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        let source = visitor.local_addr()?.ip();
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        assert!(matches!(
            policy.try_admit_visitor(source),
            Err(crate::server::admission::AdmissionRejection {
                limit: AdmissionLimit::VisitorsGlobal,
                active_work: 1,
            })
        ));
        let mut byte = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut byte))
            .await
            .map_err(|_| timeout_error("deadline should reject zero-byte Visitor intake"))?;
        match read {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected deadline rejection, got {other:?}"),
        }
        assert!(policy.try_admit_visitor(source).is_ok());
        assert_only_rejection(&metrics, VisitorRejectReason::IntakeTimeout).await
    }

    #[tokio::test]
    async fn shutdown_releases_zero_byte_pre_routing_capacity() -> io::Result<()> {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_visitors: 1,
            max_pending_visitors_per_source: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let intake = VisitorIntake::new(
            server_hostname("tunnel.example.test"),
            TunnelRegistry::single(vec![public_hostname("app.example.test")])?,
            None,
            policy.clone(),
        )?;
        let metrics = intake.tunnel_registry.metrics();
        let source = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let shutdown =
            crate::shutdown::OrderlyShutdown::new(Duration::from_secs(5), Duration::from_millis(1));
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let shutdown_for_task = shutdown.clone();
        let intake_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await?;
            intake.accept(visitor_stream, Some(shutdown_for_task));
            Ok::<_, io::Error>(())
        });
        let _visitor = TcpStream::connect(visitor_addr).await?;
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        assert!(matches!(
            policy.try_admit_visitor(source),
            Err(crate::server::admission::AdmissionRejection {
                limit: AdmissionLimit::VisitorsGlobal,
                active_work: 1,
            })
        ));
        shutdown.begin_fast();
        timeout(Duration::from_secs(1), async {
            loop {
                if policy.try_admit_visitor(source).is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| timeout_error("shutdown should release Visitor intake capacity"))?;
        assert_only_rejection(&metrics, VisitorRejectReason::Shutdown).await
    }

    #[tokio::test]
    async fn serves_acme_tls_for_the_server_hostname() -> io::Result<()> {
        let registry = TunnelRegistry::single(vec![public_hostname("app.example.test")])?;
        let (certificate, public_tls_config) = make_public_tls_config("tunnel.example.test")?;
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            Some(public_tls_config),
            test_admission_policy(),
        )?;
        let metrics = intake.tunnel_registry.metrics();

        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let connector = TlsConnector::from(make_client_tls_config(
            &certificate,
            vec![ACME_TLS_ALPN.to_vec()],
        )?);
        let visitor_stream = TcpStream::connect(visitor_addr).await?;
        let tls_stream = timeout(
            Duration::from_secs(1),
            connector.connect(
                ServerName::try_from("tunnel.example.test".to_owned()).map_err(io::Error::other)?,
                visitor_stream,
            ),
        )
        .await
        .map_err(|_| timeout_error("ACME TLS handshake should complete"))?
        .map_err(io::Error::other)?;

        drop(tls_stream);
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        // A challenge is neither placed nor rejected.
        let text = metrics.render();
        assert_eq!(
            sample(&text, "runewarp_server_visitors_accepted_total"),
            Some(1.0)
        );
        assert_eq!(
            sample(&text, "runewarp_server_visitors_placed_total"),
            Some(0.0)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_acme_events_total{event="challenge_handled"}"#
            ),
            Some(1.0)
        );
        for reason in VisitorRejectReason::ALL {
            let series = format!(
                r#"runewarp_server_visitors_rejected_total{{reason="{}"}}"#,
                reason.as_str()
            );
            assert_eq!(sample(&text, &series), Some(0.0), "{series}");
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_acme_challenge_logs_as_acme_handling_not_routing() -> io::Result<()> {
        let output = capture_logs_with_wait(
            LogLevel::Debug,
            "DEBUG server acme challenge handled: server-hostname=tunnel.example.test",
            async {
                let registry = TunnelRegistry::single(vec![public_hostname("app.example.test")])?;
                let (certificate, public_tls_config) =
                    make_public_tls_config("tunnel.example.test")?;
                let intake = VisitorIntake::new(
                    server_hostname("Tunnel.Example.Test."),
                    registry,
                    Some(public_tls_config),
                    test_admission_policy(),
                )?;

                let listener = TcpListener::bind(localhost(0)).await?;
                let visitor_addr = listener.local_addr()?;
                let intake_task = spawn_intake_task(listener, intake);

                let connector = TlsConnector::from(make_client_tls_config(
                    &certificate,
                    vec![ACME_TLS_ALPN.to_vec()],
                )?);
                let visitor_stream = TcpStream::connect(visitor_addr).await?;
                let tls_stream = timeout(
                    Duration::from_secs(1),
                    connector.connect(
                        ServerName::try_from("tunnel.example.test".to_owned())
                            .map_err(io::Error::other)?,
                        visitor_stream,
                    ),
                )
                .await
                .map_err(|_| timeout_error("ACME TLS handshake should complete"))?
                .map_err(io::Error::other)?;

                drop(tls_stream);
                intake_task
                    .await
                    .map_err(|error| join_error("intake task failed", error))??;
                Ok(())
            },
        )
        .await?;

        assert!(
            output.contains(
                "DEBUG server acme challenge handled: server-hostname=tunnel.example.test"
            )
        );
        assert!(!output.contains("server route acme-challenge"));
        assert!(!output.contains("public-hostname=tunnel.example.test"));
        Ok(())
    }

    #[tokio::test]
    async fn drops_application_traffic_for_the_server_hostname_without_opening_a_tunnel_stream()
    -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello("tunnel.example.test")?,
            Some(tunnel_connection),
            VisitorRejectReason::UnknownServerHostname,
        )
        .await
    }

    #[tokio::test]
    async fn drops_invalid_tls_without_opening_a_tunnel_stream() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            b"not tls".to_vec(),
            Some(tunnel_connection),
            VisitorRejectReason::ParseFailed,
        )
        .await
    }

    #[tokio::test]
    async fn drops_client_hello_without_sni_without_opening_a_tunnel_stream() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello_for_server_name(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))?,
            Some(tunnel_connection),
            VisitorRejectReason::ParseFailed,
        )
        .await
    }

    #[tokio::test]
    async fn drops_client_hello_with_invalid_sni_without_opening_a_tunnel_stream() -> io::Result<()>
    {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            invalid_sni_client_hello()?,
            Some(tunnel_connection),
            VisitorRejectReason::ParseFailed,
        )
        .await
    }

    #[tokio::test]
    async fn drops_incomplete_client_hello_without_opening_a_tunnel_stream() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let mut client_hello = build_client_hello("app.example.test")?;
        client_hello.truncate(10);

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            client_hello,
            Some(tunnel_connection),
            VisitorRejectReason::ParseFailed,
        )
        .await
    }

    #[tokio::test]
    async fn drops_oversized_client_hello_without_opening_a_tunnel_stream() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            oversized_client_hello(),
            Some(tunnel_connection),
            VisitorRejectReason::ParseFailed,
        )
        .await
    }

    #[tokio::test]
    async fn strict_proxy_listener_rejects_invalid_or_untrusted_intake_before_tunneling()
    -> io::Result<()> {
        let addresses = VisitorTcpAddresses {
            source: "203.0.113.9:54321".parse().unwrap(),
            destination: "198.51.100.10:443".parse().unwrap(),
        };
        let direct_tls = build_client_hello("app.example.test")?;
        let mut malformed = addresses.encode_proxy_v2();
        malformed[0] ^= 0xff;
        let mut oversized = addresses.encode_proxy_v2();
        oversized[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        let mut udp = addresses.encode_proxy_v2();
        udp[13] = 0x12;
        let mut unspecified_family = addresses.encode_proxy_v2();
        unspecified_family[13] = 0x00;
        let mut unix_family = addresses.encode_proxy_v2();
        unix_family[13] = 0x31;
        let mut local = addresses.encode_proxy_v2();
        local[12] = 0x20;

        for visitor_bytes in [
            direct_tls,
            malformed,
            oversized,
            udp,
            unspecified_family,
            unix_family,
            local,
        ] {
            let (intake, tunnel_connection) =
                configured_proxy_intake_with_active_tunnel_connection("127.0.0.0/8").await?;
            assert_admitted_drop_without_opening_a_tunnel_stream(
                intake,
                visitor_bytes,
                tunnel_connection,
                VisitorRejectReason::ParseFailed,
            )
            .await?;
        }

        let (intake, tunnel_connection) =
            configured_proxy_intake_with_active_tunnel_connection("10.0.0.0/8").await?;
        let mut valid_but_untrusted = addresses.encode_proxy_v2();
        valid_but_untrusted.extend_from_slice(&build_client_hello("app.example.test")?);
        assert_admitted_drop_without_opening_a_tunnel_stream(
            intake,
            valid_but_untrusted,
            tunnel_connection,
            VisitorRejectReason::ParseFailed,
        )
        .await
    }

    #[tokio::test]
    async fn drops_unauthorized_public_hostname_without_opening_a_tunnel_stream() -> io::Result<()>
    {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello("api.example.test")?,
            Some(tunnel_connection),
            VisitorRejectReason::UnauthorizedHostname,
        )
        .await
    }

    #[tokio::test]
    async fn drops_public_hostname_when_the_tunnel_has_no_active_connection() -> io::Result<()> {
        let registry = TunnelRegistry::single(vec![public_hostname("app.example.test")])?;
        let intake = VisitorIntake::new(
            server_hostname("tunnel.example.test"),
            registry,
            None,
            test_admission_policy(),
        )?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello("app.example.test")?,
            None,
            VisitorRejectReason::NoTunnelConnection,
        )
        .await
    }

    #[tokio::test]
    async fn drops_public_hostname_cleanly_after_the_active_tunnel_connection_closes()
    -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        fixture
            .server_connection
            .close(b"closed before visitor handling");
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            test_admission_policy(),
        )?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello("app.example.test")?,
            Some(fixture.client_connection),
            VisitorRejectReason::NoTunnelConnection,
        )
        .await
    }

    #[tokio::test]
    async fn visitor_global_admission_rejection_is_counted() -> io::Result<()> {
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            max_pending_visitors: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let _held = policy
            .try_admit_visitor_global()
            .expect("the only intake slot should fit");
        let intake = VisitorIntake::new(
            server_hostname("tunnel.example.test"),
            TunnelRegistry::single(vec![public_hostname("app.example.test")])?,
            None,
            policy,
        )?;
        let metrics = intake.tunnel_registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        let mut byte = [0_u8; 1];
        match timeout(Duration::from_secs(1), visitor.read(&mut byte)).await {
            Ok(Ok(0)) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected rejected connection, got {other:?}"),
        }
        assert_only_rejection(&metrics, VisitorRejectReason::AdmissionVisitorGlobal).await
    }

    #[tokio::test]
    async fn drops_visitors_while_the_server_certificate_is_not_serving() -> io::Result<()> {
        struct UnusedRoute;
        impl crate::server_certificate::ChallengeRouteObserver for UnusedRoute {
            fn observe(
                &self,
                _request: crate::server_certificate::ChallengeRouteRequest,
            ) -> futures_util::future::BoxFuture<
                '_,
                io::Result<crate::server_certificate::ConsumedChallengeRoute>,
            > {
                Box::pin(async { Err(io::Error::other("no ACME work runs in this test")) })
            }
        }
        let validation = crate::server_certificate::CertificateValidation::new(
            server_hostname("tunnel.example.test"),
            Arc::new(RootCertStore::empty()),
            Duration::from_secs(3_600),
            Duration::from_secs(60),
        )?;
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let options = crate::server_certificate::ServerAcmeOptions::new(
            validation,
            "https://acme.invalid/directory",
            Arc::new(client_config),
            Arc::new(UnusedRoute),
        )?;
        let store = tempfile::tempdir()?;
        // An empty store holds no committed snapshot, so the certificate is not serving.
        let certificate = crate::server_certificate::ServerCertificateController::new(
            store.path().to_path_buf(),
            "ops@example.test".to_owned(),
            options,
        )?;
        assert!(!certificate.is_serving());
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        assert_drop_without_opening_a_tunnel_stream(
            intake.with_certificate(Some(certificate)),
            build_client_hello("app.example.test")?,
            Some(tunnel_connection),
            VisitorRejectReason::CertificateNotServing,
        )
        .await
    }

    #[tokio::test]
    async fn drops_visitors_after_the_registry_stops_accepting_work() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        intake.tunnel_registry.stop_accepting_new_work();
        assert_drop_without_opening_a_tunnel_stream(
            intake,
            build_client_hello("app.example.test")?,
            Some(tunnel_connection),
            VisitorRejectReason::Shutdown,
        )
        .await
    }

    #[tokio::test]
    async fn placed_visitor_counts_tls_bytes_in_both_directions_across_half_close() -> io::Result<()>
    {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let metrics = intake.tunnel_registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let client_hello = build_client_hello("app.example.test")?;
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&client_hello).await?;
        visitor.write_all(b"request").await?;
        // Half-close: the Visitor finishes sending but still reads the response.
        visitor.shutdown().await?;

        let (mut tunnel_send, mut tunnel_recv) =
            timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
                .await
                .map_err(|_| timeout_error("intake should open a tunnel stream"))?
                .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut tunnel_recv)
            .await
            .map_err(io::Error::other)?;
        let forwarded = timeout(
            Duration::from_secs(1),
            read_to_end(&mut tunnel_recv, client_hello.len() + 8),
        )
        .await
        .map_err(|_| timeout_error("tunnel should receive the Visitor's bytes"))?
        .map_err(io::Error::other)?;
        assert_eq!(forwarded.len(), client_hello.len() + b"request".len());
        let text = metrics.render();
        assert_eq!(
            sample(&text, "runewarp_server_visitors_placed_total"),
            Some(1.0)
        );
        assert_eq!(sample(&text, "runewarp_server_visitors_active"), Some(1.0));

        tunnel_send
            .write_all(b"response-bytes")
            .await
            .map_err(io::Error::other)?;
        tunnel_send.shutdown().await.map_err(io::Error::other)?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(1), visitor.read_to_end(&mut response))
            .await
            .map_err(|_| timeout_error("Visitor should read the response to FIN"))??;
        assert_eq!(response, b"response-bytes");
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        let text = eventually_metric(
            &metrics,
            r#"runewarp_server_visitors_closed_total{outcome="ok"}"#,
            1.0,
        )
        .await?;
        // ClientHello plus forwarded TLS, without the Runewarp framing prefix.
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitor_bytes_total{direction="from_visitor"}"#
            ),
            Some((client_hello.len() + b"request".len()) as f64)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitor_bytes_total{direction="to_visitor"}"#
            ),
            Some(b"response-bytes".len() as f64)
        );
        assert_eq!(sample(&text, "runewarp_server_visitors_active"), Some(0.0));
        assert_eq!(
            sample(&text, "runewarp_server_visitor_duration_seconds_count"),
            Some(1.0)
        );
        assert_eq!(
            sample(
                &text,
                "runewarp_server_visitor_stream_open_duration_seconds_count"
            ),
            Some(1.0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn reset_tunnel_stream_closes_the_placed_visitor_with_an_error() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let metrics = intake.tunnel_registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let client_hello = build_client_hello("app.example.test")?;
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&client_hello).await?;

        let (tunnel_send, mut tunnel_recv) =
            timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
                .await
                .map_err(|_| timeout_error("intake should open a tunnel stream"))?
                .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut tunnel_recv)
            .await
            .map_err(io::Error::other)?;
        eventually_metric(&metrics, "runewarp_server_visitors_active", 1.0).await?;
        // Dropping both halves without FIN resets the stream in both directions.
        drop(tunnel_send);
        drop(tunnel_recv);
        visitor.shutdown().await?;
        let _ = timeout(Duration::from_secs(1), visitor.read(&mut [0_u8; 1])).await;
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        let text = eventually_metric(
            &metrics,
            r#"runewarp_server_visitors_closed_total{outcome="error"}"#,
            1.0,
        )
        .await?;
        assert_eq!(sample(&text, "runewarp_server_visitors_active"), Some(0.0));
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitors_closed_total{outcome="ok"}"#
            ),
            Some(0.0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_closing_the_tunnel_cancels_the_placed_visitor() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let registry = intake.tunnel_registry.clone();
        let metrics = registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor
            .write_all(&build_client_hello("app.example.test")?)
            .await?;
        let (_send, mut recv) = timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
            .await
            .map_err(|_| timeout_error("intake should open a tunnel stream"))?
            .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut recv)
            .await
            .map_err(io::Error::other)?;
        eventually_metric(&metrics, "runewarp_server_visitors_active", 1.0).await?;
        registry.close_all(b"graceful shutdown").await;
        // The closed Tunnel fails the response direction; finishing the request lets the
        // proxy return that error instead of waiting on the Visitor.
        let _ = timeout(Duration::from_secs(1), visitor.read(&mut [0_u8; 1])).await;
        let _ = visitor.shutdown().await;
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        let text = eventually_metric(
            &metrics,
            r#"runewarp_server_visitors_closed_total{outcome="cancelled"}"#,
            1.0,
        )
        .await?;
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitors_closed_total{outcome="error"}"#
            ),
            Some(0.0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn strict_proxy_prefix_is_not_counted_as_visitor_bytes() -> io::Result<()> {
        let (intake, tunnel_connection) =
            configured_proxy_intake_with_active_tunnel_connection("127.0.0.0/8").await?;
        let metrics = intake.tunnel_registry.metrics();
        let addresses = VisitorTcpAddresses {
            source: "203.0.113.9:54321".parse().unwrap(),
            destination: "198.51.100.10:443".parse().unwrap(),
        };
        let client_hello = build_client_hello("app.example.test")?;
        let mut ingress = addresses.encode_proxy_v2();
        ingress.extend_from_slice(&client_hello);
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&ingress).await?;
        visitor.shutdown().await?;
        let (mut send, mut recv) =
            timeout(Duration::from_secs(1), tunnel_connection.accept_stream())
                .await
                .map_err(|_| timeout_error("PROXY Visitor should reach the Tunnel"))?
                .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut recv)
            .await
            .map_err(io::Error::other)?;
        read_to_end(&mut recv, client_hello.len() + 1)
            .await
            .map_err(io::Error::other)?;
        send.shutdown().await.map_err(io::Error::other)?;
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        let text = eventually_metric(
            &metrics,
            r#"runewarp_server_visitors_closed_total{outcome="ok"}"#,
            1.0,
        )
        .await?;
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitor_bytes_total{direction="from_visitor"}"#
            ),
            Some(client_hello.len() as f64)
        );
        Ok(())
    }

    #[tokio::test]
    async fn revoked_visitor_closes_cancelled_and_keeps_bytes_already_forwarded() -> io::Result<()>
    {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured_managed(
            &server_hostname("tunnel.example.test"),
            &[ServerTunnelConfig {
                id: Some(crate::TunnelId::parse("tunnel-1").unwrap()),
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let metrics = registry.metrics();
        let intake = VisitorIntake::new(
            server_hostname("tunnel.example.test"),
            registry.clone(),
            None,
            test_admission_policy(),
        )?;
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);
        let client_hello = build_client_hello("app.example.test")?;
        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&client_hello).await?;

        let (mut tunnel_send, mut tunnel_recv) = timeout(
            Duration::from_secs(1),
            fixture.client_connection.accept_stream(),
        )
        .await
        .map_err(|_| timeout_error("intake should open a tunnel stream"))?
        .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut tunnel_recv)
            .await
            .map_err(io::Error::other)?;
        let mut forwarded = vec![0_u8; client_hello.len()];
        tunnel_recv
            .read_exact(&mut forwarded)
            .await
            .map_err(io::Error::other)?;
        tunnel_send
            .write_all(b"partial")
            .await
            .map_err(io::Error::other)?;
        let mut partial = [0_u8; 7];
        timeout(Duration::from_secs(1), visitor.read_exact(&mut partial))
            .await
            .map_err(|_| timeout_error("Visitor should receive the partial response"))??;

        let dispatch = registry
            .replace_authorization(
                &server_hostname("tunnel.example.test"),
                &[ServerTunnelConfig {
                    id: Some(crate::TunnelId::parse("tunnel-1").unwrap()),
                    public_hostnames: vec![public_hostname("other.example.test")],
                    authorized_client_identities: vec![client_identity.client_identity.clone()],
                }],
            )
            .await?;
        assert_eq!(dispatch.streams_reset, 1);
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;

        let text = eventually_metric(
            &metrics,
            r#"runewarp_server_visitors_closed_total{outcome="cancelled"}"#,
            1.0,
        )
        .await?;
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitor_bytes_total{direction="from_visitor"}"#
            ),
            Some(client_hello.len() as f64)
        );
        assert_eq!(
            sample(
                &text,
                r#"runewarp_server_visitor_bytes_total{direction="to_visitor"}"#
            ),
            Some(7.0)
        );
        assert_eq!(sample(&text, "runewarp_server_visitors_active"), Some(0.0));
        Ok(())
    }

    async fn configured_intake_with_active_tunnel_connection()
    -> io::Result<(VisitorIntake, ClientPeer)> {
        configured_intake_with_active_tunnel_connection_and_policy(test_admission_policy()).await
    }

    async fn configured_intake_with_active_tunnel_connection_and_policy(
        policy: ServerAdmissionPolicy,
    ) -> io::Result<(VisitorIntake, ClientPeer)> {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            policy,
        )?;

        Ok((intake, fixture.client_connection))
    }

    async fn configured_proxy_intake_with_active_tunnel_connection(
        trusted_network: &str,
    ) -> io::Result<(VisitorIntake, ClientPeer)> {
        let client_identity = generate_test_client_identity()?;
        let registry = TunnelRegistry::configured(
            &server_hostname("Tunnel.Example.Test."),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("App.Example.Test.")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        registry.register(fixture.server_connection.clone()).await;
        let intake = VisitorIntake::new_with_proxy(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            test_admission_policy(),
            Some(ProxyProtocolVersion::V2),
            vec![trusted_network.parse().unwrap()],
        )?;

        Ok((intake, fixture.client_connection))
    }

    async fn assert_admitted_drop_without_opening_a_tunnel_stream(
        intake: VisitorIntake,
        visitor_bytes: Vec<u8>,
        tunnel_connection: ClientPeer,
        expected: VisitorRejectReason,
    ) -> io::Result<()> {
        let metrics = intake.tunnel_registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&visitor_bytes).await?;
        visitor.shutdown().await?;

        match timeout(
            Duration::from_millis(100),
            tunnel_connection.accept_stream(),
        )
        .await
        {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("intake unexpectedly opened a tunnel stream"),
        }
        let mut byte = [0_u8; 1];
        match visitor.read(&mut byte).await {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("expected rejected connection, got {other:?}"),
        }
        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        assert_only_rejection(&metrics, expected).await
    }

    async fn assert_drop_without_opening_a_tunnel_stream(
        intake: VisitorIntake,
        visitor_bytes: Vec<u8>,
        tunnel_connection: Option<ClientPeer>,
        expected: VisitorRejectReason,
    ) -> io::Result<()> {
        let metrics = intake.tunnel_registry.metrics();
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&visitor_bytes).await?;
        visitor.shutdown().await?;

        if let Some(tunnel_connection) = tunnel_connection {
            match timeout(
                Duration::from_millis(200),
                tunnel_connection.accept_stream(),
            )
            .await
            {
                Err(_) | Ok(Err(_)) => {}
                Ok(Ok(_)) => panic!("intake unexpectedly opened a tunnel stream"),
            }
        }

        let mut read_buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut read_buffer))
            .await
            .map_err(|_| timeout_error("visitor should observe a dropped connection"))??;
        assert_eq!(read, 0);

        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        assert_only_rejection(&metrics, expected).await
    }

    /// Wait until `series` reads `value`, or fail with the last scrape.
    async fn eventually_metric(
        metrics: &ServerMetrics,
        series: &str,
        value: f64,
    ) -> io::Result<String> {
        let mut text = metrics.render();
        for _ in 0..200 {
            if sample(&text, series) == Some(value) {
                return Ok(text);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
            text = metrics.render();
        }
        panic!("{series} never reached {value}:\n{text}");
    }

    /// The single accepted Visitor was rejected for `expected` and nothing else.
    async fn assert_only_rejection(
        metrics: &ServerMetrics,
        expected: VisitorRejectReason,
    ) -> io::Result<()> {
        let series = format!(
            r#"runewarp_server_visitors_rejected_total{{reason="{}"}}"#,
            expected.as_str()
        );
        let text = eventually_metric(metrics, &series, 1.0).await?;
        for reason in VisitorRejectReason::ALL {
            if *reason != expected {
                let other = format!(
                    r#"runewarp_server_visitors_rejected_total{{reason="{}"}}"#,
                    reason.as_str()
                );
                assert_eq!(sample(&text, &other), Some(0.0), "{other}\n{text}");
            }
        }
        assert_eq!(
            sample(&text, "runewarp_server_visitors_accepted_total"),
            Some(1.0)
        );
        assert_eq!(
            sample(&text, "runewarp_server_visitors_placed_total"),
            Some(0.0)
        );
        Ok(())
    }

    fn spawn_intake_task(
        listener: TcpListener,
        intake: VisitorIntake,
    ) -> JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let (visitor_stream, _) =
                timeout(Duration::from_secs(1), listener.accept())
                    .await
                    .map_err(|_| timeout_error("intake should accept a visitor connection"))??;
            intake.accept(visitor_stream, None);
            Ok(())
        })
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        client_connection: ClientPeer,
        server_connection: Arc<ServerTunnel>,
    }

    impl TunnelConnectionFixture {
        async fn connect(client_identity: &GeneratedClientIdentity) -> io::Result<Self> {
            Self::connect_with_stream_budget(client_identity, 1024).await
        }

        async fn connect_with_stream_budget(
            client_identity: &GeneratedClientIdentity,
            stream_budget: u32,
        ) -> io::Result<Self> {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
            let server_endpoint = Endpoint::server(
                test_server_h3_config(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                    std::slice::from_ref(&client_identity.client_identity),
                )
                .map_err(io::Error::other)?,
                localhost(0),
            )
            .map_err(io::Error::other)?;
            let server_addr = server_endpoint.local_addr()?;

            let mut client_endpoint = Endpoint::client(localhost(0)).map_err(io::Error::other)?;
            let client_config = make_client_tunnel_h3_config(
                root_store_with(&certificate)?,
                client_certificate_chain(client_identity)?,
                client_private_key(client_identity)?,
            )
            .map_err(io::Error::other)?;
            client_endpoint.set_default_client_config(client_config);

            let accept_connection = async {
                let incoming = timeout(Duration::from_secs(1), server_endpoint.accept())
                    .await
                    .map_err(|_| timeout_error("server endpoint should accept a QUIC connection"))?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
                    })?;
                timeout(Duration::from_secs(1), incoming)
                    .await
                    .map_err(|_| timeout_error("server should finish the QUIC handshake"))?
                    .map_err(io::Error::other)
            };
            let connect_client = async {
                let connect = client_endpoint
                    .connect(server_addr, "tunnel.example.test")
                    .map_err(io::Error::other)?;
                timeout(Duration::from_secs(1), connect)
                    .await
                    .map_err(|_| timeout_error("client should finish the QUIC handshake"))?
                    .map_err(io::Error::other)
            };
            let (server_connection, client_connection) =
                tokio::try_join!(accept_connection, connect_client)?;
            let (server_connection, client_connection) =
                establish_peers(server_connection, client_connection, stream_budget as usize)
                    .await?;

            Ok(Self {
                _server_endpoint: server_endpoint,
                _client_endpoint: client_endpoint,
                client_connection,
                server_connection,
            })
        }
    }

    fn generate_test_client_identity() -> io::Result<GeneratedClientIdentity> {
        generate_client_identity().map_err(io::Error::other)
    }

    fn build_client_hello(server_name: &str) -> io::Result<Vec<u8>> {
        build_client_hello_for_server_name(
            ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?,
        )
    }

    fn build_client_hello_for_server_name(server_name: ServerName<'static>) -> io::Result<Vec<u8>> {
        build_client_hello_with_alpn(server_name, Vec::new())
    }

    fn build_client_hello_with_alpn(
        server_name: ServerName<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        let trusted_cert =
            generate_simple_self_signed(vec!["localhost".to_owned()]).map_err(io::Error::other)?;
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).map_err(io::Error::other)?;

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        let mut connection =
            ClientConnection::new(Arc::new(config), server_name).map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes)?;
        Ok(bytes)
    }

    fn invalid_sni_client_hello() -> io::Result<Vec<u8>> {
        let valid_hostname = b"app.example.test";
        let invalid_hostname = b"bad_example.test";
        let mut client_hello = build_client_hello("app.example.test")?;
        let offset = client_hello
            .windows(valid_hostname.len())
            .position(|window| window == valid_hostname)
            .ok_or_else(|| {
                io::Error::other("test client hello did not contain the expected SNI")
            })?;
        client_hello[offset..offset + valid_hostname.len()].copy_from_slice(invalid_hostname);
        Ok(client_hello)
    }

    fn oversized_client_hello() -> Vec<u8> {
        let mut oversized = vec![0x16, 0x03, 0x03, 0x40, 0x01];
        oversized.extend(std::iter::repeat_n(0_u8, CLIENT_HELLO_BUFFER_LIMIT));
        oversized
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn make_self_signed_cert(server_name: &str) -> io::Result<(CertificateDer<'static>, Vec<u8>)> {
        let certified_key =
            generate_simple_self_signed(vec![server_name.to_owned()]).map_err(io::Error::other)?;
        Ok((
            CertificateDer::from(certified_key.cert),
            certified_key.signing_key.serialize_der(),
        ))
    }

    fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn client_certificate_chain(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<Vec<CertificateDer<'static>>> {
        certificate_chain_from_pem(client_identity.certificate_pem.as_bytes())
            .map_err(io::Error::other)
    }

    fn client_private_key(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<PrivateKeyDer<'static>> {
        private_key_from_pem(client_identity.private_key_pem.as_bytes()).map_err(|source| {
            match source {
                PemError::NoItemsFound => {
                    io::Error::new(io::ErrorKind::InvalidData, "missing client private key")
                }
                other => io::Error::other(other),
            }
        })
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }

    fn make_public_tls_config(
        server_name: &str,
    ) -> io::Result<(CertificateDer<'static>, Arc<rustls::ServerConfig>)> {
        let (certificate, private_key) = make_self_signed_cert(server_name)?;
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                private_key_from_der(&private_key),
            )
            .map_err(io::Error::other)?;
        config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
        Ok((certificate, Arc::new(config)))
    }

    fn make_client_tls_config(
        certificate: &CertificateDer<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> io::Result<Arc<rustls::ClientConfig>> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(certificate)?)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        Ok(Arc::new(config))
    }

    fn timeout_error(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, message)
    }

    fn join_error(context: &'static str, error: tokio::task::JoinError) -> io::Error {
        io::Error::other(format!("{context}: {error}"))
    }
}
