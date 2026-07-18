use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::admission::{AdmissionLimit, ServerAdmissionPolicy, VisitorAdmissionPermit};
use super::tunnel_registry::{TunnelRegistry, TunnelRouteOutcome};
use crate::acme::ACME_TLS_ALPN;
use crate::client_hello::ParsedClientHello;
use crate::client_hello::read_client_hello;
use crate::proxy::{proxy_stream_error_code, proxy_tcp_over_quic};
use crate::proxy_protocol::read_proxy_v2;
use crate::runtime_log;
use crate::runtime_log::{AcmeEvent, AcmeRole, ServerRouteOutcome};
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
        })
    }

    pub(crate) fn accept(
        &self,
        visitor_stream: TcpStream,
        shutdown: Option<crate::shutdown::OrderlyShutdown>,
    ) {
        let permit = match self.admission_policy.try_admit_visitor_global() {
            Ok(permit) => permit,
            Err(rejection) => {
                drop(visitor_stream);
                self.admission_policy.report_saturation(rejection);
                return;
            }
        };
        self.admission_policy.report_recovery(&[
            AdmissionLimit::VisitorsGlobal,
            AdmissionLimit::VisitorSource,
        ]);
        let intake = self.clone();
        let timeout = self.admission_policy.limits().client_hello_timeout;
        tokio::spawn(async move {
            match shutdown {
                Some(shutdown) => {
                    let _ = intake
                        .intake_until(visitor_stream, timeout, permit, async move {
                            let _ = shutdown.wait_started().await;
                        })
                        .await;
                }
                None => {
                    let _ = intake
                        .intake_until(visitor_stream, timeout, permit, std::future::pending())
                        .await;
                }
            }
        });
    }

    async fn intake_until<Shutdown>(
        &self,
        mut visitor_stream: TcpStream,
        timeout: std::time::Duration,
        mut admission_permit: VisitorAdmissionPermit,
        shutdown: Shutdown,
    ) -> io::Result<()>
    where
        Shutdown: std::future::Future<Output = ()>,
    {
        let direct_addresses = VisitorTcpAddresses::from_socket(&visitor_stream)?;
        let peer_ip = direct_addresses.source.ip();
        let parsed_client_hello = tokio::select! {
            parsed = tokio::time::timeout(timeout, async {
                let addresses = if self.visitor_proxy_protocol.is_some() {
                    if !self.visitor_proxy_trusted_networks.iter().any(|network| network.contains(peer_ip)) {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "visitor PROXY protocol peer is not trusted"));
                    }
                    read_proxy_v2(&mut visitor_stream).await.map_err(io::Error::other)?
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
                    return Ok(None);
                }
                let hello = read_client_hello(&mut visitor_stream)
                    .await
                    .map_err(io::Error::other)?;
                Ok::<_, io::Error>(Some((hello, addresses)))
            }) => match parsed {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Visitor pre-routing intake timed out")),
            },
            _ = shutdown => return Ok(()),
        };
        // Pre-routing capacity protects ClientHello completion only. Existing routed
        // Visitor traffic must remain independent from admission saturation.
        drop(admission_permit);
        let (parsed_client_hello, addresses) = match parsed_client_hello {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(()),
            Err(error) => {
                runtime_log::warning("server", &format!("rejected Visitor stream: {error}"));
                return Ok(());
            }
        };
        self.handle_parsed(visitor_stream, parsed_client_hello, addresses)
            .await
    }

    async fn handle_parsed(
        &self,
        visitor_stream: TcpStream,
        parsed_client_hello: ParsedClientHello,
        addresses: VisitorTcpAddresses,
    ) -> io::Result<()> {
        let serves_acme_tls_alpn_01 = parsed_client_hello.offers_alpn_protocol(ACME_TLS_ALPN);
        let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();

        if public_hostname.as_str() == self.server_hostname.as_str() {
            return if serves_acme_tls_alpn_01 {
                self.serve_acme_tls_alpn_01(visitor_stream, public_hostname, buffered_bytes)
                    .await
            } else {
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::RejectedServerHostname,
                );
                Ok(())
            };
        }

        let selected_tunnel_connection = match self
            .tunnel_registry
            .route_tunnel_connection(&public_hostname)
            .await
        {
            TunnelRouteOutcome::Unauthorized => {
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::RejectedUnauthorized,
                );
                return Ok(());
            }
            TunnelRouteOutcome::NoActiveTunnelConnection => {
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::NoActiveTunnelConnection,
                );
                return Ok(());
            }
            TunnelRouteOutcome::Connected(tunnel_connection) => tunnel_connection,
        };

        self.forward_to_tunnel(
            visitor_stream,
            public_hostname,
            buffered_bytes,
            selected_tunnel_connection,
            addresses,
        )
        .await
    }

    async fn serve_acme_tls_alpn_01(
        &self,
        visitor_stream: TcpStream,
        server_hostname: PublicHostname,
        buffered_bytes: Vec<u8>,
    ) -> io::Result<()> {
        if let Some(public_tls_config) = self.public_tls_config.clone() {
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
        }
        Ok(())
    }

    async fn forward_to_tunnel(
        &self,
        visitor_stream: TcpStream,
        public_hostname: PublicHostname,
        buffered_bytes: Vec<u8>,
        tunnel_connection: super::active_client::SelectedTunnelConnection,
        addresses: VisitorTcpAddresses,
    ) -> io::Result<()> {
        let pending_open_permit = match self.admission_policy.try_admit_pending_stream_open() {
            Ok(permit) => permit,
            Err(rejection) => {
                self.admission_policy.report_saturation(rejection);
                return Ok(());
            }
        };
        self.admission_policy
            .report_recovery(&[AdmissionLimit::PendingStreamOpens]);

        let open_bi_timeout = self.admission_policy.limits().open_bi_timeout;
        let open_result =
            tokio::time::timeout(open_bi_timeout, tunnel_connection.connection().open_bi()).await;
        let (mut send, mut recv) = match open_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) | Err(_) => {
                drop(pending_open_permit);
                runtime_log::server_route(
                    public_hostname.as_str(),
                    ServerRouteOutcome::NoActiveTunnelConnection,
                );
                return Ok(());
            }
        };

        let active_stream_permit = match self.admission_policy.try_admit_active_routed_stream() {
            Ok(permit) => permit,
            Err(rejection) => {
                drop(pending_open_permit);
                let _ = send.reset(proxy_stream_error_code());
                let _ = recv.stop(proxy_stream_error_code());
                self.admission_policy.report_saturation(rejection);
                return Ok(());
            }
        };
        drop(pending_open_permit);
        self.admission_policy
            .report_recovery(&[AdmissionLimit::ActiveRoutedStreams]);

        let active_stream_guard = tunnel_connection.record_open_stream();
        runtime_log::server_route(public_hostname.as_str(), ServerRouteOutcome::Forwarded);

        let member_id = tunnel_connection.member_id();
        let client_identity = tunnel_connection.client_identity().clone();
        let registry = self.tunnel_registry.clone();
        let tracked_hostname = public_hostname.clone();
        let proxy_task = tokio::spawn(async move {
            let _active_stream_guard = active_stream_guard;
            let _active_stream_permit = active_stream_permit;
            let mut initial_bytes = addresses.encode_proxy_v2();
            initial_bytes.extend_from_slice(&buffered_bytes);
            proxy_tcp_over_quic(visitor_stream, initial_bytes, send, recv).await
        });
        // Track synchronously before the next await so commit-time revocation cannot miss
        // a stream that has already been admitted.
        let stream_id = registry.track_visitor_stream(
            tracked_hostname,
            member_id,
            client_identity,
            proxy_task.abort_handle(),
        );
        let proxy_result = match proxy_task.await {
            Ok(result) => result,
            Err(join_error) if join_error.is_cancelled() => Ok(()),
            Err(join_error) => Err(io::Error::other(format!(
                "visitor stream proxy task failed: {join_error}"
            ))),
        };
        registry.untrack_visitor_stream(stream_id);
        proxy_result
    }
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
    use quinn::{Connection, Endpoint};
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
    use crate::server::admission::{AdmissionLimit, ServerAdmissionLimits, ServerAdmissionPolicy};
    use crate::tls_material::{certificate_chain_from_pem, private_key_from_pem};
    use crate::{
        CLIENT_HELLO_BUFFER_LIMIT, GeneratedClientIdentity, PublicHostname, ServerHostname,
        ServerTunnelConfig, generate_client_identity, make_client_quic_config_with_client_auth,
        make_server_quic_config_with_client_auth,
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
        let _ = crate::runtime_log::install(level);
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
            fixture.client_connection.accept_bi(),
        )
        .await
        .map_err(|_| timeout_error("intake should open a tunnel stream"))?
        .map_err(io::Error::other)?;
        let addresses = crate::proxy_protocol::read_proxy_v2(&mut tunnel_recv)
            .await
            .map_err(io::Error::other)?;
        assert_eq!(addresses.source, visitor_source);
        assert_eq!(addresses.destination, visitor_addr);
        tunnel_send.finish().map_err(io::Error::other)?;
        let forwarded = timeout(
            Duration::from_secs(1),
            tunnel_recv.read_to_end(client_hello.len() + 1),
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

        let (_send, mut recv) = timeout(Duration::from_secs(1), tunnel_connection.accept_bi())
            .await
            .map_err(|_| timeout_error("strict PROXY Visitor should reach the Tunnel"))?
            .map_err(io::Error::other)?;
        let forwarded_addresses = crate::proxy_protocol::read_proxy_v2(&mut recv)
            .await
            .map_err(io::Error::other)?;
        assert_eq!(forwarded_addresses, addresses);
        let forwarded_tls = timeout(
            Duration::from_secs(1),
            recv.read_to_end(client_hello.len() + 1),
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
        let (send, recv) = timeout(Duration::from_secs(1), tunnel_connection.accept_bi())
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
            fixture.client_connection.accept_bi(),
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
            fixture.client_connection.accept_bi(),
        )
        .await
        .map_err(|_| timeout_error("recovery visitor should open a tunnel stream"))?
        .map_err(io::Error::other)?;
        crate::proxy_protocol::read_proxy_v2(&mut recv)
            .await
            .map_err(io::Error::other)?;
        let recovered_bytes = timeout(
            Duration::from_secs(1),
            recv.read_to_end(client_hello.len() + 1),
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
            fixture.client_connection.accept_bi(),
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
            fixture.client_connection.accept_bi(),
        )
        .await;

        intake_task
            .await
            .map_err(|error| join_error("intake task failed", error))??;
        assert_eq!(registry.tracked_visitor_stream_count(), 0);

        drop(held_active);
        assert!(policy.try_admit_active_routed_stream().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn open_bi_deadline_releases_pending_capacity_when_stream_credit_is_exhausted()
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
        let fixture =
            TunnelConnectionFixture::connect_with_bidi_credit(&client_identity, 1).await?;
        registry.register(fixture.server_connection.clone()).await;
        let policy = ServerAdmissionPolicy::new(ServerAdmissionLimits {
            open_bi_timeout: Duration::from_millis(50),
            max_pending_stream_opens: 1,
            ..ServerAdmissionLimits::for_test()
        });
        let intake = VisitorIntake::new(
            server_hostname("Tunnel.Example.Test."),
            registry,
            None,
            policy.clone(),
        )?;

        // Consume the only advertised stream credit and leave it open.
        let (_held_send, _held_recv) =
            timeout(Duration::from_secs(1), fixture.server_connection.open_bi())
                .await
                .map_err(|_| timeout_error("first open_bi should succeed"))?
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
            "open_bi timeout must release pending-open capacity"
        );
        Ok(())
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
        Ok(())
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
        Ok(())
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
        )
        .await
    }

    #[tokio::test]
    async fn drops_incomplete_client_hello_without_opening_a_tunnel_stream() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;
        let mut client_hello = build_client_hello("app.example.test")?;
        client_hello.truncate(10);

        assert_drop_without_opening_a_tunnel_stream(intake, client_hello, Some(tunnel_connection))
            .await
    }

    #[tokio::test]
    async fn drops_oversized_client_hello_without_opening_a_tunnel_stream() -> io::Result<()> {
        let (intake, tunnel_connection) = configured_intake_with_active_tunnel_connection().await?;

        assert_drop_without_opening_a_tunnel_stream(
            intake,
            oversized_client_hello(),
            Some(tunnel_connection),
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
            .close(0_u32.into(), b"closed before visitor handling");
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
        )
        .await
    }

    async fn configured_intake_with_active_tunnel_connection()
    -> io::Result<(VisitorIntake, Connection)> {
        configured_intake_with_active_tunnel_connection_and_policy(test_admission_policy()).await
    }

    async fn configured_intake_with_active_tunnel_connection_and_policy(
        policy: ServerAdmissionPolicy,
    ) -> io::Result<(VisitorIntake, Connection)> {
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
    ) -> io::Result<(VisitorIntake, Connection)> {
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
        tunnel_connection: Connection,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&visitor_bytes).await?;
        visitor.shutdown().await?;

        match timeout(Duration::from_millis(100), tunnel_connection.accept_bi()).await {
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
        Ok(())
    }

    async fn assert_drop_without_opening_a_tunnel_stream(
        intake: VisitorIntake,
        visitor_bytes: Vec<u8>,
        tunnel_connection: Option<Connection>,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(localhost(0)).await?;
        let visitor_addr = listener.local_addr()?;
        let intake_task = spawn_intake_task(listener, intake);

        let mut visitor = TcpStream::connect(visitor_addr).await?;
        visitor.write_all(&visitor_bytes).await?;
        visitor.shutdown().await?;

        if let Some(tunnel_connection) = tunnel_connection {
            match timeout(Duration::from_millis(200), tunnel_connection.accept_bi()).await {
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
        client_connection: Connection,
        server_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect(client_identity: &GeneratedClientIdentity) -> io::Result<Self> {
            Self::connect_with_bidi_credit(client_identity, crate::MAX_SERVER_OPENED_BIDI_STREAMS)
                .await
        }

        async fn connect_with_bidi_credit(
            client_identity: &GeneratedClientIdentity,
            max_bidi_streams: u32,
        ) -> io::Result<Self> {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
            let server_endpoint = Endpoint::server(
                make_server_quic_config_with_client_auth(
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
            let mut client_config = make_client_quic_config_with_client_auth(
                root_store_with(&certificate)?,
                client_certificate_chain(client_identity)?,
                client_private_key(client_identity)?,
            )
            .map_err(io::Error::other)?;
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_bidi_streams(max_bidi_streams.into());
            transport.max_concurrent_uni_streams(0_u8.into());
            client_config.transport_config(Arc::new(transport));
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
        let trusted_cert =
            generate_simple_self_signed(vec!["localhost".to_owned()]).map_err(io::Error::other)?;
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).map_err(io::Error::other)?;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
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
