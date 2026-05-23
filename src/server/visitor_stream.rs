use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::Connection;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::tunnel_registry::TunnelRegistry;
use crate::acme::ACME_TLS_ALPN;
use crate::client_hello::read_client_hello;
use crate::hostname::validate_public_hostname;
use crate::proxy::proxy_tcp_over_quic;
use crate::runtime_log::{emit_stderr, server_route_line};

#[derive(Clone)]
pub(crate) struct VisitorStreamHandler {
    server_hostname: String,
    tunnel_registry: TunnelRegistry,
    logs: bool,
    public_tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl VisitorStreamHandler {
    pub(crate) fn new(
        server_hostname: String,
        tunnel_registry: TunnelRegistry,
        logs: bool,
        public_tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> io::Result<Self> {
        Ok(Self {
            server_hostname: validate_public_hostname(&server_hostname).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("server.hostname is invalid: {error}"),
                )
            })?,
            tunnel_registry,
            logs,
            public_tls_config,
        })
    }

    pub(crate) async fn handle(&self, mut visitor_stream: TcpStream) -> io::Result<()> {
        let parsed_client_hello = match read_client_hello(&mut visitor_stream).await {
            Ok(parsed_client_hello) => parsed_client_hello,
            Err(_) => return Ok(()),
        };
        let serves_acme_tls_alpn_01 = parsed_client_hello.offers_alpn_protocol(ACME_TLS_ALPN);
        let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();

        if public_hostname == self.server_hostname {
            return if serves_acme_tls_alpn_01 {
                self.serve_acme_tls_alpn_01(visitor_stream, public_hostname, buffered_bytes)
                    .await
            } else {
                emit_stderr(
                    self.logs,
                    &server_route_line(&public_hostname, "dropped (server hostname)"),
                );
                Ok(())
            };
        }

        if !self
            .tunnel_registry
            .contains_public_hostname(&public_hostname)
        {
            emit_stderr(
                self.logs,
                &server_route_line(&public_hostname, "dropped (unauthorized)"),
            );
            return Ok(());
        }

        let Some(tunnel_connection) = self
            .tunnel_registry
            .current_connection(&public_hostname)
            .await
        else {
            emit_stderr(
                self.logs,
                &server_route_line(&public_hostname, "dropped (no active tunnel connection)"),
            );
            return Ok(());
        };

        self.forward_to_tunnel(
            visitor_stream,
            public_hostname,
            buffered_bytes,
            tunnel_connection,
        )
        .await
    }

    async fn serve_acme_tls_alpn_01(
        &self,
        visitor_stream: TcpStream,
        server_hostname: String,
        buffered_bytes: Vec<u8>,
    ) -> io::Result<()> {
        if let Some(public_tls_config) = self.public_tls_config.clone() {
            emit_stderr(
                self.logs,
                &server_route_line(&server_hostname, "acme challenge"),
            );
            let acceptor = TlsAcceptor::from(public_tls_config);
            if let Ok(mut tls_stream) = acceptor
                .accept(PrefixedStream::new(buffered_bytes, visitor_stream))
                .await
            {
                let _ = tls_stream.shutdown().await;
            }
        } else {
            emit_stderr(
                self.logs,
                &server_route_line(&server_hostname, "dropped (server hostname)"),
            );
        }
        Ok(())
    }

    async fn forward_to_tunnel(
        &self,
        visitor_stream: TcpStream,
        public_hostname: String,
        buffered_bytes: Vec<u8>,
        tunnel_connection: Connection,
    ) -> io::Result<()> {
        let (send, recv) = match tunnel_connection.open_bi().await {
            Ok(stream) => stream,
            Err(_) => {
                emit_stderr(
                    self.logs,
                    &server_route_line(&public_hostname, "dropped (no active tunnel connection)"),
                );
                return Ok(());
            }
        };
        emit_stderr(self.logs, &server_route_line(&public_hostname, "forwarded"));

        proxy_tcp_over_quic(visitor_stream, buffered_bytes, send, recv).await
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
    use std::io::Cursor;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use super::*;
    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::ClientConnection;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};
    use tokio_rustls::TlsConnector;

    use crate::acme::ACME_TLS_ALPN;
    use crate::{
        CLIENT_HELLO_BUFFER_LIMIT, GeneratedClientIdentity, ServerTunnelSettings,
        generate_client_identity, make_client_quic_config_with_client_auth,
        make_server_quic_config_with_client_auth,
    };

    #[tokio::test]
    async fn forwards_authorized_public_hostname_through_active_tunnel_connection() {
        let client_identity = generate_client_identity().expect("generate test client identity");
        let registry = TunnelRegistry::configured(
            "Tunnel.Example.Test.",
            &[ServerTunnelSettings {
                public_hostnames: vec!["App.Example.Test.".to_owned()],
                client_identity: client_identity.client_identity.clone(),
            }],
        )
        .unwrap();
        let fixture = TunnelConnectionFixture::connect(&client_identity).await;
        registry.register(fixture.server_connection.clone()).await;
        let router =
            VisitorStreamHandler::new("Tunnel.Example.Test.".to_owned(), registry, false, None)
                .unwrap();

        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let visitor_addr = listener.local_addr().unwrap();
        let router_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await.unwrap();
            router.handle(visitor_stream).await.unwrap();
        });

        let mut visitor = TcpStream::connect(visitor_addr).await.unwrap();
        let client_hello = build_client_hello("app.example.test");
        visitor.write_all(&client_hello).await.unwrap();
        visitor.shutdown().await.unwrap();

        let (mut tunnel_send, mut tunnel_recv) = timeout(
            Duration::from_secs(1),
            fixture.client_connection.accept_bi(),
        )
        .await
        .expect("router should open a tunnel stream")
        .unwrap();
        tunnel_send.finish().unwrap();
        let forwarded = tunnel_recv
            .read_to_end(client_hello.len() + 1)
            .await
            .unwrap();

        assert_eq!(forwarded, client_hello);

        router_task.await.unwrap();
    }

    #[tokio::test]
    async fn serves_acme_tls_for_the_server_hostname() {
        let registry = TunnelRegistry::single(vec!["app.example.test".to_owned()]).unwrap();
        let (certificate, public_tls_config) = make_public_tls_config("tunnel.example.test");
        let router = VisitorStreamHandler::new(
            "Tunnel.Example.Test.".to_owned(),
            registry,
            false,
            Some(public_tls_config),
        )
        .unwrap();

        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let visitor_addr = listener.local_addr().unwrap();
        let router_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await.unwrap();
            router.handle(visitor_stream).await.unwrap();
        });

        let connector = TlsConnector::from(make_client_tls_config(
            &certificate,
            vec![ACME_TLS_ALPN.to_vec()],
        ));
        let visitor_stream = TcpStream::connect(visitor_addr).await.unwrap();
        let tls_stream = connector
            .connect(
                ServerName::try_from("tunnel.example.test".to_owned()).unwrap(),
                visitor_stream,
            )
            .await
            .unwrap();

        drop(tls_stream);
        router_task.await.unwrap();
    }

    #[tokio::test]
    async fn drops_application_traffic_for_the_server_hostname_without_opening_a_tunnel_stream() {
        let (router, tunnel_connection) = configured_router_with_active_tunnel_connection().await;

        assert_drop_without_opening_a_tunnel_stream(
            router,
            build_client_hello("tunnel.example.test"),
            Some(tunnel_connection),
        )
        .await;
    }

    #[tokio::test]
    async fn drops_invalid_tls_without_opening_a_tunnel_stream() {
        let (router, tunnel_connection) = configured_router_with_active_tunnel_connection().await;

        assert_drop_without_opening_a_tunnel_stream(
            router,
            b"not tls".to_vec(),
            Some(tunnel_connection),
        )
        .await;
    }

    #[tokio::test]
    async fn drops_client_hello_without_sni_without_opening_a_tunnel_stream() {
        let (router, tunnel_connection) = configured_router_with_active_tunnel_connection().await;

        assert_drop_without_opening_a_tunnel_stream(
            router,
            build_client_hello_for_server_name(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into())),
            Some(tunnel_connection),
        )
        .await;
    }

    #[tokio::test]
    async fn drops_incomplete_client_hello_without_opening_a_tunnel_stream() {
        let (router, tunnel_connection) = configured_router_with_active_tunnel_connection().await;
        let mut client_hello = build_client_hello("app.example.test");
        client_hello.truncate(10);

        assert_drop_without_opening_a_tunnel_stream(router, client_hello, Some(tunnel_connection))
            .await;
    }

    #[tokio::test]
    async fn drops_oversized_client_hello_without_opening_a_tunnel_stream() {
        let (router, tunnel_connection) = configured_router_with_active_tunnel_connection().await;

        assert_drop_without_opening_a_tunnel_stream(
            router,
            oversized_client_hello(),
            Some(tunnel_connection),
        )
        .await;
    }

    #[tokio::test]
    async fn drops_unauthorized_public_hostname_without_opening_a_tunnel_stream() {
        let client_identity = generate_client_identity().expect("generate test client identity");
        let registry = TunnelRegistry::configured(
            "Tunnel.Example.Test.",
            &[ServerTunnelSettings {
                public_hostnames: vec!["App.Example.Test.".to_owned()],
                client_identity: client_identity.client_identity.clone(),
            }],
        )
        .unwrap();
        let fixture = TunnelConnectionFixture::connect(&client_identity).await;
        registry.register(fixture.server_connection.clone()).await;
        let router =
            VisitorStreamHandler::new("Tunnel.Example.Test.".to_owned(), registry, false, None)
                .unwrap();

        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let visitor_addr = listener.local_addr().unwrap();
        let router_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await.unwrap();
            router.handle(visitor_stream).await.unwrap();
        });

        let mut visitor = TcpStream::connect(visitor_addr).await.unwrap();
        let client_hello = build_client_hello("api.example.test");
        visitor.write_all(&client_hello).await.unwrap();
        visitor.shutdown().await.unwrap();

        let open_stream = timeout(
            Duration::from_millis(200),
            fixture.client_connection.accept_bi(),
        )
        .await;
        assert!(
            open_stream.is_err(),
            "router unexpectedly opened a tunnel stream"
        );

        let mut read_buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut read_buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);

        router_task.await.unwrap();
    }

    #[tokio::test]
    async fn drops_public_hostname_when_the_tunnel_has_no_active_connection() {
        let registry = TunnelRegistry::single(vec!["app.example.test".to_owned()]).unwrap();
        let router =
            VisitorStreamHandler::new("tunnel.example.test".to_owned(), registry, false, None)
                .unwrap();

        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let visitor_addr = listener.local_addr().unwrap();
        let router_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await.unwrap();
            router.handle(visitor_stream).await.unwrap();
        });

        let mut visitor = TcpStream::connect(visitor_addr).await.unwrap();
        let client_hello = build_client_hello("app.example.test");
        visitor.write_all(&client_hello).await.unwrap();
        visitor.shutdown().await.unwrap();

        let mut read_buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut read_buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);

        router_task.await.unwrap();
    }

    #[tokio::test]
    async fn drops_public_hostname_cleanly_after_the_active_tunnel_connection_closes() {
        let client_identity = generate_client_identity().expect("generate test client identity");
        let registry = TunnelRegistry::configured(
            "Tunnel.Example.Test.",
            &[ServerTunnelSettings {
                public_hostnames: vec!["App.Example.Test.".to_owned()],
                client_identity: client_identity.client_identity.clone(),
            }],
        )
        .unwrap();
        let fixture = TunnelConnectionFixture::connect(&client_identity).await;
        registry.register(fixture.server_connection.clone()).await;
        fixture
            .server_connection
            .close(0_u32.into(), b"closed before visitor handling");
        let router =
            VisitorStreamHandler::new("Tunnel.Example.Test.".to_owned(), registry, false, None)
                .unwrap();

        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let visitor_addr = listener.local_addr().unwrap();
        let router_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await.unwrap();
            router.handle(visitor_stream).await.unwrap();
        });

        let mut visitor = TcpStream::connect(visitor_addr).await.unwrap();
        let client_hello = build_client_hello("app.example.test");
        visitor.write_all(&client_hello).await.unwrap();
        visitor.shutdown().await.unwrap();

        let mut read_buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut read_buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);

        router_task.await.unwrap();
    }

    async fn configured_router_with_active_tunnel_connection() -> (VisitorStreamHandler, Connection)
    {
        let client_identity = generate_client_identity().expect("generate test client identity");
        let registry = TunnelRegistry::configured(
            "Tunnel.Example.Test.",
            &[ServerTunnelSettings {
                public_hostnames: vec!["App.Example.Test.".to_owned()],
                client_identity: client_identity.client_identity.clone(),
            }],
        )
        .unwrap();
        let fixture = TunnelConnectionFixture::connect(&client_identity).await;
        registry.register(fixture.server_connection.clone()).await;
        let router =
            VisitorStreamHandler::new("Tunnel.Example.Test.".to_owned(), registry, false, None)
                .unwrap();

        (router, fixture.client_connection)
    }

    async fn assert_drop_without_opening_a_tunnel_stream(
        router: VisitorStreamHandler,
        visitor_bytes: Vec<u8>,
        tunnel_connection: Option<Connection>,
    ) {
        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let visitor_addr = listener.local_addr().unwrap();
        let router_task = tokio::spawn(async move {
            let (visitor_stream, _) = listener.accept().await.unwrap();
            router.handle(visitor_stream).await.unwrap();
        });

        let mut visitor = TcpStream::connect(visitor_addr).await.unwrap();
        visitor.write_all(&visitor_bytes).await.unwrap();
        visitor.shutdown().await.unwrap();

        if let Some(tunnel_connection) = tunnel_connection {
            let open_stream =
                timeout(Duration::from_millis(200), tunnel_connection.accept_bi()).await;
            assert!(
                open_stream.is_err(),
                "router unexpectedly opened a tunnel stream"
            );
        }

        let mut read_buffer = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), visitor.read(&mut read_buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);

        router_task.await.unwrap();
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        client_connection: Connection,
        server_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect(client_identity: &GeneratedClientIdentity) -> Self {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test");
            let server_endpoint = Endpoint::server(
                make_server_quic_config_with_client_auth(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                    std::slice::from_ref(&client_identity.client_identity),
                )
                .unwrap(),
                localhost(0),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();

            let mut client_endpoint = Endpoint::client(localhost(0)).unwrap();
            client_endpoint.set_default_client_config(
                make_client_quic_config_with_client_auth(
                    root_store_with(&certificate),
                    client_certificate_chain(client_identity),
                    client_private_key(client_identity),
                )
                .unwrap(),
            );

            let accept_connection = async {
                let incoming = server_endpoint.accept().await.unwrap();
                incoming.await.unwrap()
            };
            let connect_client = async {
                client_endpoint
                    .connect(server_addr, "tunnel.example.test")
                    .unwrap()
                    .await
                    .unwrap()
            };
            let (server_connection, client_connection) =
                tokio::join!(accept_connection, connect_client);

            Self {
                _server_endpoint: server_endpoint,
                _client_endpoint: client_endpoint,
                client_connection,
                server_connection,
            }
        }
    }

    fn build_client_hello(server_name: &str) -> Vec<u8> {
        build_client_hello_for_server_name(ServerName::try_from(server_name.to_owned()).unwrap())
    }

    fn build_client_hello_for_server_name(server_name: ServerName<'static>) -> Vec<u8> {
        let trusted_cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut connection = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).unwrap();
        bytes
    }

    fn oversized_client_hello() -> Vec<u8> {
        let mut oversized = vec![0x16, 0x03, 0x03, 0x40, 0x01];
        oversized.extend(std::iter::repeat_n(0_u8, CLIENT_HELLO_BUFFER_LIMIT));
        oversized
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn make_self_signed_cert(server_name: &str) -> (CertificateDer<'static>, Vec<u8>) {
        let certified_key = generate_simple_self_signed(vec![server_name.to_owned()]).unwrap();
        (
            CertificateDer::from(certified_key.cert),
            certified_key.signing_key.serialize_der(),
        )
    }

    fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn client_certificate_chain(
        client_identity: &GeneratedClientIdentity,
    ) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut Cursor::new(client_identity.certificate_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn client_private_key(client_identity: &GeneratedClientIdentity) -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut Cursor::new(client_identity.private_key_pem.as_bytes()))
            .unwrap()
            .unwrap()
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        roots
    }

    fn make_public_tls_config(
        server_name: &str,
    ) -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
        let (certificate, private_key) = make_self_signed_cert(server_name);
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                private_key_from_der(&private_key),
            )
            .unwrap();
        config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
        (certificate, Arc::new(config))
    }

    fn make_client_tls_config(
        certificate: &CertificateDer<'static>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Arc<rustls::ClientConfig> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(certificate))
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        Arc::new(config)
    }
}
