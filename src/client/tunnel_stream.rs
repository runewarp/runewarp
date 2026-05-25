use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::client_hello::read_client_hello;
use crate::runtime_log::{client_route_line, emit_stderr, warning_line};
use crate::{ClientServiceSettings, ClientTlsMode, proxy::proxy_stream_error_code, proxy::proxy_tcp_over_quic};

#[derive(Clone)]
pub(crate) struct TunnelConnectionStreamHandler {
    services: Arc<[ClientServiceSettings]>,
    logs: bool,
    hostname_tls_configs: Arc<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl TunnelConnectionStreamHandler {
    pub(crate) fn new(
        services: Vec<ClientServiceSettings>,
        logs: bool,
        hostname_tls_configs: HashMap<String, Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self {
            services: services.into(),
            logs,
            hostname_tls_configs: Arc::new(hostname_tls_configs),
        }
    }

    pub(crate) async fn handle(&self, send: SendStream, mut recv: RecvStream) -> io::Result<()> {
        let parsed_client_hello = match read_client_hello(&mut recv).await {
            Ok(parsed_client_hello) => parsed_client_hello,
            Err(error) => {
                emit_stderr(
                    self.logs,
                    &warning_line("client", &format!("rejected stream: {error}")),
                );
                reject_stream(send, recv);
                return Err(io::Error::other(error));
            }
        };
        let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();
        let Some(service) = self.select_service(&public_hostname) else {
            emit_stderr(
                self.logs,
                &client_route_line(&public_hostname, "rejected (no matching service)"),
            );
            reject_stream(send, recv);
            return Ok(());
        };

        if service.tls_mode == ClientTlsMode::Terminate {
            return self
                .handle_terminate(send, recv, &public_hostname, buffered_bytes, service)
                .await;
        }

        let mut backend_stream = match TcpStream::connect(service.backend_address.as_str()).await {
            Ok(stream) => stream,
            Err(error) => {
                emit_stderr(
                    self.logs,
                    &backend_connect_failed_route_line(&public_hostname),
                );
                reject_stream(send, recv);
                return Err(error);
            }
        };
        if let Err(error) = backend_stream.write_all(&buffered_bytes).await {
            emit_stderr(
                self.logs,
                &backend_write_failed_route_line(&public_hostname),
            );
            reject_stream(send, recv);
            return Err(error);
        }
        emit_stderr(self.logs, &forwarded_route_line(&public_hostname));

        proxy_tcp_over_quic(backend_stream, Vec::new(), send, recv).await
    }

    async fn handle_terminate(
        &self,
        send: SendStream,
        recv: RecvStream,
        public_hostname: &str,
        buffered_bytes: Vec<u8>,
        service: &ClientServiceSettings,
    ) -> io::Result<()> {
        let Some(tls_config) = self.hostname_tls_configs.get(public_hostname) else {
            emit_stderr(
                self.logs,
                &warning_line(
                    "client",
                    &format!("no TLS config for terminating hostname {public_hostname}"),
                ),
            );
            let mut s = send;
            let mut r = recv;
            let _ = s.reset(proxy_stream_error_code());
            let _ = r.stop(proxy_stream_error_code());
            return Err(io::Error::other(format!(
                "no TLS config for {public_hostname}"
            )));
        };

        let acceptor = TlsAcceptor::from(tls_config.clone());
        // Replay the buffered ClientHello bytes back into the stream so TlsAcceptor can
        // complete the handshake from the beginning of the TLS record stream.
        let quic_stream = ReplayedQuicBiStream::new(send, recv, buffered_bytes);
        let mut tls_stream = match acceptor.accept(quic_stream).await {
            Ok(stream) => stream,
            Err(error) => {
                return Err(io::Error::other(format!(
                    "TLS termination handshake failed for {public_hostname}: {error}"
                )));
            }
        };

        let mut backend_stream = match TcpStream::connect(service.backend_address.as_str()).await {
            Ok(stream) => stream,
            Err(error) => {
                emit_stderr(
                    self.logs,
                    &backend_connect_failed_route_line(public_hostname),
                );
                return Err(error);
            }
        };

        emit_stderr(
            self.logs,
            &client_route_line(public_hostname, "terminated and forwarded"),
        );

        copy_bidirectional(&mut tls_stream, &mut backend_stream)
            .await
            .map(|_| ())
    }

    fn select_service(&self, public_hostname: &str) -> Option<&ClientServiceSettings> {
        if let [service] = &*self.services
            && service.public_hostnames.is_none()
        {
            return Some(service);
        }

        self.services.iter().find(|service| {
            service.public_hostnames.as_ref().is_some_and(|hostnames| {
                hostnames.iter().any(|hostname| hostname == public_hostname)
            })
        })
    }
}

/// A bidirectional QUIC stream that replays `buffered_bytes` before reading from `recv`.
/// Used to feed back a partially-consumed TLS ClientHello to `TlsAcceptor`.
struct ReplayedQuicBiStream {
    send: SendStream,
    recv: RecvStream,
    buffered_bytes: Vec<u8>,
    replay_offset: usize,
}

impl ReplayedQuicBiStream {
    fn new(send: SendStream, recv: RecvStream, buffered_bytes: Vec<u8>) -> Self {
        Self {
            send,
            recv,
            buffered_bytes,
            replay_offset: 0,
        }
    }
}

impl AsyncRead for ReplayedQuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.replay_offset < self.buffered_bytes.len() {
            let remaining = &self.buffered_bytes[self.replay_offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.replay_offset += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayedQuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map(|result| result.map_err(io::Error::other))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map(|result| result.map_err(io::Error::other))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map(|result| result.map_err(io::Error::other))
    }
}

fn reject_stream(mut send: SendStream, mut recv: RecvStream) {
    let _ = send.reset(proxy_stream_error_code());
    let _ = recv.stop(proxy_stream_error_code());
}

fn backend_connect_failed_route_line(public_hostname: &str) -> String {
    client_route_line(public_hostname, "backend connect failed")
}

fn backend_write_failed_route_line(public_hostname: &str) -> String {
    client_route_line(public_hostname, "backend write failed")
}

fn forwarded_route_line(public_hostname: &str) -> String {
    client_route_line(public_hostname, "forwarded")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use quinn::{Connection, Endpoint, RecvStream, SendStream};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConnection, RootCertStore};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::TunnelConnectionStreamHandler;
    use crate::{ClientServiceSettings, ClientTlsMode, make_client_quic_config, make_server_quic_config};

    #[tokio::test]
    async fn forwards_streams_for_exact_match_services() -> io::Result<()> {
        assert_forwarded_stream(
            vec![
                ClientServiceSettings {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    backend_address: "127.0.0.1:443".to_owned(),
                    tls_mode: ClientTlsMode::Passthrough,
                },
                ClientServiceSettings {
                    public_hostnames: Some(vec!["api.example.test".to_owned()]),
                    backend_address: backend_placeholder(),
                    tls_mode: ClientTlsMode::Passthrough,
                },
            ],
            "api.example.test",
        )
        .await
    }

    #[tokio::test]
    async fn forwards_streams_for_the_catch_all_service() -> io::Result<()> {
        assert_forwarded_stream(
            vec![ClientServiceSettings {
                public_hostnames: None,
                backend_address: backend_placeholder(),
                tls_mode: ClientTlsMode::Passthrough,
            }],
            "app.example.test",
        )
        .await
    }

    #[tokio::test]
    async fn rejects_streams_without_a_matching_service() -> io::Result<()> {
        assert_rejected_stream(
            vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:443".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            }],
            "api.example.test",
            |result: io::Result<()>| assert!(result.is_ok()),
        )
        .await
    }

    #[tokio::test]
    async fn rejects_streams_when_backend_connect_fails() -> io::Result<()> {
        let backend_address = unused_localhost_address().await?.to_string();

        assert_rejected_stream(
            vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address,
                tls_mode: ClientTlsMode::Passthrough,
            }],
            "app.example.test",
            |result: io::Result<()>| assert!(result.is_err()),
        )
        .await
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn rejects_streams_when_backend_write_fails() -> io::Result<()> {
        let backend_listener = TcpListener::bind(localhost(0)).await?;
        let backend_address = backend_listener.local_addr()?.to_string();
        let reset_backend_task = tokio::spawn(async move {
            let (backend_stream, _) = timeout(Duration::from_secs(1), backend_listener.accept())
                .await
                .map_err(|_| timeout_error("backend should accept a connection"))??;
            backend_stream.set_linger(Some(Duration::ZERO))?;
            drop(backend_stream);
            Ok::<(), io::Error>(())
        });

        assert_rejected_stream(
            vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address,
                tls_mode: ClientTlsMode::Passthrough,
            }],
            "app.example.test",
            |result: io::Result<()>| assert!(result.is_err()),
        )
        .await?;

        reset_backend_task
            .await
            .map_err(|error| join_error("backend reset task failed", error))??;
        Ok(())
    }

    async fn assert_forwarded_stream(
        mut services: Vec<ClientServiceSettings>,
        requested_hostname: &str,
    ) -> io::Result<()> {
        let (backend_cert, backend_key) = make_self_signed_cert(requested_hostname)?;
        let (backend_address, backend_task) = spawn_tls_backend(
            private_key_from_der(&backend_key),
            backend_cert.clone(),
            *b"pong",
        )
        .await?;
        for service in &mut services {
            if service.backend_address == backend_placeholder() {
                service.backend_address = backend_address.clone();
            }
        }

        let stream_handler = TunnelConnectionStreamHandler::new(services, false, HashMap::new());
        let fixture = TunnelConnectionFixture::connect().await?;
        let server_connection = fixture.server_connection.clone();
        let client_connection = fixture.client_connection.clone();

        let stream_handler_task = tokio::spawn(async move {
            let (send, recv) = timeout(Duration::from_secs(1), client_connection.accept_bi())
                .await
                .map_err(|_| timeout_error("handler should accept a tunnel stream"))?
                .map_err(io::Error::other)?;
            stream_handler.handle(send, recv).await
        });

        let response =
            request_tls_response_over_tunnel(server_connection, &backend_cert, requested_hostname)
                .await?;
        assert_eq!(response, *b"pong");

        backend_task
            .await
            .map_err(|error| join_error("backend task failed", error))??;
        stream_handler_task
            .await
            .map_err(|error| join_error("stream handler task failed", error))??;
        Ok(())
    }

    async fn assert_rejected_stream(
        services: Vec<ClientServiceSettings>,
        requested_hostname: &str,
        assert_handler_result: impl FnOnce(io::Result<()>) + Send + 'static,
    ) -> io::Result<()> {
        let stream_handler = TunnelConnectionStreamHandler::new(services, false, HashMap::new());
        let fixture = TunnelConnectionFixture::connect().await?;
        let server_connection = fixture.server_connection.clone();
        let client_connection = fixture.client_connection.clone();
        let client_hello = build_client_hello(requested_hostname)?;

        let stream_handler_task = tokio::spawn(async move {
            let (send, recv) = timeout(Duration::from_secs(1), client_connection.accept_bi())
                .await
                .map_err(|_| timeout_error("handler should accept a tunnel stream"))?
                .map_err(io::Error::other)?;
            assert_handler_result(stream_handler.handle(send, recv).await);
            Ok::<(), io::Error>(())
        });

        let (mut tunnel_send, mut tunnel_recv) =
            timeout(Duration::from_secs(1), server_connection.open_bi())
                .await
                .map_err(|_| timeout_error("test should open a tunnel stream"))?
                .map_err(io::Error::other)?;
        tunnel_send.write_all(&client_hello).await?;
        tunnel_send.finish().map_err(io::Error::other)?;

        if let Ok(Ok(response)) = timeout(Duration::from_secs(1), tunnel_recv.read_to_end(1)).await
        {
            assert!(response.is_empty());
        }

        stream_handler_task
            .await
            .map_err(|error| join_error("stream handler task failed", error))??;
        Ok(())
    }

    async fn spawn_tls_backend(
        private_key: PrivateKeyDer<'static>,
        certificate: CertificateDer<'static>,
        response: [u8; 4],
    ) -> io::Result<(String, JoinHandle<io::Result<()>>)> {
        let listener = TcpListener::bind(localhost(0)).await?;
        let address = listener.local_addr()?.to_string();
        let acceptor = TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)
                .map_err(io::Error::other)?,
        ));

        let task = tokio::spawn(async move {
            let (tcp_stream, _) = timeout(Duration::from_secs(1), listener.accept())
                .await
                .map_err(|_| timeout_error("backend should accept a forwarded connection"))??;
            let mut tls_stream = timeout(Duration::from_secs(1), acceptor.accept(tcp_stream))
                .await
                .map_err(|_| timeout_error("backend TLS handshake should complete"))?
                .map_err(io::Error::other)?;
            let mut request = [0_u8; 4];
            timeout(Duration::from_secs(1), tls_stream.read_exact(&mut request))
                .await
                .map_err(|_| timeout_error("backend should receive request bytes"))??;
            assert_eq!(&request, b"ping");
            timeout(Duration::from_secs(1), tls_stream.write_all(&response))
                .await
                .map_err(|_| timeout_error("backend should send response bytes"))??;
            timeout(Duration::from_secs(1), tls_stream.shutdown())
                .await
                .map_err(|_| timeout_error("backend should close cleanly"))??;
            Ok(())
        });

        Ok((address, task))
    }

    async fn request_tls_response_over_tunnel(
        server_connection: Connection,
        backend_cert: &CertificateDer<'static>,
        requested_hostname: &str,
    ) -> io::Result<[u8; 4]> {
        let (send, recv) = timeout(Duration::from_secs(1), server_connection.open_bi())
            .await
            .map_err(|_| timeout_error("test should open a tunnel stream"))?
            .map_err(io::Error::other)?;
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store_with(backend_cert)?)
                .with_no_client_auth(),
        ));
        let server_name =
            ServerName::try_from(requested_hostname.to_owned()).map_err(io::Error::other)?;
        let mut tls_stream = timeout(
            Duration::from_secs(1),
            connector.connect(server_name, QuicBiStream::new(send, recv)),
        )
        .await
        .map_err(|_| timeout_error("TLS handshake over the tunnel should complete"))?
        .map_err(io::Error::other)?;
        timeout(Duration::from_secs(1), tls_stream.write_all(b"ping"))
            .await
            .map_err(|_| timeout_error("TLS client should send request bytes"))??;

        let mut response = [0_u8; 4];
        timeout(Duration::from_secs(1), tls_stream.read_exact(&mut response))
            .await
            .map_err(|_| timeout_error("TLS client should receive response bytes"))??;
        timeout(Duration::from_secs(1), tls_stream.shutdown())
            .await
            .map_err(|_| timeout_error("TLS client should close cleanly"))??;

        Ok(response)
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        server_connection: Connection,
        client_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect() -> io::Result<Self> {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
            let server_endpoint = Endpoint::server(
                make_server_quic_config(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                )
                .map_err(io::Error::other)?,
                localhost(0),
            )
            .map_err(io::Error::other)?;
            let server_addr = server_endpoint.local_addr()?;

            let mut client_endpoint = Endpoint::client(localhost(0)).map_err(io::Error::other)?;
            client_endpoint.set_default_client_config(
                make_client_quic_config(root_store_with(&certificate)?)
                    .map_err(io::Error::other)?,
            );

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
                server_connection,
                client_connection,
            })
        }
    }

    fn backend_placeholder() -> String {
        "__backend__".to_owned()
    }

    async fn unused_localhost_address() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(localhost(0)).await?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    }

    fn build_client_hello(server_name: &str) -> io::Result<Vec<u8>> {
        let trusted_cert =
            generate_simple_self_signed(vec!["localhost".to_owned()]).map_err(io::Error::other)?;
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).map_err(io::Error::other)?;

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes)?;
        Ok(bytes)
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

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }

    fn timeout_error(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, message)
    }

    fn join_error(context: &'static str, error: tokio::task::JoinError) -> io::Error {
        io::Error::other(format!("{context}: {error}"))
    }

    struct QuicBiStream {
        send: SendStream,
        recv: RecvStream,
    }

    impl QuicBiStream {
        fn new(send: SendStream, recv: RecvStream) -> Self {
            Self { send, recv }
        }
    }

    impl AsyncRead for QuicBiStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.recv).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for QuicBiStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.send)
                .poll_write(cx, buf)
                .map(|result| result.map_err(io::Error::other))
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.send)
                .poll_flush(cx)
                .map(|result| result.map_err(io::Error::other))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.send)
                .poll_shutdown(cx)
                .map(|result| result.map_err(io::Error::other))
        }
    }

    // ---- TLS termination tests ----

    #[tokio::test]
    async fn terminates_tls_and_forwards_plaintext_to_backend() -> io::Result<()> {
        let hostname = "app.example.test";
        let (public_cert, public_key) = make_self_signed_cert(hostname)?;
        let tls_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![public_cert.clone()],
                    private_key_from_der(&public_key),
                )
                .map_err(io::Error::other)?,
        );

        // Plain-TCP backend (receives decrypted data)
        let backend_listener = TcpListener::bind(localhost(0)).await?;
        let backend_address = backend_listener.local_addr()?.to_string();
        let backend_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut backend_stream, _) =
                timeout(Duration::from_secs(1), backend_listener.accept())
                    .await
                    .map_err(|_| timeout_error("backend should accept a forwarded connection"))??;
            let mut request = [0_u8; 4];
            timeout(Duration::from_secs(1), backend_stream.read_exact(&mut request))
                .await
                .map_err(|_| timeout_error("backend should receive request bytes"))??;
            assert_eq!(&request, b"ping");
            timeout(
                Duration::from_secs(1),
                backend_stream.write_all(b"pong"),
            )
            .await
            .map_err(|_| timeout_error("backend should send response bytes"))??;
            timeout(Duration::from_secs(1), backend_stream.shutdown())
                .await
                .map_err(|_| timeout_error("backend should close cleanly"))??;
            Ok::<(), io::Error>(())
        });

        let services = vec![ClientServiceSettings {
            public_hostnames: Some(vec![hostname.to_owned()]),
            backend_address,
            tls_mode: ClientTlsMode::Terminate,
        }];
        let mut tls_configs = HashMap::new();
        tls_configs.insert(hostname.to_owned(), tls_config.clone());
        let stream_handler = TunnelConnectionStreamHandler::new(services, false, tls_configs);

        let fixture = TunnelConnectionFixture::connect().await?;
        let server_connection = fixture.server_connection.clone();
        let client_connection = fixture.client_connection.clone();

        let stream_handler_task = tokio::spawn(async move {
            let (send, recv) = timeout(Duration::from_secs(1), client_connection.accept_bi())
                .await
                .map_err(|_| timeout_error("handler should accept a tunnel stream"))?
                .map_err(io::Error::other)?;
            stream_handler.handle(send, recv).await
        });

        // The tunnel sends a real TLS connection using the public cert as CA
        let response =
            request_plaintext_response_over_terminated_tunnel(server_connection, &public_cert, hostname)
                .await?;
        assert_eq!(response, *b"pong");

        backend_task
            .await
            .map_err(|error| join_error("backend task failed", error))??;
        stream_handler_task
            .await
            .map_err(|error| join_error("stream handler task failed", error))??;
        Ok(())
    }

    /// Makes a TLS connection over the QUIC tunnel stream, talks to a plain-TCP backend
    /// (because the Client terminates TLS and forwards plaintext).
    async fn request_plaintext_response_over_terminated_tunnel(
        server_connection: Connection,
        public_cert: &CertificateDer<'static>,
        hostname: &str,
    ) -> io::Result<[u8; 4]> {
        let (send, recv) = timeout(Duration::from_secs(1), server_connection.open_bi())
            .await
            .map_err(|_| timeout_error("test should open a tunnel stream"))?
            .map_err(io::Error::other)?;
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store_with(public_cert)?)
                .with_no_client_auth(),
        ));
        let server_name =
            ServerName::try_from(hostname.to_owned()).map_err(io::Error::other)?;
        let mut tls_stream = timeout(
            Duration::from_secs(1),
            connector.connect(server_name, QuicBiStream::new(send, recv)),
        )
        .await
        .map_err(|_| timeout_error("TLS handshake over the tunnel should complete"))?
        .map_err(io::Error::other)?;
        timeout(Duration::from_secs(1), tls_stream.write_all(b"ping"))
            .await
            .map_err(|_| timeout_error("TLS client should send request bytes"))??;

        let mut response = [0_u8; 4];
        timeout(Duration::from_secs(1), tls_stream.read_exact(&mut response))
            .await
            .map_err(|_| timeout_error("TLS client should receive response bytes"))??;
        timeout(Duration::from_secs(1), tls_stream.shutdown())
            .await
            .map_err(|_| timeout_error("TLS client should close cleanly"))??;
        Ok(response)
    }
}
