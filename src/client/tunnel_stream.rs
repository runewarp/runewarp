use std::io;
use std::sync::Arc;

use quinn::{RecvStream, SendStream};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::client_hello::read_client_hello;
use crate::runtime_log::{client_route_line, emit_stderr, warning_line};
use crate::{ClientServiceSettings, proxy::proxy_stream_error_code, proxy::proxy_tcp_over_quic};

#[derive(Clone)]
pub(crate) struct TunnelConnectionStreamHandler {
    services: Arc<[ClientServiceSettings]>,
    logs: bool,
}

impl TunnelConnectionStreamHandler {
    pub(crate) fn new(services: Vec<ClientServiceSettings>, logs: bool) -> Self {
        Self {
            services: services.into(),
            logs,
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
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::ClientConnection;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::{
        TunnelConnectionStreamHandler, backend_connect_failed_route_line,
        backend_write_failed_route_line, forwarded_route_line,
    };
    use crate::{ClientServiceSettings, make_client_quic_config, make_server_quic_config};

    #[tokio::test]
    async fn forwards_streams_for_exact_match_services() {
        assert_forwarded_stream(
            vec![
                ClientServiceSettings {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    backend_address: "127.0.0.1:443".to_owned(),
                },
                ClientServiceSettings {
                    public_hostnames: Some(vec!["api.example.test".to_owned()]),
                    backend_address: backend_placeholder(),
                },
            ],
            "api.example.test",
        )
        .await;
    }

    #[tokio::test]
    async fn forwards_streams_for_the_catch_all_service() {
        assert_forwarded_stream(
            vec![ClientServiceSettings {
                public_hostnames: None,
                backend_address: backend_placeholder(),
            }],
            "app.example.test",
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_streams_without_a_matching_service() {
        assert_rejected_stream(
            vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:443".to_owned(),
            }],
            "api.example.test",
            |result: io::Result<()>| result.unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_streams_when_backend_connect_fails() {
        let backend_address = unused_localhost_address().await.to_string();

        assert_rejected_stream(
            vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address,
            }],
            "app.example.test",
            |result: io::Result<()>| assert!(result.is_err()),
        )
        .await;
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn rejects_streams_when_backend_write_fails() {
        let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
        let backend_address = backend_listener.local_addr().unwrap().to_string();
        let reset_backend_task = tokio::spawn(async move {
            let (backend_stream, _) = timeout(Duration::from_secs(1), backend_listener.accept())
                .await
                .unwrap()
                .unwrap();
            backend_stream.set_linger(Some(Duration::ZERO)).unwrap();
            drop(backend_stream);
        });

        assert_rejected_stream(
            vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address,
            }],
            "app.example.test",
            |result: io::Result<()>| assert!(result.is_err()),
        )
        .await;

        reset_backend_task.await.unwrap();
    }

    #[test]
    fn route_lines_do_not_log_backend_addresses() {
        assert_eq!(
            backend_connect_failed_route_line("app.example.test"),
            "client route app.example.test -> backend connect failed"
        );
        assert_eq!(
            backend_write_failed_route_line("app.example.test"),
            "client route app.example.test -> backend write failed"
        );
        assert_eq!(
            forwarded_route_line("app.example.test"),
            "client route app.example.test -> forwarded"
        );
    }

    async fn assert_forwarded_stream(
        mut services: Vec<ClientServiceSettings>,
        requested_hostname: &str,
    ) {
        let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
        let backend_address = backend_listener.local_addr().unwrap().to_string();
        for service in &mut services {
            if service.backend_address == backend_placeholder() {
                service.backend_address = backend_address.clone();
            }
        }

        let stream_handler = TunnelConnectionStreamHandler::new(services, false);
        let fixture = TunnelConnectionFixture::connect().await;
        let server_connection = fixture.server_connection.clone();
        let client_connection = fixture.client_connection.clone();
        let client_hello = build_client_hello(requested_hostname);
        let expected_client_hello = client_hello.clone();

        let backend_task = tokio::spawn(async move {
            let (mut backend_stream, _) =
                timeout(Duration::from_secs(1), backend_listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut forwarded_client_hello = vec![0_u8; expected_client_hello.len()];
            backend_stream
                .read_exact(&mut forwarded_client_hello)
                .await
                .unwrap();
            assert_eq!(forwarded_client_hello, expected_client_hello);
            let mut request = [0_u8; 4];
            backend_stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            backend_stream.write_all(b"pong").await.unwrap();
            backend_stream.shutdown().await.unwrap();
        });

        let stream_handler_task = tokio::spawn(async move {
            let (send, recv) = timeout(Duration::from_secs(1), client_connection.accept_bi())
                .await
                .unwrap()
                .unwrap();
            stream_handler.handle(send, recv).await.unwrap();
        });

        let (mut tunnel_send, mut tunnel_recv) =
            timeout(Duration::from_secs(1), server_connection.open_bi())
                .await
                .unwrap()
                .unwrap();
        tunnel_send.write_all(&client_hello).await.unwrap();
        tunnel_send.write_all(b"ping").await.unwrap();
        tunnel_send.finish().unwrap();

        let response = timeout(Duration::from_secs(1), tunnel_recv.read_to_end(4))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"pong");

        backend_task.await.unwrap();
        stream_handler_task.await.unwrap();
    }

    async fn assert_rejected_stream(
        services: Vec<ClientServiceSettings>,
        requested_hostname: &str,
        assert_handler_result: impl FnOnce(io::Result<()>) + Send + 'static,
    ) {
        let stream_handler = TunnelConnectionStreamHandler::new(services, false);
        let fixture = TunnelConnectionFixture::connect().await;
        let server_connection = fixture.server_connection.clone();
        let client_connection = fixture.client_connection.clone();
        let client_hello = build_client_hello(requested_hostname);

        let stream_handler_task = tokio::spawn(async move {
            let (send, recv) = timeout(Duration::from_secs(1), client_connection.accept_bi())
                .await
                .unwrap()
                .unwrap();
            assert_handler_result(stream_handler.handle(send, recv).await);
        });

        let (mut tunnel_send, mut tunnel_recv) =
            timeout(Duration::from_secs(1), server_connection.open_bi())
                .await
                .unwrap()
                .unwrap();
        tunnel_send.write_all(&client_hello).await.unwrap();
        tunnel_send.finish().unwrap();

        let response = timeout(Duration::from_secs(1), tunnel_recv.read_to_end(1))
            .await
            .unwrap();
        assert!(response.is_err() || response.as_ref().unwrap().is_empty());

        stream_handler_task.await.unwrap();
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        server_connection: Connection,
        client_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect() -> Self {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test");
            let server_endpoint = Endpoint::server(
                make_server_quic_config(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                )
                .unwrap(),
                localhost(0),
            )
            .unwrap();
            let server_addr = server_endpoint.local_addr().unwrap();

            let mut client_endpoint = Endpoint::client(localhost(0)).unwrap();
            client_endpoint.set_default_client_config(
                make_client_quic_config(root_store_with(&certificate)).unwrap(),
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
                server_connection,
                client_connection,
            }
        }
    }

    fn backend_placeholder() -> String {
        "__backend__".to_owned()
    }

    async fn unused_localhost_address() -> SocketAddr {
        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    }

    fn build_client_hello(server_name: &str) -> Vec<u8> {
        let trusted_cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(server_name.to_owned()).unwrap(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).unwrap();
        bytes
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

    fn root_store_with(certificate: &CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        roots
    }
}
