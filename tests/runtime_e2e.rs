use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    Client, ClientConfig, Server, ServerConfig, make_client_quic_config, make_server_quic_config,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn forwards_tls_passthrough_end_to_end() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");

    let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    let backend_acceptor = TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![backend_cert.clone()],
                private_key_from_der(&backend_key),
            )
            .unwrap(),
    ));
    let backend_task = tokio::spawn(async move {
        let (tcp_stream, _) = backend_listener.accept().await.unwrap();
        let mut tls_stream = backend_acceptor.accept(tcp_stream).await.unwrap();
        let mut request = [0_u8; 4];
        tls_stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        tls_stream.write_all(b"pong").await.unwrap();
        tls_stream.shutdown().await.unwrap();
    });

    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr: backend_addr.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(&backend_cert))
            .with_no_client_auth(),
    ));
    let tcp_stream = TcpStream::connect(public_addr).await.unwrap();
    let mut tls_stream = connector
        .connect(
            ServerName::try_from("app.example.test").unwrap(),
            tcp_stream,
        )
        .await
        .unwrap();
    tls_stream.write_all(b"ping").await.unwrap();

    let mut response = [0_u8; 4];
    tls_stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");

    backend_task.await.unwrap();
    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn drops_public_tls_when_no_client_is_connected() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let (backend_cert, _) = make_self_signed_cert("app.example.test");
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(&backend_cert))
            .with_no_client_auth(),
    ));
    let tcp_stream = TcpStream::connect(public_addr).await.unwrap();
    let handshake = connector
        .connect(
            ServerName::try_from("app.example.test").unwrap(),
            tcp_stream,
        )
        .await;

    assert!(handshake.is_err());

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn library_constructors_expose_addresses_before_running() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();

    assert_ne!(public_addr.port(), 0);
    assert_ne!(tunnel_addr.port(), 0);

    let server_task = tokio::spawn(server.run());
    let client = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr: available_local_addr().await.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();

    assert_ne!(client.local_addr().unwrap().port(), 0);

    let client_task = tokio::spawn(client.run());

    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn latest_client_instance_serves_subsequent_visitor_connections() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend_one = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"one!",
    )
    .await;
    let backend_two = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"two!",
    )
    .await;

    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_one = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr: backend_one.0.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_one_task = tokio::spawn(client_one.run());

    sleep(Duration::from_millis(50)).await;

    let first_response = request_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(first_response, *b"one!");

    let client_two = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr: backend_two.0.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_two_task = tokio::spawn(client_two.run());

    let second_response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(second_response, *b"two!");

    backend_one.1.abort();
    backend_two.1.abort();
    server_task.abort();
    client_one_task.abort();
    client_two_task.abort();
    let _ = backend_one.1.await;
    let _ = backend_two.1.await;
    let _ = server_task.await;
    let _ = client_one_task.await;
    let _ = client_two_task.await;
}

#[tokio::test]
async fn drops_public_tls_after_the_active_client_instance_disconnects() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"pong",
    )
    .await;
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");

    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr: backend.0.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_task = tokio::spawn(client.run());

    let response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(response, *b"pong");

    client_task.abort();
    let _ = client_task.await;

    wait_for_tls_failure(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();

    backend.1.abort();
    server_task.abort();
    let _ = backend.1.await;
    let _ = server_task.await;
}

#[tokio::test]
async fn visitor_tls_fails_when_the_local_backend_is_unreachable() {
    let closed_backend_addr = available_local_addr().await;
    let (backend_cert, _) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");

    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr: closed_backend_addr.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    let visitor_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &backend_cert, "app.example.test"),
    )
    .await;
    assert!(matches!(visitor_result, Ok(Err(_))));

    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

async fn available_local_addr() -> SocketAddr {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    listener.local_addr().unwrap()
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

async fn spawn_tls_backend(
    private_key: PrivateKeyDer<'static>,
    certificate: CertificateDer<'static>,
    response: [u8; 4],
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap(),
    ));

    let task = tokio::spawn(async move {
        loop {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();
                let mut request = [0_u8; 4];
                tls_stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                tls_stream.write_all(&response).await.unwrap();
                tls_stream.shutdown().await.unwrap();
            });
        }
    });

    (addr, task)
}

async fn request_tls_response(
    public_addr: SocketAddr,
    backend_cert: &CertificateDer<'static>,
    server_name: &str,
) -> io::Result<[u8; 4]> {
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(backend_cert))
            .with_no_client_auth(),
    ));
    let tcp_stream = TcpStream::connect(public_addr).await?;
    let mut tls_stream = connector
        .connect(
            ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?,
            tcp_stream,
        )
        .await
        .map_err(io::Error::other)?;
    tls_stream.write_all(b"ping").await?;

    let mut response = [0_u8; 4];
    tls_stream.read_exact(&mut response).await?;
    Ok(response)
}

async fn wait_for_tls_response(
    public_addr: SocketAddr,
    backend_cert: &CertificateDer<'static>,
    server_name: &str,
) -> io::Result<[u8; 4]> {
    timeout(Duration::from_secs(1), async move {
        loop {
            match request_tls_response(public_addr, backend_cert, server_name).await {
                Ok(response) => return Ok(response),
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .map_err(io::Error::other)?
}

async fn wait_for_tls_failure(
    public_addr: SocketAddr,
    backend_cert: &CertificateDer<'static>,
    server_name: &str,
) -> io::Result<()> {
    timeout(Duration::from_secs(1), async move {
        loop {
            if request_tls_response(public_addr, backend_cert, server_name)
                .await
                .is_err()
            {
                return Ok(());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(io::Error::other)?
}
