use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    Phase1Client, Phase1ClientConfig, Phase1Server, Phase1ServerConfig, make_quic_client_config,
    make_quic_server_config,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn phase1_forwards_tls_passthrough_end_to_end() {
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

    let server = Phase1Server::bind(Phase1ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        quic_server_config: make_quic_server_config(
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

    let client = Phase1Client::connect(Phase1ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_addr,
        quic_client_config: make_quic_client_config(root_store_with(&tunnel_cert)).unwrap(),
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
async fn phase1_drops_public_tls_when_no_client_is_connected() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let server = Phase1Server::bind(Phase1ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        quic_server_config: make_quic_server_config(
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
