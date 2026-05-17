use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, Client, ClientConfig,
    PreparedClient, PreparedServer, Server, ServerConfig, generate_client_identity,
    initialize_manual_server_certificate, load_client_settings, load_server_settings,
    make_client_quic_config, make_server_quic_config, make_server_quic_config_with_client_auth,
    make_server_quic_config_with_client_auth_resolver,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn forwards_tls_passthrough_end_to_end() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");

    let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
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
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
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
        backend_address: backend_address.to_string(),
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
async fn forwards_tls_passthrough_end_to_end_with_manual_private_ca_material() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    std::fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    let client_identity = generate_client_identity().unwrap();
    std::fs::write(
        tempdir
            .path()
            .join("client-identity")
            .join(CLIENT_CERT_FILENAME),
        &client_identity.certificate_pem,
    )
    .unwrap();
    std::fs::write(
        tempdir
            .path()
            .join("client-identity")
            .join(CLIENT_KEY_FILENAME),
        &client_identity.private_key_pem,
    )
    .unwrap();
    std::fs::write(
        tempdir
            .path()
            .join("client-identity")
            .join(CLIENT_IDENTITY_FILENAME),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"pong",
    )
    .await;

    std::fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
            client_identity.client_identity
        ),
    )
    .unwrap();
    std::fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-cert/server-ca.crt"
identity-directory = "client-identity"

[[client.services]]
backend-address = "__BACKEND_ADDRESS__"
"#
        .replace("__BACKEND_ADDRESS__", &backend.0.to_string()),
    )
    .unwrap();

    let server_settings = load_server_settings(&tempdir.path().join("server.toml")).unwrap();
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = load_client_settings(&tempdir.path().join("client.toml")).unwrap();
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    let response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(response, *b"pong");

    backend.1.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend.1.await;
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
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
        public_tls_config: None,
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
async fn terminates_acme_tls_alpn_challenges_for_the_server_hostname() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let (challenge_cert, challenge_key) = make_self_signed_cert("tunnel.example.test");
    let mut challenge_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![challenge_cert.clone()],
            private_key_from_der(&challenge_key),
        )
        .unwrap();
    challenge_server_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
        public_tls_config: Some(Arc::new(challenge_server_config)),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let mut challenge_client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store_with(&challenge_cert))
        .with_no_client_auth();
    challenge_client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(challenge_client_config));
    let tcp_stream = TcpStream::connect(public_addr).await.unwrap();
    let tls_stream = connector
        .connect(
            ServerName::try_from("tunnel.example.test").unwrap(),
            tcp_stream,
        )
        .await;

    assert!(tls_stream.is_ok());

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn acme_tls_alpn_challenges_do_not_terminate_customer_hostname_traffic() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
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

    let (challenge_cert, challenge_key) = make_self_signed_cert("tunnel.example.test");
    let mut challenge_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![challenge_cert], private_key_from_der(&challenge_key))
        .unwrap();
    challenge_server_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
        public_tls_config: Some(Arc::new(challenge_server_config)),
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
        backend_address: backend_address.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    let mut challenge_client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store_with(&backend_cert))
        .with_no_client_auth();
    challenge_client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(challenge_client_config));
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
async fn swapped_server_certificates_only_apply_to_new_tunnel_handshakes() {
    let tempdir = tempdir().unwrap();
    let trusted_client = generate_client_identity().unwrap();
    std::fs::write(
        tempdir.path().join("client.crt"),
        &trusted_client.certificate_pem,
    )
    .unwrap();
    std::fs::write(
        tempdir.path().join("client.key"),
        &trusted_client.private_key_pem,
    )
    .unwrap();
    std::fs::write(
        tempdir.path().join("client-identity.txt"),
        trusted_client.client_identity.to_string(),
    )
    .unwrap();

    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"pong",
    )
    .await;

    let (server_cert_a, server_key_a, server_pem_a) =
        make_self_signed_cert_with_pem("tunnel.example.test");
    let (server_cert_b, server_key_b, server_pem_b) =
        make_self_signed_cert_with_pem("tunnel.example.test");
    let resolver = Arc::new(SwappableServerCertResolver::new(
        server_cert_a.clone(),
        private_key_from_der(&server_key_a),
    ));
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
        quic_server_config: make_server_quic_config_with_client_auth_resolver(
            resolver.clone(),
            std::slice::from_ref(&trusted_client.client_identity),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    std::fs::write(tempdir.path().join("server-a.pem"), server_pem_a).unwrap();
    std::fs::write(
        tempdir.path().join("client-a.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-a.pem"
identity-directory = "."

[[client.services]]
backend-address = "__BACKEND_ADDRESS__"
"#
        .replace("__BACKEND_ADDRESS__", &backend.0.to_string()),
    )
    .unwrap();
    let client_a_settings = load_client_settings(&tempdir.path().join("client-a.toml")).unwrap();
    let client_a = PreparedClient::connect_to(&client_a_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_a_task = tokio::spawn(client_a.run());

    let first_response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(first_response, *b"pong");

    resolver.swap(server_cert_b.clone(), private_key_from_der(&server_key_b));
    sleep(Duration::from_millis(50)).await;

    let second_response = request_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(second_response, *b"pong");

    std::fs::write(tempdir.path().join("server-b.pem"), server_pem_b).unwrap();
    std::fs::write(
        tempdir.path().join("client-b.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-b.pem"
identity-directory = "."

[[client.services]]
backend-address = "__BACKEND_ADDRESS__"
"#
        .replace("__BACKEND_ADDRESS__", &backend.0.to_string()),
    )
    .unwrap();
    let client_b_settings = load_client_settings(&tempdir.path().join("client-b.toml")).unwrap();
    let client_b = PreparedClient::connect_to(&client_b_settings, localhost(0), tunnel_addr).await;

    assert!(client_b.is_ok());

    backend.1.abort();
    server_task.abort();
    client_a_task.abort();
    let _ = backend.1.await;
    let _ = server_task.await;
    let _ = client_a_task.await;
}

#[tokio::test]
async fn rejects_tunnel_clients_that_do_not_present_a_client_certificate() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"pong",
    )
    .await;
    let trusted_client = generate_client_identity().unwrap();
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        quic_server_config: make_server_quic_config_with_client_auth(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
            &[trusted_client.client_identity],
        )
        .unwrap(),
        public_tls_config: None,
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
        backend_address: backend.0.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await;

    let client_task = client.ok().map(|client| tokio::spawn(client.run()));
    sleep(Duration::from_millis(50)).await;

    let visitor_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &backend_cert, "app.example.test"),
    )
    .await;
    assert!(
        matches!(visitor_result, Ok(Err(_))),
        "an unauthenticated client must never become the active tunnel"
    );

    backend.1.abort();
    server_task.abort();
    if let Some(client_task) = client_task {
        client_task.abort();
        let _ = client_task.await;
    }
    let _ = backend.1.await;
    let _ = server_task.await;
}

#[tokio::test]
async fn library_constructors_expose_addresses_before_running() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
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
        backend_address: available_local_addr().await.to_string(),
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
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
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
        backend_address: backend_one.0.to_string(),
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
        backend_address: backend_two.0.to_string(),
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
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
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
        backend_address: backend.0.to_string(),
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
    let closed_backend_address = available_local_addr().await;
    let (backend_cert, _) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");

    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
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
        backend_address: closed_backend_address.to_string(),
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

#[tokio::test]
async fn replacing_a_tunnel_connection_drops_existing_streams() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let (backend_one_addr, backend_one_started, backend_one_release, backend_one_task) =
        spawn_staged_tls_backend(
            private_key_from_der(&backend_key),
            backend_cert.clone(),
            *b"on",
            *b"e!",
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
        authorized_public_hostnames: vec!["app.example.test".to_owned()],
        configured_tunnels: Vec::new(),
        logs: true,
        public_tls_config: None,
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
        backend_address: backend_one_addr.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_one_task = tokio::spawn(client_one.run());

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

    timeout(Duration::from_secs(1), backend_one_started)
        .await
        .expect("timed out waiting for the first backend response chunk")
        .expect("staged backend should signal once the first response chunk is sent");

    let mut initial_bytes = [0_u8; 2];
    tls_stream.read_exact(&mut initial_bytes).await.unwrap();
    assert_eq!(&initial_bytes, b"on");

    let client_two = Client::connect(ClientConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_two.0.to_string(),
        quic_client_config: make_client_quic_config(root_store_with(&tunnel_cert)).unwrap(),
    })
    .await
    .unwrap();
    let client_two_task = tokio::spawn(client_two.run());

    let replacement_response =
        wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
            .await
            .unwrap();
    assert_eq!(replacement_response, *b"two!");

    backend_one_release.notify_one();

    let mut remaining_bytes = [0_u8; 2];
    let read_result = timeout(
        Duration::from_secs(1),
        tls_stream.read_exact(&mut remaining_bytes),
    )
    .await
    .expect("timed out waiting for the replaced stream to terminate");
    assert!(
        read_result.is_err(),
        "replaced tunnel stream should not complete successfully"
    );

    backend_two.1.abort();
    server_task.abort();
    client_one_task.abort();
    client_two_task.abort();
    let _ = backend_one_task.await;
    let _ = backend_two.1.await;
    let _ = server_task.await;
    let _ = client_one_task.await;
    let _ = client_two_task.await;
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

fn make_self_signed_cert_with_pem(server_name: &str) -> (CertificateDer<'static>, Vec<u8>, String) {
    let certified_key = generate_simple_self_signed(vec![server_name.to_owned()]).unwrap();
    let certificate_pem = certified_key.cert.pem();
    (
        CertificateDer::from(certified_key.cert),
        certified_key.signing_key.serialize_der(),
        certificate_pem,
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

#[derive(Debug)]
struct SwappableServerCertResolver {
    certified_key: Mutex<Arc<CertifiedKey>>,
}

impl SwappableServerCertResolver {
    fn new(certificate: CertificateDer<'static>, private_key: PrivateKeyDer<'static>) -> Self {
        Self {
            certified_key: Mutex::new(Arc::new(certified_key(certificate, private_key))),
        }
    }

    fn swap(&self, certificate: CertificateDer<'static>, private_key: PrivateKeyDer<'static>) {
        *self.certified_key.lock().unwrap() = Arc::new(certified_key(certificate, private_key));
    }
}

impl ResolvesServerCert for SwappableServerCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.lock().unwrap().clone())
    }
}

fn certified_key(
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
) -> CertifiedKey {
    CertifiedKey::new(
        vec![certificate],
        rustls::crypto::ring::sign::any_supported_type(&private_key).unwrap(),
    )
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

async fn spawn_staged_tls_backend(
    private_key: PrivateKeyDer<'static>,
    certificate: CertificateDer<'static>,
    first_chunk: [u8; 2],
    second_chunk: [u8; 2],
) -> (
    SocketAddr,
    oneshot::Receiver<()>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap(),
    ));
    let (started_tx, started_rx) = oneshot::channel();
    let release = Arc::new(Notify::new());
    let release_for_task = release.clone();

    let task = tokio::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();
        let mut request = [0_u8; 4];
        tls_stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        tls_stream.write_all(&first_chunk).await.unwrap();
        tls_stream.flush().await.unwrap();
        let _ = started_tx.send(());
        release_for_task.notified().await;
        let _ = tls_stream.write_all(&second_chunk).await;
        let _ = tls_stream.shutdown().await;
    });

    (addr, started_rx, release, task)
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
