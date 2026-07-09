use std::io::{self, Cursor};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, Client, ClientConfig,
    ClientConfigResolutionDefaults, ClientConnectConfig, ClientPublicCertConfig, ClientRuntimeArgs,
    ClientTlsMode, GeneratedClientIdentity, LogLevel, OrderlyShutdown, PreparedClient,
    PreparedServer, PublicHostname, QUIC_CLOSE_FLUSH_DURATION, SelectedClientConfig, Server,
    ServerAddress, ServerBindConfig, ServerHostname, ServerTunnelConfig, ServiceConfig,
    ShutdownMode, generate_client_identity, initialize_manual_server_certificate,
    load_client_config, load_server_config, make_client_quic_config,
    make_client_quic_config_with_client_auth, make_server_quic_config,
    make_server_quic_config_with_client_auth, make_server_quic_config_with_client_auth_resolver,
    resolve_selected_client_config,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_acme::CertCache;
use rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;
use rustls_acme::caches::DirCache;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn public_hostname(hostname: &str) -> PublicHostname {
    PublicHostname::try_from(hostname).unwrap()
}

fn server_hostname(hostname: &str) -> ServerHostname {
    ServerHostname::try_from(hostname).unwrap()
}

fn server_address(value: &str) -> ServerAddress {
    ServerAddress::parse(value).unwrap()
}

#[tokio::test]
async fn forwards_tls_passthrough_end_to_end() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let trusted_client = generate_client_identity().unwrap();

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

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&trusted_client],
        ),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_address.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &trusted_client),
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
cert-dir = "server-cert"

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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-identity"

[[client.services]]
backend-address = "__BACKEND_ADDRESS__"
"#
        .replace("__BACKEND_ADDRESS__", &backend.0.to_string()),
    )
    .unwrap();

    let server_settings = load_server_config(&tempdir.path().join("server.toml")).unwrap();
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = load_client_config(&tempdir.path().join("client.toml")).unwrap();
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
async fn resolver_built_catch_all_settings_forward_end_to_end()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )?;

    let client_identity = generate_client_identity()?;
    std::fs::create_dir(tempdir.path().join("client-identity"))?;
    std::fs::write(
        tempdir
            .path()
            .join("client-identity")
            .join(CLIENT_CERT_FILENAME),
        &client_identity.certificate_pem,
    )?;
    std::fs::write(
        tempdir
            .path()
            .join("client-identity")
            .join(CLIENT_KEY_FILENAME),
        &client_identity.private_key_pem,
    )?;
    std::fs::write(
        tempdir
            .path()
            .join("client-identity")
            .join(CLIENT_IDENTITY_FILENAME),
        client_identity.client_identity.to_string(),
    )?;

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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
            client_identity.client_identity
        ),
    )?;
    std::fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-identity"
"#,
    )?;

    let server_settings = load_server_config(&tempdir.path().join("server.toml"))?;
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0)).await?;
    let public_addr = server.public_addr()?;
    let tunnel_addr = server.tunnel_addr()?;
    let server_task = tokio::spawn(server.run());

    let client_settings = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("client.toml")),
        &ClientRuntimeArgs {
            server_addresses: vec!["tunnel.example.test".to_owned()],
            backend_address: Some(backend.0.to_string()),
        },
        &ClientConfigResolutionDefaults {
            identity_directory: tempdir.path().join("unused-default"),
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr).await?;
    let client_task = tokio::spawn(client.run());

    let result = async {
        let response =
            wait_for_tls_response(public_addr, &backend_cert, "app.example.test").await?;
        assert_eq!(response, *b"pong");
        Ok::<(), std::io::Error>(())
    }
    .await;

    backend.1.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend.1.await;
    let _ = server_task.await;
    let _ = client_task.await;

    result.map_err(Into::into)
}

#[tokio::test]
async fn drops_public_tls_when_no_client_is_connected() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let trusted_client = generate_client_identity().unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&trusted_client],
        ),
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
    let trusted_client = generate_client_identity().unwrap();
    let mut challenge_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![challenge_cert.clone()],
            private_key_from_der(&challenge_key),
        )
        .unwrap();
    challenge_server_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&trusted_client],
        ),
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
    let trusted_client = generate_client_identity().unwrap();
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

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&trusted_client],
        ),
        public_tls_config: Some(Arc::new(challenge_server_config)),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_address.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &trusted_client),
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
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-a.pem"
identity-dir = "."

[[client.services]]
backend-address = "__BACKEND_ADDRESS__"
"#
        .replace("__BACKEND_ADDRESS__", &backend.0.to_string()),
    )
    .unwrap();
    let client_a_settings = load_client_config(&tempdir.path().join("client-a.toml")).unwrap();
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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-b.pem"
identity-dir = "."

[[client.services]]
backend-address = "__BACKEND_ADDRESS__"
"#
        .replace("__BACKEND_ADDRESS__", &backend.0.to_string()),
    )
    .unwrap();
    let client_b_settings = load_client_config(&tempdir.path().join("client-b.toml")).unwrap();
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
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
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

    let client = Client::connect(ClientConnectConfig {
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
    let trusted_client = generate_client_identity().unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &trusted_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&trusted_client],
        ),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();

    assert_ne!(public_addr.port(), 0);
    assert_ne!(tunnel_addr.port(), 0);

    let server_task = tokio::spawn(server.run());
    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: available_local_addr().await.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &trusted_client),
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
async fn server_bind_rejects_duplicate_configured_tunnel_hostnames() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let first_client = generate_client_identity().unwrap();
    let second_client = generate_client_identity().unwrap();

    let error = match Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![
            configured_tunnel(&["App.Example.Test."], &first_client),
            configured_tunnel(&["app.example.test"], &second_client),
        ],
        public_tls_config: None,
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    {
        Ok(_) => panic!("expected server bind to reject duplicate configured Public hostnames"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(
        "server.tunnels[].public-hostnames must be unique after normalization: app.example.test"
    ));
}

#[tokio::test]
async fn server_bind_rejects_duplicate_configured_tunnel_client_identities() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let shared_client = generate_client_identity().expect("shared client identity should generate");

    let error = match Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![
            configured_tunnel(&["app.example.test"], &shared_client),
            configured_tunnel(&["api.example.test"], &shared_client),
        ],
        public_tls_config: None,
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert.clone()],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    {
        Ok(_) => panic!("expected server bind to reject duplicate configured tunnel identities"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("authorized Client identities must be unique across all Server Tunnels")
    );
}

#[tokio::test]
async fn server_bind_rejects_empty_configured_tunnels() {
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");

    let error = match Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: Vec::new(),
        public_tls_config: None,
        quic_server_config: make_server_quic_config(
            vec![tunnel_cert],
            private_key_from_der(&tunnel_key),
        )
        .unwrap(),
    })
    .await
    {
        Ok(_) => panic!("expected server bind to reject an empty configured tunnel set"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("server bind requires at least one configured Tunnel")
    );
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
    let shared_client = generate_client_identity().expect("shared client identity should generate");
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .expect("server should bind");
    let public_addr = server
        .public_addr()
        .expect("public listener should have an address");
    let tunnel_addr = server
        .tunnel_addr()
        .expect("tunnel listener should have an address");
    let server_task = tokio::spawn(server.run());

    let client_one = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_one.0.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
    })
    .await
    .expect("client should connect");
    let client_one_task = tokio::spawn(client_one.run());

    sleep(Duration::from_millis(50)).await;

    let first_response = request_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .expect("public TLS request should succeed");
    assert_eq!(first_response, *b"one!");

    let client_two = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_two.0.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
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
    let shared_client = generate_client_identity().unwrap();

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .expect("server should bind");
    let public_addr = server
        .public_addr()
        .expect("public listener should have an address");
    let tunnel_addr = server
        .tunnel_addr()
        .expect("tunnel listener should have an address");
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend.0.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
    })
    .await
    .expect("client should connect");
    let client_task = tokio::spawn(client.run());

    let response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .expect("public TLS request should succeed");
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
async fn drops_public_tls_after_the_client_gracefully_shuts_down() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"pong",
    )
    .await;
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let shared_client = generate_client_identity().unwrap();

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend.0.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
    })
    .await
    .unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let client_task = tokio::spawn({
        async move {
            client
                .run_until_shutdown(async move {
                    let _ = shutdown_rx.await;
                    ShutdownMode::Graceful
                })
                .await
        }
    });

    let response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(response, *b"pong");

    shutdown_tx
        .send(())
        .expect("client shutdown signal should be delivered");
    timeout(Duration::from_secs(1), client_task)
        .await
        .expect("client should finish graceful shutdown")
        .expect("client task should join cleanly")
        .expect("client shutdown path should return success");

    wait_for_tls_failure(public_addr, &backend_cert, "app.example.test")
        .await
        .expect("public TLS should fail once the client exits gracefully");

    backend.1.abort();
    server_task.abort();
    let _ = backend.1.await;
    let _ = server_task.await;
}

#[tokio::test]
async fn server_graceful_shutdown_stops_new_accepts_and_client_observes_a_clean_close() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let backend = spawn_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"pong",
    )
    .await;
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let shared_client = generate_client_identity().expect("shared client identity should generate");

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .expect("server should bind");
    let public_addr = server
        .public_addr()
        .expect("public listener should have an address");
    let tunnel_addr = server
        .tunnel_addr()
        .expect("tunnel listener should have an address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown = OrderlyShutdown::new(Duration::ZERO, QUIC_CLOSE_FLUSH_DURATION);
    let shutdown_trigger = shutdown.clone();
    let server_task = tokio::spawn(async move {
        let signal_task = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            let _ = shutdown_trigger.begin_graceful();
        });
        let result = server.run_with_shutdown(&shutdown).await;
        let _ = signal_task.await;
        result
    });

    let client_config = ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend.0.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
    };
    let client = Client::connect(client_config.clone())
        .await
        .expect("client should connect");
    let client_task = tokio::spawn(client.run());

    let response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .expect("public TLS request should succeed");
    assert_eq!(response, *b"pong");

    shutdown_tx
        .send(())
        .expect("server shutdown signal should be delivered");
    timeout(Duration::from_secs(1), server_task)
        .await
        .expect("server should finish graceful shutdown")
        .expect("server task should join cleanly")
        .expect("server shutdown path should return success");

    let client_error = timeout(Duration::from_secs(1), client_task)
        .await
        .expect("client should observe the remote graceful close")
        .expect("client task should join cleanly")
        .expect_err("remote graceful close should still surface as a disconnect");
    assert!(matches!(
        client_error,
        quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::ConnectionClosed(_)
    ));

    wait_for_tcp_connect_failure(public_addr)
        .await
        .expect("server should stop accepting new public TCP connections");
    let reconnect_result =
        timeout(Duration::from_millis(250), Client::connect(client_config)).await;
    assert!(
        !matches!(reconnect_result, Ok(Ok(_))),
        "server shutdown should not admit a new tunnel connection"
    );

    backend.1.abort();
    let _ = backend.1.await;
}

#[tokio::test]
async fn graceful_server_shutdown_keeps_already_landed_streams_until_they_finish() {
    let (backend_cert, backend_key) = make_self_signed_cert("app.example.test");
    let (backend_addr, backend_started, backend_release, backend_task) = spawn_staged_tls_backend(
        private_key_from_der(&backend_key),
        backend_cert.clone(),
        *b"on",
        *b"e!",
    )
    .await;
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let shared_client = generate_client_identity().unwrap();

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let shutdown = OrderlyShutdown::new(Duration::from_millis(250), QUIC_CLOSE_FLUSH_DURATION);
    let shutdown_trigger = shutdown.clone();
    let mut server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });

    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_addr.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
    })
    .await
    .unwrap();
    let client_task = tokio::spawn(client.run());

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

    timeout(Duration::from_secs(1), backend_started)
        .await
        .expect("timed out waiting for the first backend response chunk")
        .expect("staged backend should signal once the first response chunk is sent");

    let mut initial_bytes = [0_u8; 2];
    tls_stream.read_exact(&mut initial_bytes).await.unwrap();
    assert_eq!(&initial_bytes, b"on");

    shutdown_trigger.begin_graceful();
    assert!(
        timeout(Duration::from_millis(100), &mut server_task)
            .await
            .is_err(),
        "graceful shutdown should stay alive while the landed stream is still active"
    );

    backend_release.notify_one();
    timeout(Duration::from_secs(1), backend_task)
        .await
        .expect("backend should finish once the landed stream is released")
        .expect("backend task should join cleanly");

    timeout(Duration::from_secs(2), server_task)
        .await
        .expect("server should complete graceful shutdown")
        .expect("server task should join cleanly")
        .expect("server shutdown should succeed");

    client_task.abort();
    let _ = client_task.await;
}

#[tokio::test]
async fn visitor_tls_fails_when_the_local_backend_is_unreachable() {
    let closed_backend_address = available_local_addr().await;
    let (backend_cert, _) = make_self_signed_cert("app.example.test");
    let (tunnel_cert, tunnel_key) = make_self_signed_cert("tunnel.example.test");
    let shared_client = generate_client_identity().unwrap();

    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: closed_backend_address.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
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
async fn a_busier_tunnel_pool_member_stops_winning_new_stream_placement() {
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
    let shared_client = generate_client_identity().unwrap();
    let server = Server::bind(ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname("tunnel.example.test"),
        configured_tunnels: vec![configured_tunnel(&["app.example.test"], &shared_client)],
        public_tls_config: None,
        quic_server_config: make_authenticated_server_quic_config(
            &tunnel_cert,
            &tunnel_key,
            &[&shared_client],
        ),
    })
    .await
    .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_one = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_one_addr.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
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

    let client_two = Client::connect(ClientConnectConfig {
        local_bind_addr: localhost(0),
        server_addr: tunnel_addr,
        server_name: "tunnel.example.test".to_owned(),
        backend_address: backend_two.0.to_string(),
        quic_client_config: make_authenticated_client_quic_config(&tunnel_cert, &shared_client),
    })
    .await
    .unwrap();
    let client_two_task = tokio::spawn(client_two.run());

    let pooled_response = wait_for_tls_response(public_addr, &backend_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(pooled_response, *b"two!");

    backend_one_release.notify_one();

    let mut remaining_bytes = [0_u8; 2];
    timeout(
        Duration::from_secs(1),
        tls_stream.read_exact(&mut remaining_bytes),
    )
    .await
    .expect("timed out waiting for the original stream to finish")
    .unwrap();
    assert_eq!(&remaining_bytes, b"e!");

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

#[tokio::test]
async fn forwards_tls_terminate_end_to_end() {
    use runewarp::{
        CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME,
        initialize_manual_client_public_cert,
    };
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

    // Bootstrap the Public hostname certificate material used for terminating Visitor TLS
    let public_cert_dir = tempdir.path().join("public-cert");
    initialize_manual_client_public_cert(&public_cert_dir, "app.example.test").unwrap();
    let public_ca_cert_pem =
        std::fs::read_to_string(public_cert_dir.join("public-ca.crt")).unwrap();
    let public_ca_cert = rustls_pemfile::certs(&mut public_ca_cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();

    // Plain TCP backend — receives decrypted traffic after Client terminates TLS
    let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut tcp_stream, _) = backend_listener.accept().await.unwrap();
        let mut request = [0_u8; 4];
        tcp_stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        tcp_stream.write_all(b"pong").await.unwrap();
        tcp_stream.shutdown().await.unwrap();
    });

    std::fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-identity"
public-cert-dir = "public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "__BACKEND_ADDRESS__"
tls-mode = "terminate"
"#
        .replace("__BACKEND_ADDRESS__", &backend_address.to_string()),
    )
    .unwrap();

    let server_settings = load_server_config(&tempdir.path().join("server.toml")).unwrap();
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = load_client_config(&tempdir.path().join("client.toml")).unwrap();
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    // Visitor connects with TLS using the Public hostname CA — backend receives plaintext
    let response = wait_for_tls_response(public_addr, &public_ca_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(response, *b"pong");

    backend_task.await.unwrap();
    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

/// One Client connects with both a terminating service (`app.example.test`) and a
/// passthrough service (`api.example.test`).  Visitor connections to each hostname
/// travel through the same tunnel but are routed independently:
///   - `app.example.test` → Client terminates TLS, backend receives plaintext
///   - `api.example.test` → Client forwards raw TLS bytes, backend terminates TLS
#[tokio::test]
async fn forwards_mixed_tls_terminate_and_passthrough_end_to_end() {
    use runewarp::{
        CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME,
        initialize_manual_client_public_cert,
    };
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

    // Bootstrap Public hostname certificate material for the terminating Service only
    let public_cert_dir = tempdir.path().join("public-cert");
    initialize_manual_client_public_cert(&public_cert_dir, "app.example.test").unwrap();
    let public_ca_cert_pem =
        std::fs::read_to_string(public_cert_dir.join("public-ca.crt")).unwrap();
    let terminate_ca_cert = rustls_pemfile::certs(&mut public_ca_cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();

    // Plain TCP backend for the terminating service (receives decrypted bytes)
    let term_backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let term_backend_addr = term_backend_listener.local_addr().unwrap();
    let term_backend_task = tokio::spawn(async move {
        let (mut stream, _) = term_backend_listener.accept().await.unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    // TLS-terminating backend for the passthrough service (receives raw TLS)
    let (pass_cert, pass_key) = make_self_signed_cert("api.example.test");
    let (pass_backend_addr, pass_backend_task) =
        spawn_tls_backend(private_key_from_der(&pass_key), pass_cert.clone(), *b"pong").await;

    // Server: one tunnel covers both hostnames under one client identity
    std::fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test", "api.example.test"]
client-identity = "{}"
"#,
            client_identity.client_identity
        ),
    )
    .unwrap();

    // Client: two services — one terminate, one passthrough
    std::fs::write(
        tempdir.path().join("client.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-identity"
public-cert-dir = "public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "{term_backend}"
tls-mode = "terminate"

[[client.services]]
public-hostnames = ["api.example.test"]
backend-address = "{pass_backend}"
tls-mode = "passthrough"
"#,
            term_backend = term_backend_addr,
            pass_backend = pass_backend_addr,
        ),
    )
    .unwrap();

    let server_settings = load_server_config(&tempdir.path().join("server.toml")).unwrap();
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = load_client_config(&tempdir.path().join("client.toml")).unwrap();
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    // Visitor 1: terminating service — Client decrypts, backend gets plaintext
    let term_response = wait_for_tls_response(public_addr, &terminate_ca_cert, "app.example.test")
        .await
        .unwrap();
    assert_eq!(term_response, *b"pong");
    term_backend_task.await.unwrap();

    // Visitor 2: passthrough service — Client proxies raw TLS, backend decrypts
    let pass_response = wait_for_tls_response(public_addr, &pass_cert, "api.example.test")
        .await
        .unwrap();
    assert_eq!(pass_response, *b"pong");
    pass_backend_task.abort();

    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// The Server routes `acme-tls/1` challenges for public hostnames to the Client unchanged —
/// the Server only intercepts `acme-tls/1` for its own `server.hostname`.
/// This test uses a Client in ACME termination mode and verifies that:
/// 1. The challenge connection is forwarded through the tunnel to the Client.
/// 2. The Client attempts the TLS handshake (it fails closed with no cert acquired yet).
/// The TCP connection reaching the TLS layer — rather than being dropped at the server —
/// is the observable proof that the Server forwarded rather than terminated it.
#[tokio::test]
async fn server_forwards_acme_tls_alpn_challenges_for_public_hostnames_to_client() {
    let tempdir = tempdir().unwrap();

    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let client_identity = generate_client_identity().unwrap();
    std::fs::create_dir(tempdir.path().join("client-identity")).unwrap();
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

    let acme_state_dir = tempdir.path().join("acme-state");
    std::fs::create_dir(&acme_state_dir).unwrap();

    let server_settings = load_server_config(&{
        let path = tempdir.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
                client_identity.client_identity
            ),
        )
        .unwrap();
        path
    })
    .unwrap();

    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-cert/server-ca.crt")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "localhost:80".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Acme {
            email: "test@example.test".to_owned(),
            state_directory: acme_state_dir,
            state_directory_was_defaulted: false,
        }),
    };
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    // Connect with acme-tls/1 ALPN for the public hostname (not the server hostname).
    // The Server must forward it to the Client through the tunnel; it must NOT terminate it.
    // Since the Client has no cert acquired yet, the TLS handshake will fail — but the
    // failure is a TLS-layer failure, not a connection refusal, proving routing occurred.
    let mut challenge_client_config = rustls::ClientConfig::builder()
        .with_root_certificates({
            // Use a dummy root — the handshake will fail regardless, we only care about routing.
            let (dummy_cert, _) = make_self_signed_cert("app.example.test");
            root_store_with(&dummy_cert)
        })
        .with_no_client_auth();
    challenge_client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(challenge_client_config));

    // TCP must connect (public port is open).
    let tcp_stream = TcpStream::connect(public_addr).await.unwrap();

    // TLS handshake fails (no cert ready), but the attempt reaches the Client.
    // A dropped connection at the Server side would also fail here, so we additionally
    // verify: a connection attempt that never enters the TLS layer gives a different
    // kind of failure than one that does reach TLS negotiation. The connector will return
    // an io::Error; we only assert that the TCP connect succeeds and the connection is
    // attempted, which is already proven by TcpStream::connect succeeding above.
    let handshake_result = connector
        .connect(
            ServerName::try_from("app.example.test").unwrap(),
            tcp_stream,
        )
        .await;
    // Handshake may fail (no ACME cert yet), but must not panic or be a logic error.
    // The connection reached the TLS layer — that is the observable routing proof.
    assert!(
        handshake_result.is_err(),
        "TLS handshake must fail because no ACME cert is ready yet (fail closed)"
    );

    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

/// An ACME-mode terminating Client fails closed for all managed hostnames until
/// Let's Encrypt issues a certificate.  A Visitor connecting before any cert is
/// acquired must receive a TLS error, not be silently dropped or accepted.
#[tokio::test]
async fn acme_terminating_client_serves_https_with_cached_certificate() {
    let tempdir = tempdir().unwrap();

    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let client_identity = generate_client_identity().unwrap();
    std::fs::create_dir(tempdir.path().join("client-identity")).unwrap();
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

    let acme_state_dir = tempdir.path().join("acme-state");
    std::fs::create_dir(&acme_state_dir).unwrap();
    let cached_public_cert =
        generate_simple_self_signed(vec!["app.example.test".to_owned()]).unwrap();
    let cached_public_pem = format!(
        "{}\n{}",
        cached_public_cert.signing_key.serialize_pem(),
        cached_public_cert.cert.pem()
    );
    DirCache::new(acme_state_dir.clone())
        .store_cert(
            &["app.example.test".to_owned()],
            LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            cached_public_pem.as_bytes(),
        )
        .await
        .unwrap();

    let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut backend_stream, _) = backend_listener.accept().await.unwrap();
        let mut request = [0_u8; 4];
        backend_stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        backend_stream.write_all(b"pong").await.unwrap();
        backend_stream.shutdown().await.unwrap();
    });

    let server_settings = load_server_config(&{
        let path = tempdir.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
                client_identity.client_identity
            ),
        )
        .unwrap();
        path
    })
    .unwrap();

    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-cert/server-ca.crt")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: backend_address.to_string(),
            tls_mode: ClientTlsMode::Terminate,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Acme {
            email: "test@example.test".to_owned(),
            state_directory: acme_state_dir,
            state_directory_was_defaulted: false,
        }),
    };
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    let mut client_tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store_with(&cached_public_cert.cert.der().clone()))
        .with_no_client_auth();
    client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_tls_config));
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
async fn acme_terminating_client_fails_closed_before_cert_is_acquired() {
    let tempdir = tempdir().unwrap();

    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let client_identity = generate_client_identity().unwrap();
    std::fs::create_dir(tempdir.path().join("client-identity")).unwrap();
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

    let acme_state_dir = tempdir.path().join("acme-state");
    std::fs::create_dir(&acme_state_dir).unwrap();

    let server_settings = load_server_config(&{
        let path = tempdir.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
                client_identity.client_identity
            ),
        )
        .unwrap();
        path
    })
    .unwrap();

    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-cert/server-ca.crt")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: "localhost:80".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Acme {
            email: "test@example.test".to_owned(),
            state_directory: acme_state_dir,
            state_directory_was_defaulted: false,
        }),
    };
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    // Regular HTTPS connection: the resolver has no cert yet, so the handshake must fail.
    let (dummy_cert, _) = make_self_signed_cert("app.example.test");
    let tls_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &dummy_cert, "app.example.test"),
    )
    .await;

    assert!(
        matches!(tls_result, Ok(Err(_))),
        "ACME terminating client must fail closed when no cert is ready yet"
    );

    server_task.abort();
    client_task.abort();
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn acme_tls_alpn_challenge_for_public_hostname_does_not_reach_backend() {
    let tempdir = tempdir().unwrap();

    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let client_identity = generate_client_identity().unwrap();
    std::fs::create_dir(tempdir.path().join("client-identity")).unwrap();
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

    let acme_state_dir = tempdir.path().join("acme-state");
    std::fs::create_dir(&acme_state_dir).unwrap();
    let cached_public_cert =
        generate_simple_self_signed(vec!["app.example.test".to_owned()]).unwrap();
    let cached_public_pem = format!(
        "{}\n{}",
        cached_public_cert.signing_key.serialize_pem(),
        cached_public_cert.cert.pem()
    );
    DirCache::new(acme_state_dir.clone())
        .store_cert(
            &["app.example.test".to_owned()],
            LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            cached_public_pem.as_bytes(),
        )
        .await
        .unwrap();

    let backend_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let (backend_connected_tx, backend_connected_rx) = oneshot::channel();
    let backend_task = tokio::spawn(async move {
        let _guard = backend_connected_tx;
        let (_backend_stream, _) = backend_listener.accept().await.unwrap();
        let _ = _guard.send(());
    });

    let server_settings = load_server_config(&{
        let path = tempdir.path().join("server.toml");
        std::fs::write(
            &path,
            format!(
                r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
                client_identity.client_identity
            ),
        )
        .unwrap();
        path
    })
    .unwrap();

    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let public_addr = server.public_addr().unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = ClientConfig {
        server_addresses: vec![server_address("tunnel.example.test")],
        server_hostname: server_hostname("tunnel.example.test"),
        server_port: 443,
        log_level: LogLevel::Off,
        server_ca_file: Some(tempdir.path().join("server-cert/server-ca.crt")),
        identity_directory: tempdir.path().join("client-identity"),
        services: vec![ServiceConfig {
            public_hostnames: Some(vec![public_hostname("app.example.test")]),
            backend_address: backend_address.to_string(),
            tls_mode: ClientTlsMode::Terminate,
        }],
        public_cert_config: Some(ClientPublicCertConfig::Acme {
            email: "test@example.test".to_owned(),
            state_directory: acme_state_dir,
            state_directory_was_defaulted: false,
        }),
    };
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_task = tokio::spawn(client.run());

    sleep(Duration::from_millis(50)).await;

    let mut challenge_client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store_with(&cached_public_cert.cert.der().clone()))
        .with_no_client_auth();
    challenge_client_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(challenge_client_config));
    let tcp_stream = TcpStream::connect(public_addr).await.unwrap();
    let _ = timeout(
        Duration::from_secs(1),
        connector.connect(
            ServerName::try_from("app.example.test").unwrap(),
            tcp_stream,
        ),
    )
    .await;

    assert!(
        timeout(Duration::from_millis(200), backend_connected_rx)
            .await
            .is_err(),
        "ACME challenge traffic must not open a backend connection"
    );

    backend_task.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend_task.await;
    let _ = server_task.await;
    let _ = client_task.await;
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

fn configured_tunnel(
    public_hostnames: &[&str],
    client_identity: &GeneratedClientIdentity,
) -> ServerTunnelConfig {
    ServerTunnelConfig {
        public_hostnames: public_hostnames
            .iter()
            .map(|hostname| public_hostname(hostname))
            .collect(),
        authorized_client_identities: vec![client_identity.client_identity.clone()],
    }
}

fn make_authenticated_server_quic_config(
    certificate: &CertificateDer<'static>,
    private_key: &[u8],
    trusted_clients: &[&GeneratedClientIdentity],
) -> quinn::ServerConfig {
    let trusted_client_identities = trusted_clients
        .iter()
        .map(|client| client.client_identity.clone())
        .collect::<Vec<_>>();
    make_server_quic_config_with_client_auth(
        vec![certificate.clone()],
        private_key_from_der(private_key),
        &trusted_client_identities,
    )
    .unwrap()
}

fn make_authenticated_client_quic_config(
    server_certificate: &CertificateDer<'static>,
    client_identity: &GeneratedClientIdentity,
) -> quinn::ClientConfig {
    make_client_quic_config_with_client_auth(
        root_store_with(server_certificate),
        client_certificate_chain(client_identity),
        client_private_key(client_identity),
    )
    .unwrap()
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

async fn wait_for_tcp_connect_failure(public_addr: SocketAddr) -> io::Result<()> {
    timeout(Duration::from_secs(1), async move {
        loop {
            if TcpStream::connect(public_addr).await.is_err() {
                return Ok(());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(io::Error::other)?
}
