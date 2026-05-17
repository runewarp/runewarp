use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    PreparedClient, PreparedServer, generate_client_identity, initialize_manual_server_certificate,
    load_client_settings, load_server_settings,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_acme::CertCache;
use rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;
use rustls_acme::caches::DirCache;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn prepared_server_binds_the_existing_runtime_from_validated_settings() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_settings(&tempdir.path().join("config.toml")).unwrap();
    let server = PreparedServer::bind(&settings, localhost(0), localhost(0))
        .await
        .unwrap();

    assert_ne!(server.public_addr().unwrap().port(), 0);
    assert_ne!(server.tunnel_addr().unwrap().port(), 0);
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[tokio::test]
async fn prepared_server_drops_public_tls_addressed_to_the_server_hostname() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let client_identity = generate_client_identity().unwrap();
    fs::write(
        tempdir.path().join("client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
client-identity = "{}"
"#,
            client_identity.client_identity
        ),
    )
    .unwrap();

    let backend = spawn_tls_backend(
        vec![
            "app.example.test".to_owned(),
            "tunnel.example.test".to_owned(),
        ],
        *b"pong",
    )
    .await;

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-cert/server-ca.crt"
identity-directory = "."

[[client.services]]
backend-address = "__BACKEND_ADDR__"
"#
        .replace("__BACKEND_ADDR__", &backend.0.to_string()),
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

    let app_response = request_tls_response(public_addr, &backend.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(app_response, *b"pong");

    let server_hostname_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &backend.1, "tunnel.example.test"),
    )
    .await;
    assert!(matches!(server_hostname_result, Ok(Err(_))));

    backend.2.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend.2.await;
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn prepared_server_rejects_an_untrusted_client_identity_before_serving_public_tls() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let trusted_client_identity = generate_client_identity().unwrap();
    let untrusted_client_identity = generate_client_identity().unwrap();
    fs::write(
        tempdir.path().join("client.crt"),
        untrusted_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client.key"),
        untrusted_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity.txt"),
        untrusted_client_identity.client_identity.to_string(),
    )
    .unwrap();

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
client-identity = "{}"
"#,
            trusted_client_identity.client_identity
        ),
    )
    .unwrap();

    let backend = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"pong").await;

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-cert/server-ca.crt"
identity-directory = "."

[[client.services]]
backend-address = "__BACKEND_ADDR__"
"#
        .replace("__BACKEND_ADDR__", &backend.0.to_string()),
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
    let client = PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr).await;
    let client_task = client.ok().map(|client| tokio::spawn(client.run()));

    let visitor_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &backend.1, "app.example.test"),
    )
    .await;
    assert!(
        matches!(visitor_result, Ok(Err(_))),
        "an untrusted client identity must never become the active tunnel"
    );

    backend.2.abort();
    server_task.abort();
    if let Some(client_task) = client_task {
        client_task.abort();
        let _ = client_task.await;
    }
    let _ = backend.2.await;
    let _ = server_task.await;
}

#[tokio::test]
async fn prepared_server_binds_acme_settings_without_cached_tls_material() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.acme]
email = "admin@example.test"
state-directory = "acme-state"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_settings(&tempdir.path().join("config.toml")).unwrap();
    let server = PreparedServer::bind(&settings, localhost(0), localhost(0))
        .await
        .unwrap();

    assert_ne!(server.public_addr().unwrap().port(), 0);
    assert_ne!(server.tunnel_addr().unwrap().port(), 0);
}

#[tokio::test]
async fn prepared_server_loads_cached_acme_certificates_from_state_directory() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    let cached_server_cert =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let cached_server_pem = format!(
        "{}\n{}",
        cached_server_cert.signing_key.serialize_pem(),
        cached_server_cert.cert.pem()
    );
    DirCache::new(tempdir.path().join("acme-state"))
        .store_cert(
            &["tunnel.example.test".to_owned()],
            LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            cached_server_pem.as_bytes(),
        )
        .await
        .unwrap();

    let client_identity = generate_client_identity().unwrap();
    fs::write(
        tempdir.path().join("client.crt"),
        client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client.key"),
        client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity.txt"),
        client_identity.client_identity.to_string(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("server-ca.pem"),
        cached_server_cert.cert.pem(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

[server.acme]
email = "admin@example.test"
state-directory = "acme-state"

[[server.tunnels]]
client-identity = "{}"
"#,
            client_identity.client_identity
        ),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-ca.pem"
identity-directory = "."

[[client.services]]
backend-address = "127.0.0.1:1"
"#,
    )
    .unwrap();

    let server_settings = load_server_settings(&tempdir.path().join("server.toml")).unwrap();
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = load_client_settings(&tempdir.path().join("client.toml")).unwrap();
    let client = timeout(Duration::from_secs(1), async {
        loop {
            match PreparedClient::connect_to(&client_settings, localhost(0), tunnel_addr).await {
                Ok(client) => return client,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("timed out waiting for the cached ACME certificate to load");

    assert_ne!(client.local_addr().unwrap().port(), 0);

    server_task.abort();
    let _ = server_task.await;
}

async fn spawn_tls_backend(
    server_names: Vec<String>,
    response: [u8; 4],
) -> (
    SocketAddr,
    CertificateDer<'static>,
    tokio::task::JoinHandle<()>,
) {
    let certified_key = generate_simple_self_signed(server_names).unwrap();
    let certificate = CertificateDer::from(certified_key.cert);
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der())
            .into();
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
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

    (addr, certificate, task)
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

fn root_store_with(certificate: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    roots
}
