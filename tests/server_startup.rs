use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    PreparedClient, PreparedServer, generate_client_identity, initialize_manual_server_certificate,
    load_client_config, load_server_config,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_acme::CertCache;
use rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY;
use rustls_acme::caches::DirCache;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod common;

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

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
    let server = PreparedServer::bind(&settings, localhost(0), localhost(0))
        .await
        .unwrap();

    assert_ne!(server.public_addr().unwrap().port(), 0);
    assert_ne!(server.tunnel_addr().unwrap().port(), 0);
}

#[tokio::test]
async fn prepared_server_binds_listener_addresses_loaded_from_settings() {
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
cert-dir = "server-cert"
public-bind-address = "127.0.0.1:0"
tunnel-bind-address = "127.0.0.1:0"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
    let server = PreparedServer::bind(
        &settings,
        settings.public_bind_address,
        settings.tunnel_connection_bind_address,
    )
    .await
    .unwrap();

    assert!(server.public_addr().unwrap().ip().is_loopback());
    assert!(server.tunnel_addr().unwrap().ip().is_loopback());
}

#[tokio::test]
async fn prepared_server_binds_readiness_listener_when_enabled() {
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
cert-dir = "server-cert"
public-bind-address = "127.0.0.1:0"
tunnel-bind-address = "127.0.0.1:0"
readiness-bind-address = "127.0.0.1:0"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
    let server = PreparedServer::bind(
        &settings,
        settings.public_bind_address,
        settings.tunnel_connection_bind_address,
    )
    .await
    .unwrap();

    let readiness_addr = server
        .readiness_addr()
        .expect("readiness listener should bind");
    assert!(readiness_addr.ip().is_loopback());
    TcpStream::connect(readiness_addr).await.unwrap();
}

#[tokio::test]
async fn prepared_server_fails_startup_when_readiness_bind_address_is_in_use() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    let readiness_listener = TcpListener::bind(localhost(0)).await.unwrap();
    let readiness_addr = readiness_listener.local_addr().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
readiness-bind-address = "{readiness_addr}"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#
        ),
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
    let error = match PreparedServer::bind(&settings, localhost(0), localhost(0)).await {
        Ok(_) => panic!("expected readiness bind failure"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("failed to bind server.readiness-bind-address")
    );
}

#[tokio::test]
async fn prepared_server_accepts_an_expired_pinned_client_identity_certificate() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let (client_identity, certificate_pem, private_key_pem) =
        common::expired_client_identity_material();
    let certificate_der =
        rustls_pemfile::certs(&mut std::io::Cursor::new(certificate_pem.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der.as_ref()).unwrap();
    assert!(
        certificate.validity().not_after.to_datetime() < OffsetDateTime::now_utc(),
        "test certificate must already be expired"
    );

    fs::write(tempdir.path().join("client.crt"), certificate_pem).unwrap();
    fs::write(tempdir.path().join("client.key"), private_key_pem).unwrap();
    fs::write(
        tempdir.path().join("client-identity.txt"),
        client_identity.to_string(),
    )
    .unwrap();

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{client_identity}"
"#
        ),
    )
    .unwrap();

    let backend = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"pong").await;

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "."

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

    let app_response = request_tls_response(public_addr, &backend.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(app_response, *b"pong");

    backend.2.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend.2.await;
    let _ = server_task.await;
    let _ = client_task.await;
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

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "."

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
async fn prepared_server_drops_public_tls_for_unconfigured_public_hostnames() {
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

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"
"#,
            client_identity.client_identity
        ),
    )
    .unwrap();

    let backend = spawn_tls_backend(
        vec![
            "app.example.test".to_owned(),
            "other.example.test".to_owned(),
        ],
        *b"pong",
    )
    .await;

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "."

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

    let app_response = request_tls_response(public_addr, &backend.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(app_response, *b"pong");

    let unknown_hostname_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &backend.1, "other.example.test"),
    )
    .await;
    assert!(matches!(unknown_hostname_result, Ok(Err(_))));

    backend.2.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend.2.await;
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn prepared_client_routes_mirrored_public_hostnames_to_matching_services() {
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

    let app_backend = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"app!").await;
    let api_backend = spawn_tls_backend(vec!["api.example.test".to_owned()], *b"api!").await;

    fs::write(
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

    fs::write(
        tempdir.path().join("client.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "."

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "{}"

[[client.services]]
public-hostnames = ["api.example.test"]
backend-address = "{}"
"#,
            app_backend.0, api_backend.0
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

    let app_response = request_tls_response(public_addr, &app_backend.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(app_response, *b"app!");

    let api_response = request_tls_response(public_addr, &api_backend.1, "api.example.test")
        .await
        .unwrap();
    assert_eq!(api_response, *b"api!");

    app_backend.2.abort();
    api_backend.2.abort();
    server_task.abort();
    client_task.abort();
    let _ = app_backend.2.await;
    let _ = api_backend.2.await;
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn prepared_client_rejects_streams_without_a_matching_service() {
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

    let backend = spawn_tls_backend(
        vec!["app.example.test".to_owned(), "api.example.test".to_owned()],
        *b"pong",
    )
    .await;

    fs::write(
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

    fs::write(
        tempdir.path().join("client.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "."

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "{}"
"#,
            backend.0
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

    let app_response = request_tls_response(public_addr, &backend.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(app_response, *b"pong");

    let api_result = timeout(
        Duration::from_secs(1),
        request_tls_response(public_addr, &backend.1, "api.example.test"),
    )
    .await;
    assert!(matches!(api_result, Ok(Err(_))));

    backend.2.abort();
    server_task.abort();
    client_task.abort();
    let _ = backend.2.await;
    let _ = server_task.await;
    let _ = client_task.await;
}

#[tokio::test]
async fn prepared_server_routes_different_public_hostnames_to_different_tunnels() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let app_client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-app")).unwrap();
    fs::write(
        tempdir.path().join("client-app/client.crt"),
        app_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-app/client.key"),
        app_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-app/client-identity.txt"),
        app_client_identity.client_identity.to_string(),
    )
    .unwrap();

    let api_client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-api")).unwrap();
    fs::write(
        tempdir.path().join("client-api/client.crt"),
        api_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-api/client.key"),
        api_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-api/client-identity.txt"),
        api_client_identity.client_identity.to_string(),
    )
    .unwrap();

    let app_backend = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"app!").await;
    let api_backend = spawn_tls_backend(vec!["api.example.test".to_owned()], *b"api!").await;

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"

[[server.tunnels]]
public-hostnames = ["api.example.test"]
client-identity = "{}"
"#,
            app_client_identity.client_identity, api_client_identity.client_identity
        ),
    )
    .unwrap();

    fs::write(
        tempdir.path().join("client-app.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-app"

[[client.services]]
backend-address = "{}"
"#,
            app_backend.0
        ),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-api.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-api"

[[client.services]]
backend-address = "{}"
"#,
            api_backend.0
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

    let app_client_settings = load_client_config(&tempdir.path().join("client-app.toml")).unwrap();
    let app_client = PreparedClient::connect_to(&app_client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let app_client_task = tokio::spawn(app_client.run());

    let api_client_settings = load_client_config(&tempdir.path().join("client-api.toml")).unwrap();
    let api_client = PreparedClient::connect_to(&api_client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let api_client_task = tokio::spawn(api_client.run());

    let app_response = request_tls_response(public_addr, &app_backend.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(app_response, *b"app!");

    let api_response = request_tls_response(public_addr, &api_backend.1, "api.example.test")
        .await
        .unwrap();
    assert_eq!(api_response, *b"api!");

    app_backend.2.abort();
    api_backend.2.abort();
    server_task.abort();
    app_client_task.abort();
    api_client_task.abort();
    let _ = app_backend.2.await;
    let _ = api_backend.2.await;
    let _ = server_task.await;
    let _ = app_client_task.await;
    let _ = api_client_task.await;
}

#[tokio::test]
async fn pooling_same_tunnel_clients_does_not_disrupt_other_tunnels() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let app_client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-app")).unwrap();
    fs::write(
        tempdir.path().join("client-app/client.crt"),
        app_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-app/client.key"),
        app_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-app/client-identity.txt"),
        app_client_identity.client_identity.to_string(),
    )
    .unwrap();

    let api_client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-api")).unwrap();
    fs::write(
        tempdir.path().join("client-api/client.crt"),
        api_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-api/client.key"),
        api_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-api/client-identity.txt"),
        api_client_identity.client_identity.to_string(),
    )
    .unwrap();

    let app_backend_one = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"one!").await;
    let app_backend_two = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"two!").await;
    let api_backend = spawn_tls_backend(vec!["api.example.test".to_owned()], *b"api!").await;

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "{}"

[[server.tunnels]]
public-hostnames = ["api.example.test"]
client-identity = "{}"
"#,
            app_client_identity.client_identity, api_client_identity.client_identity
        ),
    )
    .unwrap();

    fs::write(
        tempdir.path().join("client-app-one.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-app"

[[client.services]]
backend-address = "{}"
"#,
            app_backend_one.0
        ),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-app-two.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-app"

[[client.services]]
backend-address = "{}"
"#,
            app_backend_two.0
        ),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-api.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-api"

[[client.services]]
backend-address = "{}"
"#,
            api_backend.0
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

    let app_client_one_settings =
        load_client_config(&tempdir.path().join("client-app-one.toml")).unwrap();
    let app_client_one =
        PreparedClient::connect_to(&app_client_one_settings, localhost(0), tunnel_addr)
            .await
            .unwrap();
    let app_client_one_task = tokio::spawn(app_client_one.run());

    let api_client_settings = load_client_config(&tempdir.path().join("client-api.toml")).unwrap();
    let api_client = PreparedClient::connect_to(&api_client_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let api_client_task = tokio::spawn(api_client.run());

    let first_app_response =
        request_tls_response(public_addr, &app_backend_one.1, "app.example.test")
            .await
            .unwrap();
    assert_eq!(first_app_response, *b"one!");
    let first_api_response = request_tls_response(public_addr, &api_backend.1, "api.example.test")
        .await
        .unwrap();
    assert_eq!(first_api_response, *b"api!");

    let app_client_two_settings =
        load_client_config(&tempdir.path().join("client-app-two.toml")).unwrap();
    let app_client_two =
        PreparedClient::connect_to(&app_client_two_settings, localhost(0), tunnel_addr)
            .await
            .unwrap();
    let app_client_two_task = tokio::spawn(app_client_two.run());

    let pooled_app_response = timeout(Duration::from_secs(1), async {
        loop {
            match request_tls_response(public_addr, &app_backend_two.1, "app.example.test").await {
                Ok(response) => return response,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("timed out waiting for the second app pool member to serve traffic");
    assert_eq!(pooled_app_response, *b"two!");

    let rotated_app_response =
        request_tls_response(public_addr, &app_backend_one.1, "app.example.test")
            .await
            .unwrap();
    assert_eq!(rotated_app_response, *b"one!");

    let second_api_response = request_tls_response(public_addr, &api_backend.1, "api.example.test")
        .await
        .unwrap();
    assert_eq!(second_api_response, *b"api!");

    app_backend_one.2.abort();
    app_backend_two.2.abort();
    api_backend.2.abort();
    server_task.abort();
    app_client_one_task.abort();
    app_client_two_task.abort();
    api_client_task.abort();
    let _ = app_backend_one.2.await;
    let _ = app_backend_two.2.await;
    let _ = api_backend.2.await;
    let _ = server_task.await;
    let _ = app_client_one_task.await;
    let _ = app_client_two_task.await;
    let _ = api_client_task.await;
}

#[tokio::test]
async fn different_authorized_client_identities_can_share_the_same_tunnel_pool() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();

    let first_client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-one")).unwrap();
    fs::write(
        tempdir.path().join("client-one/client.crt"),
        first_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-one/client.key"),
        first_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-one/client-identity.txt"),
        first_client_identity.client_identity.to_string(),
    )
    .unwrap();

    let second_client_identity = generate_client_identity().unwrap();
    fs::create_dir(tempdir.path().join("client-two")).unwrap();
    fs::write(
        tempdir.path().join("client-two/client.crt"),
        second_client_identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-two/client.key"),
        second_client_identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-two/client-identity.txt"),
        second_client_identity.client_identity.to_string(),
    )
    .unwrap();

    let app_backend_one = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"one!").await;
    let app_backend_two = spawn_tls_backend(vec!["app.example.test".to_owned()], *b"two!").await;

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identities = ["{}", "{}"]
"#,
            first_client_identity.client_identity, second_client_identity.client_identity
        ),
    )
    .unwrap();

    fs::write(
        tempdir.path().join("client-one.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-one"

[[client.services]]
backend-address = "{}"
"#,
            app_backend_one.0
        ),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-two.toml"),
        format!(
            r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "client-two"

[[client.services]]
backend-address = "{}"
"#,
            app_backend_two.0
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

    let client_one_settings = load_client_config(&tempdir.path().join("client-one.toml")).unwrap();
    let client_one = PreparedClient::connect_to(&client_one_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_one_task = tokio::spawn(client_one.run());

    let first_response = request_tls_response(public_addr, &app_backend_one.1, "app.example.test")
        .await
        .unwrap();
    assert_eq!(first_response, *b"one!");

    let client_two_settings = load_client_config(&tempdir.path().join("client-two.toml")).unwrap();
    let client_two = PreparedClient::connect_to(&client_two_settings, localhost(0), tunnel_addr)
        .await
        .unwrap();
    let client_two_task = tokio::spawn(client_two.run());

    let pooled_response = timeout(Duration::from_secs(1), async {
        loop {
            match request_tls_response(public_addr, &app_backend_two.1, "app.example.test").await {
                Ok(response) => return response,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("timed out waiting for the second authorized identity to join the tunnel pool");
    assert_eq!(pooled_response, *b"two!");

    let rotated_response =
        request_tls_response(public_addr, &app_backend_one.1, "app.example.test")
            .await
            .unwrap();
    assert_eq!(rotated_response, *b"one!");

    app_backend_one.2.abort();
    app_backend_two.2.abort();
    server_task.abort();
    client_one_task.abort();
    client_two_task.abort();
    let _ = app_backend_one.2.await;
    let _ = app_backend_two.2.await;
    let _ = server_task.await;
    let _ = client_one_task.await;
    let _ = client_two_task.await;
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

cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "."

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
state-dir = "acme-state"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
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
state-dir = "acme-state"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
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
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-dir = "."

[[client.services]]
backend-address = "127.0.0.1:1"
"#,
    )
    .unwrap();

    let server_settings = load_server_config(&tempdir.path().join("server.toml")).unwrap();
    let server = PreparedServer::bind(&server_settings, localhost(0), localhost(0))
        .await
        .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_settings = load_client_config(&tempdir.path().join("client.toml")).unwrap();
    let client = timeout(Duration::from_secs(3), async {
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
