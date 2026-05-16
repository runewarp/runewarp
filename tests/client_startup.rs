use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use runewarp::{
    ClientSettings, PreparedClient, Server, ServerConfig, generate_client_identity,
    load_client_settings, make_server_quic_config,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::tempdir;

#[tokio::test]
async fn prepared_client_connects_from_validated_settings() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![server_cert],
            private_key_from_der(&server_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_identity = generate_client_identity().unwrap();
    fs::write(tempdir.path().join("server-ca.pem"), server_cert_pem).unwrap();
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
        tempdir.path().join("config.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
server-ca-file = "server-ca.pem"
cert-file = "client.crt"
key-file = "client.key"

[[client.services]]
local-addr = "localhost:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();
    let client = PreparedClient::connect_to(&settings, localhost(0), tunnel_addr)
        .await
        .unwrap();

    assert_ne!(client.local_addr().unwrap().port(), 0);

    server_task.abort();
    let _ = server_task.await;
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(der.to_vec()).into()
}

#[tokio::test]
async fn prepared_client_rejects_settings_without_a_catch_all_service() {
    let tempdir = tempdir().unwrap();
    let certified_server =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_cert_pem = certified_server.cert.pem();
    let server_cert = CertificateDer::from(certified_server.cert);
    let server_key = certified_server.signing_key.serialize_der();
    let server = Server::bind(ServerConfig {
        public_bind_addr: localhost(0),
        tunnel_bind_addr: localhost(0),
        server_hostname: "tunnel.example.test".to_owned(),
        quic_server_config: make_server_quic_config(
            vec![server_cert],
            private_key_from_der(&server_key),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    let tunnel_addr = server.tunnel_addr().unwrap();
    let server_task = tokio::spawn(server.run());

    let client_identity = generate_client_identity().unwrap();
    fs::write(tempdir.path().join("server-ca.pem"), server_cert_pem).unwrap();
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

    let settings = ClientSettings {
        server_hostname: "tunnel.example.test".to_owned(),
        server_ca_file: Some(tempdir.path().join("server-ca.pem")),
        cert_file: tempdir.path().join("client.crt"),
        key_file: tempdir.path().join("client.key"),
        retry_interval: Duration::from_secs(5),
        services: Vec::new(),
    };

    let join = tokio::spawn(async move {
        PreparedClient::connect_to(&settings, localhost(0), tunnel_addr).await
    })
    .await;

    let error = match join {
        Ok(Err(error)) => error,
        Ok(Ok(_)) => panic!("expected client startup to reject missing services"),
        Err(error) => panic!("expected a client startup error, got panic: {error}"),
    };
    assert!(
        error
            .to_string()
            .contains("client settings must include exactly one Catch-all Service")
    );

    server_task.abort();
    let _ = server_task.await;
}
