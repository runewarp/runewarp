use std::fs;
use std::net::{Ipv4Addr, SocketAddr};

use rcgen::generate_simple_self_signed;
use runewarp::{PreparedServer, load_server_settings};
use tempfile::tempdir;

#[tokio::test]
async fn prepared_server_binds_the_existing_runtime_from_validated_settings() {
    let tempdir = tempdir().unwrap();
    let cert = generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    fs::write(tempdir.path().join("server.crt"), cert.cert.pem()).unwrap();
    fs::write(
        tempdir.path().join("server.key"),
        cert.signing_key.serialize_pem(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-file = "server.crt"
key-file = "server.key"

[[server.tunnels]]
client-public-key-fingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
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
