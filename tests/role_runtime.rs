use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use runewarp::{
    ClientAdmission, ClientConfig, ClientRuntime, ClientTlsMode, LogLevel, ServerAddress,
    ServerRuntime, ServiceConfig, initialize_manual_server_certificate, load_server_config,
};
use tempfile::tempdir;

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[tokio::test]
async fn client_runtime_tears_down_after_shutdown_signal_failure() {
    let server_address = ServerAddress::parse("localhost:9").unwrap();
    let config = ClientConfig {
        server_hostname: server_address.hostname().clone(),
        server_port: server_address.port(),
        server_addresses: vec![server_address],
        log_level: LogLevel::Off,
        server_ca_file: None,
        identity_directory: "/missing/client-identity".into(),
        services: vec![ServiceConfig {
            public_hostnames: None,
            backend_address: "127.0.0.1:443".to_owned(),
            tls_mode: ClientTlsMode::Passthrough,
            proxy_protocol: None,
        }],
        public_cert_config: None,
        control: None,
        admission: ClientAdmission::Static,
    };
    let runtime = ClientRuntime::prepare(&config, localhost(0)).await.unwrap();

    let error = runtime
        .run(async { Err(io::Error::other("signal adapter failed")) })
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "signal adapter failed");
}

#[tokio::test]
async fn server_runtime_owns_preparation_and_orderly_shutdown() {
    let directory = tempdir().unwrap();
    initialize_manual_server_certificate(
        &directory.path().join("server-cert"),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        directory.path().join("config.toml"),
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
    let config = load_server_config(&directory.path().join("config.toml")).unwrap();
    let runtime = ServerRuntime::prepare(&config, localhost(0), localhost(0))
        .await
        .unwrap();
    assert_ne!(runtime.public_addr().unwrap().port(), 0);
    assert_ne!(runtime.tunnel_addr().unwrap().port(), 0);

    runtime.shutdown().begin_fast();
    runtime.run().await.unwrap();
}
