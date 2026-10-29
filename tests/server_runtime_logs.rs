use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use runewarp::{ServerRuntime, initialize_manual_server_certificate, load_server_config};
#[path = "common/log_capture.rs"]
mod log_capture;
use log_capture::Logs;

#[tokio::test]
async fn server_runtime_logs_identify_each_start_before_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    let logs = Logs::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    )?;
    let directory = tempfile::tempdir()?;
    initialize_manual_server_certificate(&directory.path().join("cert"), "tunnel.example.test")?;
    let config_path = directory.path().join("config.toml");
    std::fs::write(
        &config_path,
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "cert"
readiness-bind-address = "127.0.0.1:0"
[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )?;
    let config = load_server_config(&config_path)?;
    let addresses: Vec<SocketAddr> = vec!["127.0.0.1:0".parse()?, "[::1]:0".parse()?];
    let mut generations = Vec::new();
    let mut previous_connection_id = 0;
    for _ in 0..2 {
        let offset = logs.read().len();
        let runtime =
            ServerRuntime::prepare_listeners(&config, addresses.clone(), addresses.clone()).await?;
        let public = runtime.public_addr()?;
        let trigger = runtime.shutdown();
        let task = tokio::spawn(runtime.run());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut tls = rustls::ClientConnection::new(
            Arc::new(tls_config),
            rustls::pki_types::ServerName::try_from("app.example.test")?,
        )?;
        let mut hello = Vec::new();
        tls.write_tls(&mut hello)?;
        let mut visitor = tokio::net::TcpStream::connect(public).await?;
        visitor.write_all(&hello).await?;
        let _ = tokio::time::timeout(Duration::from_secs(2), visitor.read(&mut [0])).await?;
        trigger.begin_fast();
        tokio::time::timeout(Duration::from_secs(2), task).await???;
        let output = logs.read();
        let lines: Vec<_> = output[offset..].lines().collect();
        let starts: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains("server runtime started"))
            .collect();
        assert_eq!(starts.len(), 1, "one startup per runtime: {lines:?}");
        let (start_index, line) = starts[0];
        let generation = line
            .strip_prefix(" INFO server runtime started: server-generation=")
            .or_else(|| line.strip_prefix("INFO server runtime started: server-generation="))
            .expect("stable INFO startup contract");
        let parsed = uuid::Uuid::parse_str(generation)?;
        assert_eq!(parsed.get_version_num(), 7);
        assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
        assert_eq!(parsed.hyphenated().to_string(), generation);
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("server public listener ready"))
                .count(),
            2
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("server tunnel listener ready"))
                .count(),
            2
        );
        for (index, line) in lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains("listener") || line.contains("readiness gained"))
        {
            assert!(start_index < index, "startup must precede {line}");
        }
        let unavailable = lines.iter().find(|line| line.contains("WARN server route unavailable: public-hostname=app.example.test reason=no-active-tunnel-connection")).expect("unavailable route at INFO level");
        assert!(unavailable.contains(&format!("server-generation={generation}")));
        let connection_id: u64 = unavailable
            .split("connection-id=")
            .nth(1)
            .expect("Visitor connection ID")
            .parse()?;
        assert!(
            connection_id > previous_connection_id,
            "IDs never restart within one process"
        );
        previous_connection_id = connection_id;
        generations.push(generation.to_owned());
    }
    assert_ne!(generations[0], generations[1]);
    Ok(())
}
