//! Scrape real Server and Client runtimes after Tunnel connect, reject and close.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientAdmission,
    ClientConfig, ClientRuntime, ClientTlsMode, LogLevel, OrderlyShutdown, Server, ServerAddress,
    ServerAdmission, ServerAuthorization, ServerBindConfig, ServerTunnelConfig, ServiceConfig,
    ShutdownMode,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

#[path = "common/log_capture.rs"]
mod log_capture;
use log_capture::Logs;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn logs() -> &'static Logs {
    static LOGS: OnceLock<Logs> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(logs.clone())
                .with_ansi(false)
                .without_time()
                .with_target(false)
                .finish(),
        )
        .expect("one global subscriber per test binary");
        logs
    })
}

async fn scrape(address: SocketAddr) -> Result<String> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics\r\n\r\n")
        .await?;
    let mut response = String::new();
    timeout(Duration::from_secs(5), stream.read_to_string(&mut response)).await??;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("content-type: application/openmetrics-text"),
        "{response}"
    );
    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default())
}

fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (name, value) = line.rsplit_once(' ')?;
            (name == series).then(|| value.parse().ok()).flatten()
        })
}

/// Scrape until every `(series, value)` holds, or fail with the last scrape.
async fn eventually(address: SocketAddr, expected: &[(&str, f64)]) -> Result<String> {
    let mut last = String::new();
    for _ in 0..100 {
        last = scrape(address).await?;
        if expected
            .iter()
            .all(|(series, value)| sample(&last, series) == Some(*value))
        {
            return Ok(last);
        }
        sleep(Duration::from_millis(50)).await;
    }
    let mismatches: Vec<_> = expected
        .iter()
        .map(|(series, value)| format!("{series}: want {value}, got {:?}", sample(&last, series)))
        .collect();
    Err(format!("{mismatches:#?}\n{last}").into())
}

struct Fixture {
    hostname: runewarp::ServerHostname,
    cert: rcgen::CertifiedKey<rcgen::KeyPair>,
    authorized: runewarp::GeneratedClientIdentity,
    authorization: ServerAuthorization,
}

impl Fixture {
    fn new() -> Result<Self> {
        let hostname: runewarp::ServerHostname = "localhost".try_into().expect("literal hostname");
        let authorized = runewarp::generate_client_identity()?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let authorization = ServerAuthorization::from_static_tunnels(
            &hostname,
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec!["app.example.test".try_into().expect("literal hostname")],
                authorized_client_identities: vec![authorized.client_identity.clone()],
            }],
        )?;
        Ok(Self {
            hostname,
            cert,
            authorized,
            authorization,
        })
    }

    async fn bind(
        &self,
        tunnel_bind_addrs: Vec<SocketAddr>,
        metrics_bind_addr: SocketAddr,
    ) -> Result<Server> {
        Ok(Server::bind(ServerBindConfig {
            public_bind_addrs: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
            tunnel_connection_bind_addrs: tunnel_bind_addrs,
            readiness_bind_addr: None,
            metrics_bind_addr: Some(metrics_bind_addr),
            server_hostname: self.hostname.clone(),
            authorization: self.authorization.clone(),
            public_tls_config: None,
            quic_server_config: runewarp::make_server_tunnel_h3_config(
                vec![self.cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(self.cert.signing_key.serialize_der()).into(),
                Arc::new(self.authorization.clone()),
            )?,
            admission: ServerAdmission::Static,
        })
        .await?)
    }

    fn quic_client_config(
        &self,
        identity: &runewarp::GeneratedClientIdentity,
    ) -> Result<quinn::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.cert.der().clone())?;
        Ok(runewarp::make_client_tunnel_h3_config(
            roots,
            CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
                .collect::<std::result::Result<_, _>>()?,
            PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())?,
        )?)
    }
}

/// One free UDP port bound on both loopback families, so `localhost` reaches the Server
/// whichever address the resolver returns first.
fn dual_stack_tunnel_addrs() -> Result<Vec<SocketAddr>> {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = probe.local_addr()?.port();
    drop(probe);
    Ok(vec![
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ])
}

fn ephemeral() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn client_config(
    directory: &std::path::Path,
    fixture: &Fixture,
    tunnel_port: u16,
    metrics_bind_address: SocketAddr,
) -> Result<ClientConfig> {
    client_config_with_backend(
        directory,
        fixture,
        tunnel_port,
        metrics_bind_address,
        "127.0.0.1:9",
    )
}

fn client_config_with_backend(
    directory: &std::path::Path,
    fixture: &Fixture,
    tunnel_port: u16,
    metrics_bind_address: SocketAddr,
    backend_address: &str,
) -> Result<ClientConfig> {
    fs::write(directory.join("server-ca.pem"), fixture.cert.cert.pem())?;
    let identity_directory = directory.join("client-identity");
    fs::create_dir(&identity_directory)?;
    fs::write(
        identity_directory.join(CLIENT_CERT_FILENAME),
        &fixture.authorized.certificate_pem,
    )?;
    fs::write(
        identity_directory.join(CLIENT_KEY_FILENAME),
        &fixture.authorized.private_key_pem,
    )?;
    fs::write(
        identity_directory.join(CLIENT_IDENTITY_FILENAME),
        fixture.authorized.client_identity.to_string(),
    )?;
    let server_address = ServerAddress::parse(&format!("localhost:{tunnel_port}"))?;
    Ok(ClientConfig {
        max_visitor_streams: 16_384,
        graceful_shutdown_duration: Duration::from_secs(5),
        metrics_bind_address: Some(metrics_bind_address),
        server_hostname: server_address.hostname().clone(),
        server_port: server_address.port(),
        server_addresses: vec![server_address],
        log_level: LogLevel::Off,
        log_format: runewarp::LogFormat::Text,
        server_trust: runewarp::ClientServerTrust::CaFile(directory.join("server-ca.pem")),
        identity_directory,
        services: vec![ServiceConfig {
            public_hostnames: None,
            backend_address: backend_address.to_owned(),
            tls_mode: ClientTlsMode::Passthrough,
            proxy_protocol: None,
        }],
        public_cert_config: None,
        control: None,
        admission: ClientAdmission::Static,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrapes_track_tunnel_connect_reject_and_close_on_both_roles() -> Result<()> {
    logs();
    let fixture = Fixture::new()?;
    let tunnel_addrs = dual_stack_tunnel_addrs()?;
    let server = fixture.bind(tunnel_addrs.clone(), ephemeral()).await?;
    let server_metrics = server.metrics_addr().expect("server metrics bound");
    let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });

    let idle = scrape(server_metrics).await?;
    assert_eq!(sample(&idle, "runewarp_server_ready"), Some(1.0));
    assert_eq!(sample(&idle, "runewarp_server_draining"), Some(0.0));
    assert_eq!(
        sample(&idle, "runewarp_server_tunnel_connections"),
        Some(0.0)
    );

    // Connect: a real Client runtime reaches the Server and offers credit.
    let directory = tempfile::tempdir()?;
    let settings = client_config(
        directory.path(),
        &fixture,
        tunnel_addrs[0].port(),
        ephemeral(),
    )?;
    // Dual-stack wildcard: `localhost` may resolve to either loopback family.
    let client =
        ClientRuntime::prepare(&settings, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).await?;
    let client_metrics = client.metrics_addr().expect("client metrics bound");
    let (client_stop, client_stopped) = oneshot::channel::<()>();
    let client_run = client.run(async move {
        let _ = client_stopped.await;
        Ok(ShutdownMode::Graceful)
    });
    tokio::pin!(client_run);
    let connected_and_rejected = async {
        eventually(
            server_metrics,
            &[
                ("runewarp_server_tunnel_connections_accepted_total", 1.0),
                ("runewarp_server_tunnel_connections", 1.0),
                ("runewarp_server_tunnels_connected", 1.0),
                (
                    r#"runewarp_server_admission_in_use{limit="tunnel_connection_global"}"#,
                    1.0,
                ),
            ],
        )
        .await?;
        eventually(
            client_metrics,
            &[
                (
                    r#"runewarp_client_tunnel_connection_attempts_total{outcome="connected"}"#,
                    1.0,
                ),
                ("runewarp_client_tunnel_connections", 1.0),
                ("runewarp_client_visitor_credit_available", 256.0),
                ("runewarp_client_stream_handlers_active", 0.0),
            ],
        )
        .await?;

        // Reject: an identity no Tunnel authorizes fails the pinned-identity handshake.
        let stranger = runewarp::generate_client_identity()?;
        let mut endpoint = quinn::Endpoint::client(ephemeral())?;
        endpoint.set_default_client_config(fixture.quic_client_config(&stranger)?);
        let _ = timeout(
            Duration::from_secs(5),
            endpoint.connect(tunnel_addrs[0], "localhost")?,
        )
        .await?;
        eventually(
            server_metrics,
            &[(
                r#"runewarp_server_tunnel_connections_rejected_total{reason="unauthorized"}"#,
                1.0,
            )],
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::select! {
        result = &mut client_run => {
            return Err(format!("client exited early: {:?}", result.err().map(|e| e.to_string())).into());
        }
        result = connected_and_rejected => {
            if let Err(error) = result {
                return Err(format!("{error}\nclient: {}\nlogs: {}", scrape(client_metrics).await?, logs().read()).into());
            }
        }
    }

    // Close: graceful Client shutdown withdraws and closes its connection.
    client_stop
        .send(())
        .map_err(|()| "client already stopped")?;
    timeout(Duration::from_secs(10), client_run)
        .await?
        .map_err(|error| error.to_string())?;
    let closed = eventually(
        server_metrics,
        &[
            (
                r#"runewarp_server_tunnel_connections_closed_total{reason="closed"}"#,
                1.0,
            ),
            ("runewarp_server_tunnel_connections", 0.0),
            ("runewarp_server_tunnels_connected", 0.0),
            (
                "runewarp_server_tunnel_connection_duration_seconds_count",
                1.0,
            ),
            (
                r#"runewarp_server_admission_in_use{limit="tunnel_connection_global"}"#,
                0.0,
            ),
        ],
    )
    .await?;
    for reason in ["handshake_failed", "pool_full", "shutdown"] {
        let series =
            format!(r#"runewarp_server_tunnel_connections_rejected_total{{reason="{reason}"}}"#);
        assert_eq!(sample(&closed, &series), Some(0.0), "{series}");
    }
    for reason in ["dropped", "replaced", "shutdown"] {
        let series =
            format!(r#"runewarp_server_tunnel_connections_closed_total{{reason="{reason}"}}"#);
        assert_eq!(sample(&closed, &series), Some(0.0), "{series}");
    }

    server_shutdown.begin_fast();
    timeout(Duration::from_secs(5), server_task).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_bind_failure_logs_an_error_and_keeps_serving() -> Result<()> {
    let logs = logs();
    let fixture = Fixture::new()?;
    let occupied = std::net::TcpListener::bind(ephemeral())?;
    let taken = occupied.local_addr()?;
    let server = fixture.bind(vec![ephemeral()], taken).await?;
    assert_eq!(server.metrics_addr(), None);
    let tunnel_addr = server.tunnel_addr()?;
    let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });

    let mut endpoint = quinn::Endpoint::client(ephemeral())?;
    endpoint.set_default_client_config(fixture.quic_client_config(&fixture.authorized)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(tunnel_addr, "localhost")?,
    )
    .await??;
    let tunnel = timeout(
        Duration::from_secs(5),
        runewarp::tunnel::ClientTunnel::establish(
            connection,
            &fixture.hostname,
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
    )
    .await??;
    drop(tunnel);

    let expected = format!(
        "ERROR server metrics listener disabled: config-key=server.metrics-bind-address bind-address={taken}: bind failed:"
    );
    assert!(logs.read().contains(&expected), "{}", logs.read());
    server_shutdown.begin_fast();
    timeout(Duration::from_secs(5), server_task).await???;
    Ok(())
}

fn client_hello(hostname: &str) -> Result<Vec<u8>> {
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut tls = rustls::ClientConnection::new(
        Arc::new(tls_config),
        rustls::pki_types::ServerName::try_from(hostname.to_owned())?,
    )?;
    let mut hello = Vec::new();
    tls.write_tls(&mut hello)?;
    Ok(hello)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scrapes_track_visitor_stages_latency_and_bytes_on_both_roles() -> Result<()> {
    logs();
    let fixture = Fixture::new()?;
    let tunnel_addrs = dual_stack_tunnel_addrs()?;
    let server = fixture.bind(tunnel_addrs.clone(), ephemeral()).await?;
    let server_metrics = server.metrics_addr().expect("server metrics bound");
    let public = server.public_addr()?;
    let shutdown = OrderlyShutdown::new(Duration::ZERO, Duration::ZERO);
    let server_shutdown = shutdown.clone();
    let server_task = tokio::spawn(async move { server.run_with_shutdown(&shutdown).await });

    // A plain TCP backend: passthrough forwards the Visitor's bytes untouched.
    let backend = tokio::net::TcpListener::bind(ephemeral()).await?;
    let backend_address = backend.local_addr()?.to_string();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        stream.write_all(b"pong").await?;
        stream.shutdown().await?;
        Ok::<_, std::io::Error>(received.len())
    });

    let directory = tempfile::tempdir()?;
    let settings = client_config_with_backend(
        directory.path(),
        &fixture,
        tunnel_addrs[0].port(),
        ephemeral(),
        &backend_address,
    )?;
    let client =
        ClientRuntime::prepare(&settings, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))).await?;
    let client_metrics = client.metrics_addr().expect("client metrics bound");
    let (client_stop, client_stopped) = oneshot::channel::<()>();
    let client_run = client.run(async move {
        let _ = client_stopped.await;
        Ok(ShutdownMode::Fast)
    });
    tokio::pin!(client_run);

    let hello = client_hello("app.example.test")?;
    let visitors = async {
        eventually(
            server_metrics,
            &[("runewarp_server_tunnels_connected", 1.0)],
        )
        .await?;

        // An unauthorized hostname is rejected with a typed reason.
        let mut stranger = TcpStream::connect(public).await?;
        stranger
            .write_all(&client_hello("other.example.test")?)
            .await?;
        let _ = timeout(Duration::from_secs(5), stranger.read(&mut [0])).await?;

        let mut visitor = TcpStream::connect(public).await?;
        visitor.write_all(&hello).await?;
        visitor.write_all(b"ping").await?;
        visitor.shutdown().await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), visitor.read_to_end(&mut response)).await??;
        assert_eq!(response, b"pong");
        let received = timeout(Duration::from_secs(5), backend_task).await???;
        assert_eq!(received, hello.len() + 4);

        let visitor_bytes = (hello.len() + 4) as f64;
        let server_text = eventually(
            server_metrics,
            &[
                ("runewarp_server_visitors_accepted_total", 2.0),
                (
                    r#"runewarp_server_visitors_rejected_total{reason="unauthorized_hostname"}"#,
                    1.0,
                ),
                ("runewarp_server_visitors_placed_total", 1.0),
                (
                    r#"runewarp_server_visitors_closed_total{outcome="ok"}"#,
                    1.0,
                ),
                ("runewarp_server_visitors_active", 0.0),
                (
                    r#"runewarp_server_visitor_bytes_total{direction="from_visitor"}"#,
                    visitor_bytes,
                ),
                (
                    r#"runewarp_server_visitor_bytes_total{direction="to_visitor"}"#,
                    4.0,
                ),
                ("runewarp_server_visitor_duration_seconds_count", 1.0),
                (
                    "runewarp_server_visitor_stream_open_duration_seconds_count",
                    1.0,
                ),
            ],
        )
        .await?;
        let rejected: f64 = server_text
            .lines()
            .filter(|line| line.starts_with("runewarp_server_visitors_rejected_total{"))
            .filter_map(|line| line.rsplit_once(' ')?.1.parse::<f64>().ok())
            .sum();
        assert_eq!(rejected, 1.0, "{server_text}");
        eventually(
            client_metrics,
            &[
                ("runewarp_client_visitors_handled_total", 1.0),
                ("runewarp_client_visitors_active", 0.0),
                (
                    "runewarp_client_backend_connect_duration_seconds_count",
                    1.0,
                ),
                ("runewarp_client_backend_connect_failures_total", 0.0),
                (
                    r#"runewarp_client_backend_bytes_total{direction="to_backend"}"#,
                    visitor_bytes,
                ),
                (
                    r#"runewarp_client_backend_bytes_total{direction="from_backend"}"#,
                    4.0,
                ),
            ],
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::select! {
        result = &mut client_run => {
            return Err(format!("client exited early: {:?}", result.err().map(|e| e.to_string())).into());
        }
        result = visitors => {
            if let Err(error) = result {
                return Err(format!("{error}\nclient: {}\nlogs: {}", scrape(client_metrics).await?, logs().read()).into());
            }
        }
    }

    client_stop
        .send(())
        .map_err(|()| "client already stopped")?;
    timeout(Duration::from_secs(10), client_run)
        .await?
        .map_err(|error| error.to_string())?;
    server_shutdown.begin_fast();
    timeout(Duration::from_secs(5), server_task).await???;
    Ok(())
}
