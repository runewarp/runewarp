//! Explicit release-only, multi-process benchmark entry point. See scripts/benchmark-visitor-capacity.
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(crate) static GUARD_RESETS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static OPEN_TIMEOUTS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static ADMISSION_REJECTIONS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static ADMISSION_BY_LIMIT: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];
pub(crate) static NO_ACTIVE_ROUTE: AtomicUsize = AtomicUsize::new(0);
static BACKEND_ERROR_COUNT: AtomicUsize = AtomicUsize::new(0);
static BACKEND_ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static OPEN_ERROR_COUNT: AtomicUsize = AtomicUsize::new(0);
static OPEN_ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub(crate) fn record_open_error(error: String) {
    if std::env::var_os("RUNEWARP_BENCH_DIR").is_some() {
        OPEN_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
        let mut errors = OPEN_ERRORS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if errors.len() < 16 {
            errors.push(error);
        }
    }
}

pub(crate) fn record_backend_error(error: &std::io::Error) {
    if std::env::var_os("RUNEWARP_BENCH_DIR").is_some() {
        BACKEND_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
        let mut errors = BACKEND_ERRORS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if errors.len() < 16 {
            errors.push(format!(
                "kind={:?} os-code={:?}",
                error.kind(),
                error.raw_os_error()
            ));
        }
    }
}

pub(crate) fn client_hello() -> Result<Vec<u8>, Box<dyn Error>> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("app.example.test")?,
    )?;
    let mut hello = Vec::new();
    client.write_tls(&mut hello)?;
    Ok(hello)
}

pub(crate) fn address(port: u16) -> SocketAddr {
    (Ipv4Addr::LOCALHOST, port).into()
}
fn write_json(path: &Path, value: serde_json::Value) -> Result<(), Box<dyn Error>> {
    // Rename prevents the coordinator from observing a partially written readiness/metrics file.
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, serde_json::to_vec_pretty(&value)?)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}
async fn stopping(directory: &Path) {
    while !directory.join("stop").exists() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
fn counts() -> serde_json::Value {
    serde_json::json!({
        "actual_guard_resets": GUARD_RESETS.load(Ordering::Relaxed),
        "no_active_route": NO_ACTIVE_ROUTE.load(Ordering::Relaxed),
        "open_errors": OPEN_ERROR_COUNT.load(Ordering::Relaxed),
        "backend_connect_errors": BACKEND_ERROR_COUNT.load(Ordering::Relaxed),
        "first_16_backend_errors": BACKEND_ERRORS.lock().unwrap_or_else(|error| error.into_inner()).clone(),
        "first_16_open_errors": OPEN_ERRORS.lock().unwrap_or_else(|error| error.into_inner()).clone(),
        "server_open_timeouts": OPEN_TIMEOUTS.load(Ordering::Relaxed),
        "established_tunnel_connections": CONNECTIONS.load(Ordering::Relaxed),
        "admission_rejections": ADMISSION_REJECTIONS.load(Ordering::Relaxed),
        "admission_by_limit": ADMISSION_BY_LIMIT.each_ref().map(|v| v.load(Ordering::Relaxed)),
    })
}

pub(crate) fn setup(directory: &Path) -> Result<(), Box<dyn Error>> {
    crate::initialize_manual_server_certificate(&directory.join("cert"), "localhost")?;
    let identity = crate::generate_client_identity()?;
    std::fs::create_dir(directory.join("identity"))?;
    std::fs::write(
        directory
            .join("identity")
            .join(crate::CLIENT_IDENTITY_FILENAME),
        identity.client_identity.to_string(),
    )?;
    for (file, bytes) in [
        (
            crate::CLIENT_CERT_FILENAME,
            identity.certificate_pem.as_bytes(),
        ),
        (
            crate::CLIENT_KEY_FILENAME,
            identity.private_key_pem.as_bytes(),
        ),
    ] {
        std::fs::write(directory.join("identity").join(file), bytes)?;
    }
    std::fs::write(
        directory.join("server.toml"),
        format!(
            "[server]\nhostname = \"localhost\"\ncert-dir = \"cert\"\n[[server.tunnels]]\npublic-hostnames = [\"app.example.test\"]\nclient-identity = \"{}\"\n",
            identity.client_identity
        ),
    )?;
    Ok(())
}

#[test]
#[ignore = "multi-process release benchmark; run scripts/benchmark-visitor-capacity"]
fn visitor_capacity_role() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(std::env::var("RUNEWARP_BENCH_DIR")?);
    let role = std::env::var("RUNEWARP_BENCH_ROLE")?;
    let tunnel_bind: SocketAddr = std::env::var("RUNEWARP_BENCH_TUNNEL_BIND")?.parse()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        match role.as_str() {
            "provenance" => {
                write_json(&directory.join("build-provenance.json"), serde_json::json!({
                    "rust_source_sha256": option_env!("RUNEWARP_BENCH_SOURCE_SHA256")
                }))?;
            }
            "setup" => {
                setup(&directory)?;
            }
            "server" => {
                crate::runtime_log::install(crate::LogLevel::Info)?;
                let id = std::env::var("RUNEWARP_BENCH_ID")?;
                let config = crate::load_server_config(&directory.join("server.toml"))?;
                let server = crate::ServerRuntime::prepare(&config, address(0), tunnel_bind).await?;
                write_json(&directory.join(format!("server-{id}.ready")), serde_json::json!({
                    "public": server.public_addr()?.to_string(), "tunnel": server.tunnel_addr()?.to_string()
                }))?;
                let shutdown = server.shutdown();
                tokio::select! {
                    result = server.run() => result?,
                    _ = stopping(&directory) => { shutdown.begin_fast(); }
                }
                write_json(&directory.join(format!("server-{id}.counts.json")), counts())?;
            }
            "client" => {
                crate::runtime_log::install(crate::LogLevel::Info)?;
                let config = crate::load_client_config(&directory.join("client.toml"))?;
                let client = crate::ClientRuntime::prepare(&config, tunnel_bind).await?;
                let announce = async {
                    loop {
                        write_json(&directory.join("client.counts.json"), counts()).expect("write counts");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                };
                tokio::select! {
                    result = client.run(async { stopping(&directory).await; Ok(crate::ShutdownMode::Fast) }) => result?,
                    _ = announce => {}
                }
                write_json(&directory.join("client.counts.json"), counts())?;
            }
            "backend" => {
                let listener = TcpListener::bind("[::1]:0").await?;
                write_json(&directory.join("backend.ready"), serde_json::json!({"address":listener.local_addr()?.to_string()}))?;
                let mut tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut socket, _) = accepted?;
                            tasks.spawn(async move {
                                let (mut read, mut write) = socket.split();
                                let _ = tokio::io::copy(&mut read, &mut write).await;
                            });
                        }
                        _ = tasks.join_next(), if !tasks.is_empty() => {}
                        _ = stopping(&directory) => break,
                    }
                }
                tasks.shutdown().await;
            }
            "load" => load(&directory).await?,
            _ => return Err(format!("unknown benchmark role {role}").into()),
        }
        Ok(())
    })
}

pub(crate) async fn connect_visitor(
    target: SocketAddr,
    hello: Vec<u8>,
    index: usize,
) -> std::io::Result<(TcpStream, f64, usize)> {
    let start = Instant::now();
    let mut socket = TcpStream::connect(target).await?;
    socket.set_nodelay(true)?;
    let mut bytes = hello;
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&[0x5a; 256]);
    socket.write_all(&bytes).await?;
    let mut response = vec![0; bytes.len()];
    socket.read_exact(&mut response[..1]).await?;
    let first_byte_ms = start.elapsed().as_secs_f64() * 1000.;
    socket.read_exact(&mut response[1..]).await?;
    if response != bytes {
        return Err(std::io::Error::other("echo byte mismatch"));
    }
    Ok((socket, first_byte_ms, bytes.len()))
}
async fn load(directory: &Path) -> Result<(), Box<dyn Error>> {
    let count: usize = std::env::var("RUNEWARP_BENCH_COUNT")?.parse()?;
    let batch: usize = std::env::var("RUNEWARP_BENCH_BATCH")?.parse()?;
    let targets: Vec<SocketAddr> = std::env::var("RUNEWARP_BENCH_TARGETS")?
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let transfer = std::env::var("RUNEWARP_BENCH_TRANSFER").is_ok_and(|v| v == "1");
    let slow = std::env::var("RUNEWARP_BENCH_SLOW").is_ok_and(|v| v == "1");
    let hello = client_hello()?;
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..count {
        let target = targets[index % targets.len()];
        let hello = hello.clone();
        tasks.spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(8),
                connect_visitor(target, hello, index),
            )
            .await
        });
        if (index + 1) % batch == 0 && batch < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let mut sockets = Vec::new();
    let mut latencies = Vec::new();
    let mut failures = std::collections::BTreeMap::<String, usize>::new();
    let mut validated_bytes = 0;
    while let Some(result) = tasks.join_next().await {
        match result? {
            Ok(Ok((socket, latency, bytes))) => {
                sockets.push(socket);
                latencies.push(latency);
                validated_bytes += bytes;
            }
            other => *failures.entry(format!("{other:?}")).or_default() += 1,
        }
    }
    let established = sockets.len();
    let establish_seconds = start.elapsed().as_secs_f64();
    let mut slow_writers = tokio::task::JoinSet::new();
    if slow {
        // Each socket echoes 4 MiB while its Visitor does not consume responses. Writes are bounded.
        for mut socket in sockets.drain(..) {
            slow_writers.spawn(async move {
                let bytes = vec![0x63; 4 * 1024 * 1024];
                let sent =
                    tokio::time::timeout(Duration::from_secs(15), socket.write_all(&bytes)).await;
                (socket, sent.is_ok_and(|v| v.is_ok()))
            });
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        // New unrelated Visitors on the same connection test shared-window availability.
        for index in 0..32 {
            let target = targets[index % targets.len()];
            let hello = hello.clone();
            tasks.spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    connect_visitor(target, hello, index),
                )
                .await
            });
        }
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut working = 0;
    let transfer_start = Instant::now();
    for (index, mut socket) in sockets.into_iter().enumerate() {
        tasks.spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let probe = if transfer {
                    vec![0x71; 1024 * 1024]
                } else {
                    index.to_be_bytes().to_vec()
                };
                socket.write_all(&probe).await?;
                let mut response = vec![0; probe.len()];
                socket.read_exact(&mut response).await?;
                if response != probe {
                    return Err(std::io::Error::other("hold probe mismatch"));
                }
                Ok((socket, 0., probe.len()))
            })
            .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        if matches!(result?, Ok(Ok(_))) {
            working += 1;
        }
    }
    let transfer_seconds = transfer_start.elapsed().as_secs_f64();
    let mut slow_uploads_completed = 0;
    while let Some(result) = slow_writers.join_next().await {
        if result?.1 {
            slow_uploads_completed += 1;
        }
    }
    latencies.sort_by(f64::total_cmp);
    let percentile = |p: usize| {
        latencies
            .get((latencies.len().saturating_sub(1) * p) / 100)
            .copied()
    };
    write_json(
        &directory.join("load.result.json"),
        serde_json::json!({
            "attempted":count, "established_and_byte_validated":established,
            "still_working_after_hold":working, "hold_seconds":5, "batch":batch,
            "pacing_ms_between_batches":10, "ttfb_p50_ms":percentile(50), "ttfb_p99_ms":percentile(99),
            "establish_seconds":establish_seconds, "validated_echo_bytes":validated_bytes,
            "failures":failures, "slow_reader":slow, "slow_uploads_completed":slow_uploads_completed,
            "transfer_bytes_validated": if transfer { working * 1024 * 1024 } else { 0 },
        "transfer_seconds": transfer_seconds,
        "unrelated_probes": if slow { 32 } else { 0 },
        }),
    )?;
    Ok(())
}

#[test]
fn benchmark_client_hello_is_valid_passthrough_input() {
    let hello = client_hello().expect("construct ClientHello");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let parsed = crate::read_client_hello(&mut hello.as_slice())
            .await
            .expect("valid ClientHello");
        assert_eq!(parsed.into_parts().0.as_str(), "app.example.test");
    });
}
