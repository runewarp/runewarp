//! Black-box integration tests for managed Server authorization apply (#155)
//! and revocation/drain semantics (#156).

mod common;

use std::convert::Infallible;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::Stream;
use http::header::CONTENT_TYPE;
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::BoxBody as HttpBoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::generate_simple_self_signed;
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, CONTROL_ALPN_H2,
    ControlAddress, ControlClientIdentityMaterial, ControlTrust, GeneratedClientIdentity,
    ManagedSession, ManagedSessionEvent, ManagedSessionRole, OrderlyShutdown, PreparedClient,
    PreparedServer, QUIC_CLOSE_FLUSH_DURATION, SERVER_IDENTITY_CERT_FILENAME,
    SERVER_IDENTITY_KEY_FILENAME, SessionMaterial, events_path, generate_client_identity,
    initialize_manual_server_certificate, load_client_config, load_server_config, state_path,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ServerConfig, ServerConfig as RustlsServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde_json::{Value, json};
use std::sync::Mutex;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use common::{
    ControlMtlsMaterial, generate_control_mtls_material, write_control_ca_and_certs,
    write_control_client_as_server_identity,
};

const SERVER_HOSTNAME: &str = "tunnel.example.test";
const APP_HOSTNAME: &str = "app.example.test";
const API_HOSTNAME: &str = "api.example.test";

#[derive(Debug)]
struct FixtureMetrics {
    tls_accepts: AtomicUsize,
    state_bodies: Mutex<Vec<Value>>,
    state_statuses: Mutex<Vec<u16>>,
    concurrent_streams: AtomicUsize,
    max_concurrent_streams: AtomicUsize,
}

impl FixtureMetrics {
    fn new() -> Self {
        Self {
            tls_accepts: AtomicUsize::new(0),
            state_bodies: Mutex::new(Vec::new()),
            state_statuses: Mutex::new(Vec::new()),
            concurrent_streams: AtomicUsize::new(0),
            max_concurrent_streams: AtomicUsize::new(0),
        }
    }

    fn begin_stream(&self) {
        let current = self.concurrent_streams.fetch_add(1, Ordering::SeqCst) + 1;
        let mut max = self.max_concurrent_streams.load(Ordering::SeqCst);
        while current > max {
            match self.max_concurrent_streams.compare_exchange_weak(
                max,
                current,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => max = observed,
            }
        }
    }

    fn end_stream(&self) {
        self.concurrent_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ControlFixture {
    port: u16,
    metrics: Arc<FixtureMetrics>,
    snapshot_tx: mpsc::UnboundedSender<String>,
    shutdown: Arc<tokio::sync::Notify>,
    task: JoinHandle<()>,
}

impl ControlFixture {
    async fn start(material: &ControlMtlsMaterial) -> Self {
        let listener = TcpListener::bind(localhost(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = build_server_acceptor(material);
        let metrics = Arc::new(FixtureMetrics::new());
        let (snapshot_tx, snapshot_rx) = mpsc::unbounded_channel();
        let snapshot_rx = Arc::new(AsyncMutex::new(snapshot_rx));
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_wait = shutdown.clone();
        let metrics_task = metrics.clone();
        let snapshots_task = snapshot_rx.clone();

        let task = tokio::spawn(async move {
            loop {
                let accept = tokio::select! {
                    _ = shutdown_wait.notified() => break,
                    accept = listener.accept() => accept,
                };
                let Ok((tcp, _)) = accept else {
                    break;
                };
                let acceptor = acceptor.clone();
                let metrics = metrics_task.clone();
                let snapshots = snapshots_task.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    metrics.tls_accepts.fetch_add(1, Ordering::SeqCst);
                    let service = service_fn({
                        let metrics = metrics.clone();
                        let snapshots = snapshots.clone();
                        move |request: Request<Incoming>| {
                            let metrics = metrics.clone();
                            let snapshots = snapshots.clone();
                            async move { handle_request(request, metrics, snapshots).await }
                        }
                    });
                    let io = TokioIo::new(tls);
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        Self {
            port,
            metrics,
            snapshot_tx,
            shutdown,
            task,
        }
    }

    fn push_snapshot(&self, sse: String) {
        self.snapshot_tx.send(sse).unwrap();
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.task.await;
    }
}

struct ManagedServerHarness {
    _tempdir: TempDir,
    control: ControlFixture,
    public_addr: SocketAddr,
    tunnel_addr: SocketAddr,
    readiness_addr: SocketAddr,
    app_backend_key: Vec<u8>,
    api_backend_key: Vec<u8>,
    app_backend_cert: CertificateDer<'static>,
    api_backend_cert: CertificateDer<'static>,
    trusted_client: GeneratedClientIdentity,
    second_client: GeneratedClientIdentity,
    event_rx: mpsc::UnboundedReceiver<ManagedSessionEvent>,
    stop_tx: Option<oneshot::Sender<()>>,
    shutdown: Option<OrderlyShutdown>,
    server_task: Option<JoinHandle<io::Result<()>>>,
    session_task: JoinHandle<()>,
    client_tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl ManagedServerHarness {
    async fn start() -> Self {
        Self::start_inner(None).await
    }

    async fn start_with_graceful_drain(graceful: Duration) -> Self {
        Self::start_inner(Some(OrderlyShutdown::new(
            graceful,
            QUIC_CLOSE_FLUSH_DURATION,
        )))
        .await
    }

    fn begin_graceful(&self) {
        self.shutdown
            .as_ref()
            .expect("graceful drain harness required")
            .begin_graceful();
    }

    async fn start_inner(shutdown: Option<OrderlyShutdown>) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let material = generate_control_mtls_material("runewarp-server-a");
        let control = ControlFixture::start(&material).await;

        initialize_manual_server_certificate(
            tempdir.path().join("server-cert").as_path(),
            SERVER_HOSTNAME,
        )
        .unwrap();
        let control_paths =
            write_control_ca_and_certs(tempdir.path().join("control").as_path(), &material);
        write_control_client_as_server_identity(
            tempdir.path().join("server-identity").as_path(),
            &material,
        );

        fs::write(
            tempdir.path().join("config.toml"),
            format!(
                r#"
[control]
address = "localhost:{}"
trust = "ca-file"
ca-file = "control/ca.crt"

[server]
hostname = "{SERVER_HOSTNAME}"
cert-dir = "server-cert"
identity-dir = "server-identity"
readiness-bind-address = "127.0.0.1:0"
public-bind-address = "127.0.0.1:0"
tunnel-bind-address = "127.0.0.1:0"
"#,
                control.port
            ),
        )
        .unwrap();

        let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
        assert!(settings.tunnels.is_empty());

        let server = PreparedServer::bind(
            &settings,
            settings.public_bind_address,
            settings.tunnel_connection_bind_address,
        )
        .await
        .expect("managed Server must bind with empty authorization");

        let public_addr = server.public_addr().unwrap();
        let tunnel_addr = server.tunnel_addr().unwrap();
        let readiness_addr = server
            .readiness_addr()
            .expect("managed Server must expose readiness");

        let trusted_client = generate_client_identity().unwrap();
        let second_client = generate_client_identity().unwrap();
        write_client_identity_material(&tempdir.path().join("client-one"), &trusted_client);
        write_client_identity_material(&tempdir.path().join("client-two"), &second_client);

        let (app_backend_cert, app_backend_key) = make_self_signed_cert(APP_HOSTNAME);
        let (api_backend_cert, api_backend_key) = make_self_signed_cert(API_HOSTNAME);

        let session_material = SessionMaterial {
            control_hostname: "localhost".to_owned(),
            trust: ControlTrust::CaFile(control_paths.ca_cert),
            identity: ControlClientIdentityMaterial {
                cert_path: tempdir
                    .path()
                    .join("server-identity")
                    .join(SERVER_IDENTITY_CERT_FILENAME),
                key_path: tempdir
                    .path()
                    .join("server-identity")
                    .join(SERVER_IDENTITY_KEY_FILENAME),
            },
        };
        let mut session = ManagedSession::new(
            ControlAddress::parse(&format!("localhost:{}", control.port)).unwrap(),
            ManagedSessionRole::Server,
            session_material,
        )
        .unwrap();
        let mut adapter = server
            .authorization_adapter()
            .expect("managed Server exposes authorization adapter");
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let session_task = tokio::spawn(async move {
            session
                .run(
                    &mut adapter,
                    move |event| {
                        let event_tx = event_tx.clone();
                        async move {
                            let _ = event_tx.send(event);
                        }
                    },
                    async {
                        let _ = stop_rx.await;
                    },
                )
                .await;
        });
        let server_task = if let Some(ref shutdown) = shutdown {
            let shutdown = shutdown.clone();
            tokio::spawn(async move { server.run_with_shutdown(&shutdown).await })
        } else {
            tokio::spawn(async move { server.run().await })
        };

        Self {
            _tempdir: tempdir,
            control,
            public_addr,
            tunnel_addr,
            readiness_addr,
            app_backend_key,
            api_backend_key,
            app_backend_cert,
            api_backend_cert,
            trusted_client,
            second_client,
            event_rx,
            stop_tx: Some(stop_tx),
            shutdown,
            server_task: Some(server_task),
            session_task,
            client_tasks: Mutex::new(Vec::new()),
        }
    }

    async fn spawn_client(
        &self,
        identity_dir: &str,
        backend_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle = connect_running_client(self, identity_dir, backend_addr).await?;
        self.client_tasks.lock().unwrap().push(handle);
        Ok(())
    }

    async fn spawn_dual_hostname_client(
        &self,
        identity_dir: &str,
        app_backend_addr: SocketAddr,
        api_backend_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle = connect_running_dual_hostname_client(
            self,
            identity_dir,
            app_backend_addr,
            api_backend_addr,
        )
        .await?;
        self.client_tasks.lock().unwrap().push(handle);
        Ok(())
    }

    async fn stop_clients(&self) {
        let tasks = {
            let mut guard = self.client_tasks.lock().unwrap();
            std::mem::take(&mut *guard)
        };
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        sleep(Duration::from_millis(50)).await;
    }

    fn push_authorization(&self, revision: &str, input: &str) {
        self.control.push_snapshot(snapshot_sse(revision, input));
    }

    async fn shutdown(mut self) {
        self.stop_clients().await;
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = self.session_task.await;
        if let Some(server_task) = self.server_task.take() {
            server_task.abort();
            let _ = server_task.await;
        }
        self.control.shutdown().await;
    }
}

#[tokio::test]
async fn managed_server_authorization_apply_controls_traffic_and_readiness() {
    let mut harness = ManagedServerHarness::start().await;
    let app_backend = spawn_tls_backend(
        &harness.app_backend_cert,
        &harness.app_backend_key,
        *b"pong",
    )
    .await;
    let api_backend = spawn_tls_backend(
        &harness.api_backend_cert,
        &harness.api_backend_key,
        *b"pong",
    )
    .await;

    // 1. Before first apply: readiness Unready, no successful Visitor traffic.
    if let Ok(Ok(_)) = timeout(
        Duration::from_millis(100),
        TcpStream::connect(harness.readiness_addr),
    )
    .await
    {
        panic!("readiness must stay Unready before the first successful apply");
    }
    wait_for_tls_failure(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("visitor traffic must not succeed before authorization apply");

    // 2. First valid apply: readiness opens, state reports revision, traffic succeeds.
    let first_identity = harness.trusted_client.client_identity.to_string();
    harness.push_authorization(
        "rev-1",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{first_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-1").await;
    wait_for_readiness_open(harness.readiness_addr).await;
    wait_for_state_revision(&harness.control.metrics, "rev-1").await;

    harness
        .spawn_client("client-one", app_backend.0)
        .await
        .expect("authorized tunnel client must connect after first apply");
    sleep(Duration::from_millis(50)).await;

    let response = visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("authorized visitor traffic must succeed after first apply");
    assert_eq!(response, *b"pong");
    harness.stop_clients().await;

    // 3. Replacement apply: new authorization works; prior identity is denied.
    let second_identity = harness.second_client.client_identity.to_string();
    harness.push_authorization(
        "rev-2",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{API_HOSTNAME}"],"client_identities":["{second_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-2").await;
    wait_for_state_revision(&harness.control.metrics, "rev-2").await;

    harness
        .spawn_client("client-two", api_backend.0)
        .await
        .expect("replacement authorization must admit the new client identity");
    sleep(Duration::from_millis(50)).await;

    let api_response = visitor_ping(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
        .await
        .expect("replacement authorization must route visitor traffic");
    assert_eq!(api_response, *b"pong");
    harness.stop_clients().await;
    wait_for_tls_failure(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("prior public hostname must stop routing after replacement apply");

    // 4. Empty tunnels apply: readiness stays ready; visitor and tunnel are unauthorized.
    harness.push_authorization("rev-empty", r#"{"tunnels":[]}"#);
    wait_for_applied(&mut harness.event_rx, "rev-empty").await;
    harness.stop_clients().await;
    wait_for_readiness_open(harness.readiness_addr).await;
    wait_for_tls_failure(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
        .await
        .expect("visitor traffic must fail with empty authorization");
    if harness
        .spawn_client("client-two", api_backend.0)
        .await
        .is_ok()
    {
        wait_for_tls_failure(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
            .await
            .expect("empty authorization must keep visitor traffic unauthorized");
        harness.stop_clients().await;
    }

    // 5. Invalid candidate: rejected, prior authorization retained, prior revision reported.
    harness.push_authorization(
        "rev-bad",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{SERVER_HOSTNAME}"],"client_identities":["{second_identity}"]}}]}}"#
        ),
    );
    wait_for_rejected(&mut harness.event_rx, "rev-bad").await;
    harness.push_authorization("rev-empty", r#"{"tunnels":[]}"#);
    wait_for_state_revision(&harness.control.metrics, "rev-empty").await;
    {
        let bodies = harness.control.metrics.state_bodies.lock().unwrap();
        assert!(
            bodies
                .iter()
                .all(|body| body.get("revision").and_then(Value::as_str) != Some("rev-bad")),
            "rejected revision must not be acknowledged to Control"
        );
    }
    wait_for_tls_failure(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
        .await
        .expect("invalid apply must retain the prior empty authorization");

    // 6. Rollback to an earlier revision applies again.
    harness.push_authorization(
        "rev-1",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{first_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-1").await;
    harness
        .spawn_client("client-one", app_backend.0)
        .await
        .expect("rollback must restore tunnel admission");
    sleep(Duration::from_millis(50)).await;
    let rollback_response =
        visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
            .await
            .expect("rollback must restore visitor routing");
    assert_eq!(rollback_response, *b"pong");

    // 7. Control session survives: another snapshot applies on the same connection.
    let tls_before = harness.control.metrics.tls_accepts.load(Ordering::SeqCst);
    harness.push_authorization("rev-alive", r#"{"tunnels":[]}"#);
    wait_for_applied(&mut harness.event_rx, "rev-alive").await;
    wait_for_state_revision(&harness.control.metrics, "rev-alive").await;
    assert_eq!(
        harness.control.metrics.tls_accepts.load(Ordering::SeqCst),
        tls_before,
        "managed session should keep the existing Control connection alive"
    );
    assert!(
        harness
            .control
            .metrics
            .max_concurrent_streams
            .load(Ordering::SeqCst)
            >= 2,
        "events and state streams should remain open on one Control connection"
    );

    app_backend.1.abort();
    api_backend.1.abort();
    let _ = app_backend.1.await;
    let _ = api_backend.1.await;
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_server_identity_revocation_closes_live_work_and_denies_new_handshakes() {
    let mut harness = ManagedServerHarness::start().await;
    let app_backend = spawn_tls_backend(
        &harness.app_backend_cert,
        &harness.app_backend_key,
        *b"pong",
    )
    .await;

    let first_identity = harness.trusted_client.client_identity.to_string();
    let second_identity = harness.second_client.client_identity.to_string();
    harness.push_authorization(
        "rev-1",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{first_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-1").await;
    wait_for_readiness_open(harness.readiness_addr).await;

    harness
        .spawn_client("client-one", app_backend.0)
        .await
        .expect("authorized tunnel client must connect");
    sleep(Duration::from_millis(50)).await;
    let response = visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("authorized visitor traffic must succeed");
    assert_eq!(response, *b"pong");

    // Replace authorization while client-one is still connected.
    harness.push_authorization(
        "rev-2",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{second_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-2").await;
    wait_for_state_revision(&harness.control.metrics, "rev-2").await;
    wait_for_readiness_open(harness.readiness_addr).await;

    wait_for_tls_failure(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("revoked identity live visitor traffic must fail");
    match connect_running_client(&harness, "client-one", app_backend.0).await {
        Err(_) => {}
        Ok(handle) => {
            // QUIC may surface ApplicationVerificationFailure after connect returns.
            sleep(Duration::from_millis(50)).await;
            wait_for_tls_failure(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
                .await
                .expect("revoked identity must not serve after a new handshake attempt");
            handle.abort();
            let _ = handle.await;
        }
    }

    harness
        .spawn_client("client-two", app_backend.0)
        .await
        .expect("replacement identity must connect");
    sleep(Duration::from_millis(50)).await;
    let replacement = visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("replacement identity must serve visitor traffic");
    assert_eq!(replacement, *b"pong");
    wait_for_readiness_open(harness.readiness_addr).await;

    app_backend.1.abort();
    let _ = app_backend.1.await;
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_server_hostname_only_revocation_resets_only_affected_streams() {
    let mut harness = ManagedServerHarness::start().await;
    let app_backend = spawn_tls_backend(
        &harness.app_backend_cert,
        &harness.app_backend_key,
        *b"pong",
    )
    .await;
    let api_backend = spawn_tls_backend(
        &harness.api_backend_cert,
        &harness.api_backend_key,
        *b"pong",
    )
    .await;

    let identity = harness.trusted_client.client_identity.to_string();
    harness.push_authorization(
        "rev-both",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}","{API_HOSTNAME}"],"client_identities":["{identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-both").await;
    wait_for_readiness_open(harness.readiness_addr).await;

    harness
        .spawn_dual_hostname_client("client-one", app_backend.0, api_backend.0)
        .await
        .expect("dual-hostname tunnel client must connect");
    sleep(Duration::from_millis(50)).await;

    let app_response = visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("APP hostname must work before hostname-only revocation");
    assert_eq!(app_response, *b"pong");
    let api_response = visitor_ping(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
        .await
        .expect("API hostname must work before hostname-only revocation");
    assert_eq!(api_response, *b"pong");

    harness.push_authorization(
        "rev-app-only",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-app-only").await;
    wait_for_state_revision(&harness.control.metrics, "rev-app-only").await;

    wait_for_tls_failure(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
        .await
        .expect("revoked hostname must stop routing");
    let still_app = visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("retained hostname must keep working on the same connected client");
    assert_eq!(still_app, *b"pong");

    app_backend.1.abort();
    api_backend.1.abort();
    let _ = app_backend.1.await;
    let _ = api_backend.1.await;
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_server_unrelated_identity_survives_targeted_revocation() {
    let mut harness = ManagedServerHarness::start().await;
    let app_backend = spawn_tls_backend(
        &harness.app_backend_cert,
        &harness.app_backend_key,
        *b"pong",
    )
    .await;
    let api_backend = spawn_tls_backend(
        &harness.api_backend_cert,
        &harness.api_backend_key,
        *b"pong",
    )
    .await;

    let first_identity = harness.trusted_client.client_identity.to_string();
    let second_identity = harness.second_client.client_identity.to_string();
    harness.push_authorization(
        "rev-both",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{first_identity}"]}},{{"public_hostnames":["{API_HOSTNAME}"],"client_identities":["{second_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-both").await;
    wait_for_readiness_open(harness.readiness_addr).await;

    harness
        .spawn_client("client-one", app_backend.0)
        .await
        .expect("client-one must connect");
    harness
        .spawn_client("client-two", api_backend.0)
        .await
        .expect("client-two must connect");
    sleep(Duration::from_millis(50)).await;

    assert_eq!(
        visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
            .await
            .expect("APP must work before targeted revocation"),
        *b"pong"
    );
    assert_eq!(
        visitor_ping(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
            .await
            .expect("API must work before targeted revocation"),
        *b"pong"
    );

    harness.push_authorization(
        "rev-drop-one",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{API_HOSTNAME}"],"client_identities":["{second_identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-drop-one").await;
    wait_for_state_revision(&harness.control.metrics, "rev-drop-one").await;

    wait_for_tls_failure(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
        .await
        .expect("revoked client-one/APP must fail");
    let api_still = visitor_ping(harness.public_addr, &harness.api_backend_cert, API_HOSTNAME)
        .await
        .expect("unrelated client-two/API must survive targeted revocation");
    assert_eq!(api_still, *b"pong");

    app_backend.1.abort();
    api_backend.1.abort();
    let _ = app_backend.1.await;
    let _ = api_backend.1.await;
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_server_retains_authorization_through_control_session_loss() {
    let mut harness = ManagedServerHarness::start().await;
    let app_backend = spawn_tls_backend(
        &harness.app_backend_cert,
        &harness.app_backend_key,
        *b"pong",
    )
    .await;

    let identity = harness.trusted_client.client_identity.to_string();
    let auth_input = format!(
        r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{identity}"]}}]}}"#
    );
    harness.push_authorization("rev-1", &auth_input);
    wait_for_applied(&mut harness.event_rx, "rev-1").await;
    wait_for_readiness_open(harness.readiness_addr).await;
    wait_for_state_revision(&harness.control.metrics, "rev-1").await;

    harness
        .spawn_client("client-one", app_backend.0)
        .await
        .expect("authorized tunnel client must connect");
    sleep(Duration::from_millis(50)).await;
    assert_eq!(
        visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
            .await
            .expect("visitor traffic must work before session loss"),
        *b"pong"
    );

    let tls_before = harness.control.metrics.tls_accepts.load(Ordering::SeqCst);
    let reports_before = harness.control.metrics.state_bodies.lock().unwrap().len();
    harness
        .control
        .push_snapshot("event: patch\ndata: {}\n\n".to_owned());
    wait_for_reconnecting(&mut harness.event_rx).await;

    wait_for_readiness_open(harness.readiness_addr).await;
    assert_eq!(
        visitor_ping(harness.public_addr, &harness.app_backend_cert, APP_HOSTNAME)
            .await
            .expect("authorization must be retained while Control reconnects"),
        *b"pong"
    );

    harness.push_authorization("rev-1", &auth_input);
    timeout(Duration::from_secs(5), async {
        loop {
            let resumed = {
                let bodies = harness.control.metrics.state_bodies.lock().unwrap();
                if bodies.len() > reports_before {
                    assert_eq!(
                        bodies.last(),
                        Some(&json!({ "revision": "rev-1" })),
                        "equal revision after reconnect must resume state reporting"
                    );
                    true
                } else {
                    false
                }
            };
            if resumed {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("equal revision after reconnect must resume state reporting");
    assert!(
        harness.control.metrics.tls_accepts.load(Ordering::SeqCst) > tls_before,
        "Control reconnect must open a new TLS connection"
    );

    app_backend.1.abort();
    let _ = app_backend.1.await;
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_server_applies_authorization_change_during_graceful_drain() {
    let mut harness = ManagedServerHarness::start_with_graceful_drain(Duration::from_secs(5)).await;
    let (backend_addr, backend_started, backend_release, backend_task) = spawn_staged_tls_backend(
        &harness.app_backend_cert,
        &harness.app_backend_key,
        *b"on",
        *b"e!",
    )
    .await;

    let identity = harness.trusted_client.client_identity.to_string();
    harness.push_authorization(
        "rev-live",
        &format!(
            r#"{{"tunnels":[{{"public_hostnames":["{APP_HOSTNAME}"],"client_identities":["{identity}"]}}]}}"#
        ),
    );
    wait_for_applied(&mut harness.event_rx, "rev-live").await;
    wait_for_readiness_open(harness.readiness_addr).await;

    harness
        .spawn_client("client-one", backend_addr)
        .await
        .expect("authorized tunnel client must connect");
    sleep(Duration::from_millis(50)).await;

    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(&harness.app_backend_cert))
            .with_no_client_auth(),
    ));
    let tcp_stream = TcpStream::connect(harness.public_addr).await.unwrap();
    let mut tls_stream = connector
        .connect(
            ServerName::try_from(APP_HOSTNAME.to_owned()).unwrap(),
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

    harness.begin_graceful();
    wait_for_readiness_closed(harness.readiness_addr).await;
    let mut server_task = harness
        .server_task
        .take()
        .expect("graceful drain harness owns the server task");
    assert!(
        timeout(Duration::from_millis(100), &mut server_task)
            .await
            .is_err(),
        "graceful drain must stay alive while the landed stream is still active"
    );

    harness.push_authorization("rev-drain-revoke", r#"{"tunnels":[]}"#);
    wait_for_applied(&mut harness.event_rx, "rev-drain-revoke").await;
    wait_for_state_revision(&harness.control.metrics, "rev-drain-revoke").await;

    let mut rest = [0_u8; 2];
    let aborted = timeout(Duration::from_secs(1), tls_stream.read_exact(&mut rest)).await;
    assert!(
        matches!(aborted, Ok(Err(_)) | Err(_)),
        "authorization revocation during drain must abort the landed stream immediately"
    );
    drop(backend_release);

    timeout(Duration::from_secs(2), &mut server_task)
        .await
        .expect("server should complete after revocation clears active streams")
        .expect("server task should join cleanly")
        .expect("server shutdown should succeed");

    backend_task.abort();
    let _ = backend_task.await;
    harness.shutdown().await;
}

fn write_client_identity_material(directory: &std::path::Path, identity: &GeneratedClientIdentity) {
    fs::create_dir_all(directory).unwrap();
    fs::write(
        directory.join(CLIENT_CERT_FILENAME),
        &identity.certificate_pem,
    )
    .unwrap();
    fs::write(
        directory.join(CLIENT_KEY_FILENAME),
        &identity.private_key_pem,
    )
    .unwrap();
    fs::write(
        directory.join(CLIENT_IDENTITY_FILENAME),
        identity.client_identity.to_string(),
    )
    .unwrap();
}

fn write_client_config(
    base: &std::path::Path,
    identity_dir: &str,
    backend_addr: SocketAddr,
) -> std::path::PathBuf {
    let path = base.join(format!("{identity_dir}.toml"));
    fs::write(
        &path,
        format!(
            r#"
[client]
server-address = "{SERVER_HOSTNAME}"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "{identity_dir}"

[[client.services]]
backend-address = "{backend_addr}"
"#
        ),
    )
    .unwrap();
    path
}

fn write_dual_hostname_client_config(
    base: &std::path::Path,
    identity_dir: &str,
    app_backend_addr: SocketAddr,
    api_backend_addr: SocketAddr,
) -> std::path::PathBuf {
    let path = base.join(format!("{identity_dir}-dual.toml"));
    fs::write(
        &path,
        format!(
            r#"
[client]
server-address = "{SERVER_HOSTNAME}"
server-trust = "ca-file"
server-ca-file = "server-cert/server-ca.crt"
identity-dir = "{identity_dir}"

[[client.services]]
public-hostnames = ["{APP_HOSTNAME}"]
backend-address = "{app_backend_addr}"

[[client.services]]
public-hostnames = ["{API_HOSTNAME}"]
backend-address = "{api_backend_addr}"
"#
        ),
    )
    .unwrap();
    path
}

async fn connect_running_client(
    harness: &ManagedServerHarness,
    identity_dir: &str,
    backend_addr: SocketAddr,
) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let config_path = write_client_config(harness._tempdir.path(), identity_dir, backend_addr);
    let settings = load_client_config(&config_path)?;
    let client = PreparedClient::connect_to(&settings, localhost(0), harness.tunnel_addr).await?;
    Ok(tokio::spawn(async move {
        let _ = client.run().await;
    }))
}

async fn connect_running_dual_hostname_client(
    harness: &ManagedServerHarness,
    identity_dir: &str,
    app_backend_addr: SocketAddr,
    api_backend_addr: SocketAddr,
) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let config_path = write_dual_hostname_client_config(
        harness._tempdir.path(),
        identity_dir,
        app_backend_addr,
        api_backend_addr,
    );
    let settings = load_client_config(&config_path)?;
    let client = PreparedClient::connect_to(&settings, localhost(0), harness.tunnel_addr).await?;
    Ok(tokio::spawn(async move {
        let _ = client.run().await;
    }))
}

async fn wait_for_applied(
    event_rx: &mut mpsc::UnboundedReceiver<ManagedSessionEvent>,
    revision: &str,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            match event_rx.recv().await {
                Some(ManagedSessionEvent::Applied { revision: applied }) if applied == revision => {
                    break;
                }
                Some(_) => {}
                None => panic!("managed session event channel closed"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for Applied {{ revision: {revision} }}"));
}

async fn wait_for_rejected(
    event_rx: &mut mpsc::UnboundedReceiver<ManagedSessionEvent>,
    revision: &str,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            match event_rx.recv().await {
                Some(ManagedSessionEvent::Rejected { revision: rejected })
                    if rejected == revision =>
                {
                    break;
                }
                Some(_) => {}
                None => panic!("managed session event channel closed"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for Rejected {{ revision: {revision} }}"));
}

async fn wait_for_reconnecting(event_rx: &mut mpsc::UnboundedReceiver<ManagedSessionEvent>) {
    timeout(Duration::from_secs(5), async {
        loop {
            match event_rx.recv().await {
                Some(ManagedSessionEvent::Reconnecting { .. }) => break,
                Some(_) => {}
                None => panic!("managed session event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for ManagedSessionEvent::Reconnecting");
}

async fn wait_for_state_revision(metrics: &FixtureMetrics, revision: &str) {
    let expected = json!({ "revision": revision });
    timeout(Duration::from_secs(5), async {
        loop {
            let ready = metrics
                .state_bodies
                .lock()
                .unwrap()
                .iter()
                .any(|body| body == &expected);
            if ready {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for state revision {revision}"));
}

async fn wait_for_readiness_open(readiness_addr: SocketAddr) {
    timeout(Duration::from_secs(2), async {
        loop {
            if TcpStream::connect(readiness_addr).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("readiness must open after the first successful apply");
}

async fn wait_for_readiness_closed(readiness_addr: SocketAddr) {
    timeout(Duration::from_secs(2), async {
        loop {
            if TcpStream::connect(readiness_addr).await.is_err() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("readiness must close when graceful drain begins");
}

fn snapshot_sse(revision: &str, input: &str) -> String {
    format!("event: snapshot\ndata: {{\"revision\":\"{revision}\",\"input\":{input}}}\n\n")
}

type ResponseBody = HttpBoxBody<Bytes, Infallible>;

fn empty_body() -> ResponseBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn boxed_stream<S>(stream: S) -> ResponseBody
where
    S: Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + Sync + 'static,
{
    StreamBody::new(stream)
        .map_err(|never| match never {})
        .boxed()
}

async fn handle_request(
    request: Request<Incoming>,
    metrics: Arc<FixtureMetrics>,
    snapshots: Arc<AsyncMutex<mpsc::UnboundedReceiver<String>>>,
) -> Result<Response<ResponseBody>, Infallible> {
    let path = request.uri().path().to_owned();
    if path == events_path(ManagedSessionRole::Server) {
        metrics.begin_stream();
        let metrics_drop = metrics.clone();
        let body = boxed_stream(SnapshotFeedStream {
            snapshots,
            pending: None,
            metrics: Some(metrics_drop),
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(body)
            .unwrap());
    }

    if path == state_path(ManagedSessionRole::Server) {
        metrics.begin_stream();
        let body = request.collect().await.unwrap().to_bytes();
        let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        metrics.state_bodies.lock().unwrap().push(parsed);
        metrics.state_statuses.lock().unwrap().push(204);
        metrics.end_stream();
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(empty_body())
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty_body())
        .unwrap())
}

struct SnapshotFeedStream {
    snapshots: Arc<AsyncMutex<mpsc::UnboundedReceiver<String>>>,
    pending: Option<String>,
    metrics: Option<Arc<FixtureMetrics>>,
}

impl Stream for SnapshotFeedStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(payload) = this.pending.take() {
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(payload)))));
        }
        let mut guard = match this.snapshots.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        match guard.poll_recv(cx) {
            Poll::Ready(Some(payload)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(payload))))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SnapshotFeedStream {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics.take() {
            metrics.end_stream();
        }
    }
}

fn build_server_acceptor(material: &ControlMtlsMaterial) -> TlsAcceptor {
    let ca_certs: Vec<CertificateDer<'static>> = certs(&mut material.ca_cert_pem.as_bytes())
        .map(|result| result.unwrap())
        .collect();
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).unwrap();
    }
    let client_verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();
    let server_certs: Vec<CertificateDer<'static>> =
        certs(&mut material.server_cert_pem.as_bytes())
            .map(|result| result.unwrap())
            .collect();
    let server_key = pkcs8_private_keys(&mut material.server_key_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, PrivateKeyDer::Pkcs8(server_key))
        .unwrap();
    server_config.alpn_protocols = vec![CONTROL_ALPN_H2.to_vec()];
    TlsAcceptor::from(Arc::new(server_config))
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn make_self_signed_cert(server_name: &str) -> (CertificateDer<'static>, Vec<u8>) {
    let certified_key = generate_simple_self_signed(vec![server_name.to_owned()]).unwrap();
    (
        CertificateDer::from(certified_key.cert),
        certified_key.signing_key.serialize_der(),
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

async fn spawn_tls_backend(
    certificate: &CertificateDer<'static>,
    private_key: &[u8],
    response: [u8; 4],
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(
        RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key_from_der(private_key))
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
                let _ = tls_stream.shutdown().await;
            });
        }
    });

    (addr, task)
}

async fn spawn_staged_tls_backend(
    certificate: &CertificateDer<'static>,
    private_key: &[u8],
    first_chunk: [u8; 2],
    second_chunk: [u8; 2],
) -> (
    SocketAddr,
    oneshot::Receiver<()>,
    Arc<Notify>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind(localhost(0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(
        RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key_from_der(private_key))
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

async fn visitor_ping(
    public_addr: SocketAddr,
    backend_cert: &CertificateDer<'static>,
    server_name: &str,
) -> io::Result<[u8; 4]> {
    timeout(Duration::from_secs(2), async {
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
    timeout(Duration::from_secs(2), async {
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
    let server_name = ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;
    tls_stream.write_all(b"ping").await?;
    let mut response = [0_u8; 4];
    tls_stream.read_exact(&mut response).await?;
    Ok(response)
}
