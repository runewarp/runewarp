//! Black-box integration tests for managed Client assignment reconciliation (#157).

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
use futures_util::FutureExt;
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
    AddressController, AddressWorkerControl, AssignmentConvergence, CLIENT_CERT_FILENAME,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientConfig, ClientIdentity,
    ClientInstancePrep, ClientTlsMode, ControlAddress, ControlClientIdentityMaterial, ControlTrust,
    LogLevel, MaintenanceIntent, ManagedSession, ManagedSessionEvent, ManagedSessionRole,
    OrderlyShutdown, PreparedClient, PublicHostname, QUIC_CLOSE_FLUSH_DURATION, Server,
    ServerAddress, ServerAdmission, ServerAuthorization, ServerBindConfig, ServerHostname,
    ServerTunnelConfig, ServiceConfig, SessionMaterial, ShutdownMode,
    client_identity_from_certificate_der, make_server_quic_config_with_client_admission,
};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ServerConfig, ServerConfig as RustlsServerConfig};
use serde_json::{Value, json};
use std::sync::Mutex;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use common::{
    CLIENT_EVENTS_PATH, CLIENT_STATE_PATH, CONTROL_ALPN_H2, ControlMtlsMaterial,
    generate_control_mtls_material, write_control_ca_and_certs,
};

const APP_HOSTNAME: &str = "app.example.test";

#[derive(Debug)]
struct FixtureMetrics {
    tls_accepts: AtomicUsize,
    state_bodies: Mutex<Vec<Value>>,
}

impl FixtureMetrics {
    fn new() -> Self {
        Self {
            tls_accepts: AtomicUsize::new(0),
            state_bodies: Mutex::new(Vec::new()),
        }
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

struct QuicServerNode {
    public_addr: SocketAddr,
    tunnel_addr: SocketAddr,
    shutdown: OrderlyShutdown,
    task: JoinHandle<io::Result<()>>,
}

impl QuicServerNode {
    /// Close Tunnel connections from the Server side (remote closure for Retiring Clients).
    async fn close_remotely(self) {
        let _ = self.shutdown.begin_fast();
        let _ = timeout(Duration::from_secs(2), self.task).await;
    }
}

struct ManagedClientHarness {
    _tempdir: TempDir,
    control: ControlFixture,
    client_identity: ClientIdentity,
    server_cert: CertificateDer<'static>,
    server_key: Vec<u8>,
    backend_cert: CertificateDer<'static>,
    event_rx: mpsc::UnboundedReceiver<ManagedSessionEvent>,
    stop_tx: Option<oneshot::Sender<()>>,
    runtime_task: JoinHandle<Result<(), String>>,
    controller_view: runewarp::AddressControllerView,
    dial_attempts: Arc<AtomicUsize>,
}

impl ManagedClientHarness {
    async fn start(backend_addr: SocketAddr, backend_cert: CertificateDer<'static>) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let material = generate_control_mtls_material("runewarp-client-a");
        let control = ControlFixture::start(&material).await;
        let control_paths =
            write_control_ca_and_certs(tempdir.path().join("control").as_path(), &material);

        let client_identity = identity_from_cert_pem(&material.client_cert_pem);
        let identity_dir = tempdir.path().join("client-identity");
        fs::create_dir_all(&identity_dir).unwrap();
        fs::write(
            identity_dir.join(CLIENT_CERT_FILENAME),
            &material.client_cert_pem,
        )
        .unwrap();
        fs::write(
            identity_dir.join(CLIENT_KEY_FILENAME),
            &material.client_key_pem,
        )
        .unwrap();
        fs::write(
            identity_dir.join(CLIENT_IDENTITY_FILENAME),
            client_identity.to_string(),
        )
        .unwrap();

        let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_cert_pem = certified.cert.pem();
        let server_cert = CertificateDer::from(certified.cert);
        let server_key = certified.signing_key.serialize_der();
        fs::write(tempdir.path().join("server-ca.pem"), &server_cert_pem).unwrap();

        let settings = ClientConfig {
            server_addresses: vec![],
            server_hostname: ServerHostname::try_from("localhost").unwrap(),
            server_port: 443,
            log_level: LogLevel::Off,
            server_ca_file: Some(tempdir.path().join("server-ca.pem")),
            identity_directory: identity_dir.clone(),
            services: vec![ServiceConfig {
                public_hostnames: None,
                backend_address: backend_addr.to_string(),
                tls_mode: ClientTlsMode::Passthrough,
            }],
            public_cert_config: None,
            control: Some(runewarp::ControlConfig {
                address: ControlAddress::parse(&format!("localhost:{}", control.port)).unwrap(),
                trust: ControlTrust::CaFile(control_paths.ca_cert.clone()),
            }),
        };
        let settings = Arc::new(settings);
        let dial_attempts = Arc::new(AtomicUsize::new(0));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        let instance = ClientInstancePrep::prepare(settings.as_ref())
            .await
            .expect("client instance should prepare");
        instance.start_acme_once();

        let session_material = SessionMaterial {
            control_hostname: "localhost".to_owned(),
            trust: ControlTrust::CaFile(control_paths.ca_cert),
            identity: ControlClientIdentityMaterial::from_client_identity_dir(&identity_dir),
        };
        let mut session = ManagedSession::new(
            ControlAddress::parse(&format!("localhost:{}", control.port)).unwrap(),
            ManagedSessionRole::Client,
            session_material,
        )
        .unwrap();

        let factory: runewarp::AddressWorkerFactory = {
            let settings = Arc::clone(&settings);
            let instance = Arc::clone(&instance);
            let dial_attempts = Arc::clone(&dial_attempts);
            Arc::new(move |server_address, control| {
                let settings = Arc::clone(&settings);
                let instance = Arc::clone(&instance);
                let dial_attempts = Arc::clone(&dial_attempts);
                async move {
                    run_test_address_worker(
                        settings,
                        instance,
                        server_address,
                        localhost(0),
                        control,
                        dial_attempts,
                    )
                    .await
                }
                .boxed()
            })
        };

        let (mut controller, mut adapter) = AddressController::for_managed(factory);
        let controller_view = controller.view();
        let shutdown = controller.shutdown_handle();

        let runtime_task = tokio::spawn(async move {
            let session_runtime = session.run(
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
            );
            tokio::pin!(session_runtime);
            let runtime = controller.run();
            tokio::pin!(runtime);

            let result = tokio::select! {
                result = &mut runtime => result,
                _session_done = &mut session_runtime => {
                    shutdown.request();
                    runtime.await
                }
            };
            instance.stop_acme().await;
            result
        });

        sleep(Duration::from_millis(50)).await;

        Self {
            _tempdir: tempdir,
            control,
            client_identity,
            server_cert,
            server_key,
            backend_cert,
            event_rx,
            stop_tx: Some(stop_tx),
            runtime_task,
            controller_view,
            dial_attempts,
        }
    }

    async fn spawn_server_node(&self) -> QuicServerNode {
        let authorization = ServerAuthorization::from_tunnels(
            &ServerHostname::try_from("localhost").unwrap(),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![PublicHostname::try_from(APP_HOSTNAME).unwrap()],
                authorized_client_identities: vec![self.client_identity.clone()],
            }],
        )
        .unwrap();
        let server = Server::bind(ServerBindConfig {
            public_bind_addr: localhost(0),
            tunnel_connection_bind_addr: localhost(0),
            readiness_bind_addr: None,
            server_hostname: ServerHostname::try_from("localhost").unwrap(),
            authorization: authorization.clone(),
            public_tls_config: None,
            quic_server_config: make_server_quic_config_with_client_admission(
                vec![self.server_cert.clone()],
                private_key_from_der(&self.server_key),
                Arc::new(authorization),
            )
            .unwrap(),
            admission: ServerAdmission::Static,
        })
        .await
        .unwrap();
        let public_addr = server.public_addr().unwrap();
        let tunnel_addr = server.tunnel_addr().unwrap();
        let shutdown = OrderlyShutdown::new(Duration::from_millis(50), QUIC_CLOSE_FLUSH_DURATION);
        let server_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { server.run_with_shutdown(&server_shutdown).await });
        QuicServerNode {
            public_addr,
            tunnel_addr,
            shutdown,
            task,
        }
    }

    fn push_assignment(&self, revision: &str, addresses: &[&str]) {
        let input = json!({ "server_addresses": addresses });
        self.control
            .push_snapshot(snapshot_sse(revision, &input.to_string()));
    }

    fn worker_count(&self) -> usize {
        self.controller_view.worker_count()
    }

    fn dial_attempts(&self) -> usize {
        self.dial_attempts.load(Ordering::SeqCst)
    }

    fn convergence(&self) -> AssignmentConvergence {
        self.controller_view.assignment_convergence()
    }

    async fn shutdown(mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = timeout(Duration::from_secs(5), self.runtime_task).await;
        self.control.shutdown().await;
    }
}

#[tokio::test]
async fn managed_client_reconciles_assignments_across_real_servers() {
    let (backend_cert, backend_key) = make_self_signed_cert(APP_HOSTNAME);
    let backend = spawn_tls_backend(&backend_cert, &backend_key, *b"pong").await;
    let mut harness = ManagedClientHarness::start(backend.0, backend_cert.clone()).await;
    let server_a = harness.spawn_server_node().await;
    let server_b = harness.spawn_server_node().await;
    let failing_port = {
        let sock = std::net::UdpSocket::bind(localhost(0)).unwrap();
        let port = sock.local_addr().unwrap().port();
        drop(sock);
        port
    };

    // 1. Fresh managed Client maintains no workers until the first apply.
    sleep(Duration::from_millis(100)).await;
    assert_eq!(harness.worker_count(), 0);

    // 2. First apply acknowledges revision without waiting for full convergence.
    let addr_a = format!("localhost:{}", server_a.tunnel_addr.port());
    let addr_fail = format!("localhost:{failing_port}");
    harness.push_assignment("rev-1", &[&addr_a, &addr_fail]);
    wait_for_applied(&mut harness.event_rx, "rev-1").await;
    wait_for_state_revision(&harness.control.metrics, "rev-1").await;
    wait_until(|| harness.worker_count() == 2).await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    wait_until(|| {
        matches!(
            harness.convergence(),
            AssignmentConvergence::PartiallyConverged
        )
    })
    .await;

    // 3. Cancel the never-connected failing address; healthy traffic continues.
    harness.push_assignment("rev-1b", &[&addr_a]);
    wait_for_applied(&mut harness.event_rx, "rev-1b").await;
    wait_for_state_revision(&harness.control.metrics, "rev-1b").await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    wait_until(|| harness.worker_count() <= 1).await;
    wait_until(|| harness.convergence() == AssignmentConvergence::Converged).await;

    // 4. Add a second healthy Server; both serve during convergence.
    let addr_b = format!("localhost:{}", server_b.tunnel_addr.port());
    harness.push_assignment("rev-2", &[&addr_a, &addr_b]);
    wait_for_applied(&mut harness.event_rx, "rev-2").await;
    wait_for_state_revision(&harness.control.metrics, "rev-2").await;
    wait_until_visitor_ok(server_b.public_addr, &harness.backend_cert).await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    wait_until(|| harness.convergence() == AssignmentConvergence::Converged).await;

    // 5. Empty assignment applies immediately, is Converged, and reports.
    harness.push_assignment("rev-empty", &[]);
    wait_for_applied(&mut harness.event_rx, "rev-empty").await;
    wait_for_state_revision(&harness.control.metrics, "rev-empty").await;
    assert_eq!(harness.convergence(), AssignmentConvergence::Converged);

    // 6. Fresh assignment after empty starts a new independent worker.
    let server_c = harness.spawn_server_node().await;
    let addr_c = format!("localhost:{}", server_c.tunnel_addr.port());
    harness.push_assignment("rev-3", &[&addr_c]);
    wait_for_applied(&mut harness.event_rx, "rev-3").await;
    wait_until_visitor_ok(server_c.public_addr, &harness.backend_cert).await;

    server_a.close_remotely().await;
    server_b.close_remotely().await;
    server_c.close_remotely().await;
    backend.1.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_client_retires_re_adopts_and_preserves_assignment_through_control_loss() {
    let (backend_cert, backend_key) = make_self_signed_cert(APP_HOSTNAME);
    let backend = spawn_tls_backend(&backend_cert, &backend_key, *b"pong").await;
    let mut harness = ManagedClientHarness::start(backend.0, backend_cert.clone()).await;
    let server_a = harness.spawn_server_node().await;
    let addr_a = format!("localhost:{}", server_a.tunnel_addr.port());

    harness.push_assignment("rev-1", &[&addr_a]);
    wait_for_applied(&mut harness.event_rx, "rev-1").await;
    wait_for_state_revision(&harness.control.metrics, "rev-1").await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    wait_until(|| harness.convergence() == AssignmentConvergence::Converged).await;
    let dials_after_connect = harness.dial_attempts();
    assert!(dials_after_connect >= 1);
    assert_eq!(harness.worker_count(), 1);

    // Remove the connected address: Retiring leaves remote Server closure in charge.
    harness.push_assignment("rev-retire", &[]);
    wait_for_applied(&mut harness.event_rx, "rev-retire").await;
    wait_for_state_revision(&harness.control.metrics, "rev-retire").await;
    assert_eq!(harness.convergence(), AssignmentConvergence::Converged);
    assert_eq!(harness.worker_count(), 1);
    assert_eq!(harness.dial_attempts(), dials_after_connect);
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;

    // Re-add before remote closure: re-adopt without a duplicate dial.
    harness.push_assignment("rev-readopt", &[&addr_a]);
    wait_for_applied(&mut harness.event_rx, "rev-readopt").await;
    wait_for_state_revision(&harness.control.metrics, "rev-readopt").await;
    wait_until(|| harness.convergence() == AssignmentConvergence::Converged).await;
    assert_eq!(harness.worker_count(), 1);
    assert_eq!(
        harness.dial_attempts(),
        dials_after_connect,
        "re-adoption must not dial a duplicate Tunnel connection"
    );
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;

    // Control loss retains the last assignment and reconnect loops.
    let tls_before = harness.control.metrics.tls_accepts.load(Ordering::SeqCst);
    let reports_before = harness.control.metrics.state_bodies.lock().unwrap().len();
    let dials_before_loss = harness.dial_attempts();
    harness
        .control
        .push_snapshot("event: patch\ndata: {}\n\n".to_owned());
    wait_for_reconnecting(&mut harness.event_rx).await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    assert_eq!(harness.worker_count(), 1);
    assert_eq!(harness.dial_attempts(), dials_before_loss);

    // Repeated applied revision after reconnect resumes reporting without churn.
    harness.push_assignment("rev-readopt", &[&addr_a]);
    timeout(Duration::from_secs(5), async {
        loop {
            let resumed = {
                let bodies = harness.control.metrics.state_bodies.lock().unwrap();
                if bodies.len() > reports_before {
                    assert_eq!(
                        bodies.last(),
                        Some(&json!({ "revision": "rev-readopt" })),
                        "equal revision after reconnect must be acknowledged"
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
    .expect("equal revision after reconnect must be acknowledged");
    assert!(
        harness.control.metrics.tls_accepts.load(Ordering::SeqCst) > tls_before,
        "Control reconnect must open a new TLS connection"
    );
    assert_eq!(
        harness.dial_attempts(),
        dials_before_loss,
        "repeated revision must not churn address workers"
    );
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;

    // Retire again, then remote Server closure ends the worker without reconnect.
    harness.push_assignment("rev-retire-2", &[]);
    wait_for_applied(&mut harness.event_rx, "rev-retire-2").await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    let dials_before_remote_close = harness.dial_attempts();
    server_a.close_remotely().await;
    wait_until(|| harness.worker_count() == 0).await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        harness.dial_attempts(),
        dials_before_remote_close,
        "Retiring workers must not reconnect after remote closure"
    );

    backend.1.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_client_restart_fail_closed_requires_fresh_snapshot() {
    let (backend_cert, backend_key) = make_self_signed_cert(APP_HOSTNAME);
    let backend = spawn_tls_backend(&backend_cert, &backend_key, *b"pong").await;
    let mut first = ManagedClientHarness::start(backend.0, backend_cert.clone()).await;
    let server = first.spawn_server_node().await;
    let addr = format!("localhost:{}", server.tunnel_addr.port());

    first.push_assignment("rev-live", &[&addr]);
    wait_for_applied(&mut first.event_rx, "rev-live").await;
    wait_until_visitor_ok(server.public_addr, &first.backend_cert).await;
    first.shutdown().await;
    server.close_remotely().await;

    // Process restart restores no managed input: a fresh runtime dials nothing
    // until Control publishes a new full snapshot (no static fallback).
    let mut second = ManagedClientHarness::start(backend.0, backend_cert.clone()).await;
    sleep(Duration::from_millis(150)).await;
    assert_eq!(second.worker_count(), 0);
    assert_eq!(second.dial_attempts(), 0);
    assert_eq!(second.convergence(), AssignmentConvergence::Converged);

    let server_fresh = second.spawn_server_node().await;
    let addr_fresh = format!("localhost:{}", server_fresh.tunnel_addr.port());
    second.push_assignment("rev-fresh", &[&addr_fresh]);
    wait_for_applied(&mut second.event_rx, "rev-fresh").await;
    wait_until_visitor_ok(server_fresh.public_addr, &second.backend_cert).await;
    assert!(second.dial_attempts() >= 1);

    server_fresh.close_remotely().await;
    backend.1.abort();
    second.shutdown().await;
}

#[tokio::test]
async fn managed_client_isolates_per_address_failures() {
    let (backend_cert, backend_key) = make_self_signed_cert(APP_HOSTNAME);
    let backend = spawn_tls_backend(&backend_cert, &backend_key, *b"pong").await;
    let mut harness = ManagedClientHarness::start(backend.0, backend_cert.clone()).await;
    let server_ok = harness.spawn_server_node().await;
    let failing_port = {
        let sock = std::net::UdpSocket::bind(localhost(0)).unwrap();
        let port = sock.local_addr().unwrap().port();
        drop(sock);
        port
    };
    let addr_ok = format!("localhost:{}", server_ok.tunnel_addr.port());
    let addr_fail = format!("localhost:{failing_port}");

    harness.push_assignment("rev-partial", &[&addr_ok, &addr_fail]);
    wait_for_applied(&mut harness.event_rx, "rev-partial").await;
    wait_until_visitor_ok(server_ok.public_addr, &harness.backend_cert).await;
    wait_until(|| {
        matches!(
            harness.convergence(),
            AssignmentConvergence::PartiallyConverged
        )
    })
    .await;
    assert_eq!(harness.worker_count(), 2);
    // Healthy traffic continues while the unavailable address keeps its own worker.
    sleep(Duration::from_millis(100)).await;
    wait_until_visitor_ok(server_ok.public_addr, &harness.backend_cert).await;
    assert_eq!(harness.worker_count(), 2);
    assert!(
        matches!(
            harness.convergence(),
            AssignmentConvergence::PartiallyConverged
        ),
        "partial failure must not withdraw the whole Client assignment"
    );

    server_ok.close_remotely().await;
    backend.1.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn managed_client_fatal_worker_exits_the_runtime() {
    let tempdir = tempfile::tempdir().unwrap();
    let material = generate_control_mtls_material("runewarp-client-fatal");
    let control = ControlFixture::start(&material).await;
    let control_paths =
        write_control_ca_and_certs(tempdir.path().join("control").as_path(), &material);
    let client_identity = identity_from_cert_pem(&material.client_cert_pem);
    let identity_dir = tempdir.path().join("client-identity");
    fs::create_dir_all(&identity_dir).unwrap();
    fs::write(
        identity_dir.join(CLIENT_CERT_FILENAME),
        &material.client_cert_pem,
    )
    .unwrap();
    fs::write(
        identity_dir.join(CLIENT_KEY_FILENAME),
        &material.client_key_pem,
    )
    .unwrap();
    fs::write(
        identity_dir.join(CLIENT_IDENTITY_FILENAME),
        client_identity.to_string(),
    )
    .unwrap();

    let factory: runewarp::AddressWorkerFactory =
        Arc::new(|_address, _control| async { Err("worker exploded".to_owned()) }.boxed());
    let (mut controller, mut adapter) = AddressController::for_managed(factory);
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (_stop_tx, stop_rx) = oneshot::channel::<()>();
    let mut session = ManagedSession::new(
        ControlAddress::parse(&format!("localhost:{}", control.port)).unwrap(),
        ManagedSessionRole::Client,
        SessionMaterial {
            control_hostname: "localhost".to_owned(),
            trust: ControlTrust::CaFile(control_paths.ca_cert),
            identity: ControlClientIdentityMaterial::from_client_identity_dir(&identity_dir),
        },
    )
    .unwrap();

    let shutdown = controller.shutdown_handle();
    let controller_task = tokio::spawn(async move { controller.run().await });
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
            .await
    });

    control.push_snapshot(snapshot_sse(
        "rev-fatal",
        &json!({ "server_addresses": ["localhost:9"] }).to_string(),
    ));
    wait_for_applied(&mut event_rx, "rev-fatal").await;
    let result = timeout(Duration::from_secs(5), controller_task)
        .await
        .expect("fatal worker should end the runtime")
        .expect("runtime join");
    assert_eq!(result, Err("worker exploded".to_owned()));
    shutdown.request();
    let _ = timeout(Duration::from_secs(2), session_task).await;
    control.shutdown().await;
}

async fn wait_for_reconnecting(events: &mut mpsc::UnboundedReceiver<ManagedSessionEvent>) {
    timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            if matches!(event, ManagedSessionEvent::Reconnecting { .. }) {
                return;
            }
        }
        panic!("event stream closed before reconnecting");
    })
    .await
    .expect("timed out waiting for managed session reconnect");
}

async fn run_test_address_worker(
    settings: Arc<ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    server_address: ServerAddress,
    local_bind_addr: SocketAddr,
    control: AddressWorkerControl,
    dial_attempts: Arc<AtomicUsize>,
) -> Result<(), String> {
    let mut maintenance = control.subscribe_maintenance();
    loop {
        if control.shutdown_requested() {
            return Ok(());
        }
        // Establishing / reconnecting work stops on Retire. Connected retirement is
        // handled inside the tunnel run below and must not locally close the connection.
        if control.maintenance_intent() == MaintenanceIntent::Retire {
            return Ok(());
        }

        let resolved = match tokio::select! {
            _ = wait_for_shutdown(&control) => return Ok(()),
            changed = maintenance.changed() => {
                if changed.is_err()
                    || control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    return Ok(());
                }
                continue;
            }
            result = lookup_host((server_address.hostname().as_str(), server_address.port())) => {
                match result {
                    Ok(addrs) => {
                        let resolved: Vec<_> = addrs.collect();
                        // Prefer IPv4 so Linux CI (where localhost often resolves
                        // ::1 first) still reaches Servers bound to 127.0.0.1.
                        resolved
                            .iter()
                            .copied()
                            .find(SocketAddr::is_ipv4)
                            .or_else(|| resolved.first().copied())
                            .ok_or_else(|| "no resolved address".to_owned())
                    }
                    Err(error) => Err(error.to_string()),
                }
            }
        } {
            Ok(addr) => addr,
            Err(_) => {
                if !wait_for_retry_delay(Duration::from_millis(20), &control).await {
                    return Ok(());
                }
                continue;
            }
        };

        if control.maintenance_intent() == MaintenanceIntent::Retire {
            return Ok(());
        }

        dial_attempts.fetch_add(1, Ordering::SeqCst);
        let client = match tokio::select! {
            _ = wait_for_shutdown(&control) => return Ok(()),
            changed = maintenance.changed() => {
                if changed.is_err()
                    || control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    return Ok(());
                }
                continue;
            }
            result = PreparedClient::connect_to_server_address(
                &settings,
                &instance,
                local_bind_addr,
                &server_address,
                resolved,
            ) => result,
        } {
            Ok(client) => client,
            Err(_) => {
                if !wait_for_retry_delay(Duration::from_millis(20), &control).await {
                    return Ok(());
                }
                continue;
            }
        };

        control.observe_connected(&server_address);

        // Retire must not locally close: only process shutdown ends the tunnel run.
        let _run_result = client
            .run_until_shutdown({
                let control = control.clone();
                async move {
                    let mut maintenance = control.subscribe_maintenance();
                    let mut shutdown = control.subscribe_shutdown();
                    if control.shutdown_requested() {
                        return ShutdownMode::Graceful;
                    }
                    loop {
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || control.shutdown_requested() {
                                    return ShutdownMode::Graceful;
                                }
                            }
                            changed = maintenance.changed() => {
                                // Observe Retire without closing; re-adopt restores Maintain.
                                if changed.is_err() {
                                    return ShutdownMode::Graceful;
                                }
                            }
                        }
                    }
                }
            })
            .await;

        control.observe_disconnected(&server_address);

        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            return Ok(());
        }

        if !wait_for_retry_delay(Duration::from_millis(20), &control).await {
            return Ok(());
        }
    }
}

async fn wait_for_shutdown(control: &AddressWorkerControl) {
    let mut shutdown = control.subscribe_shutdown();
    loop {
        if control.shutdown_requested() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_for_retry_delay(delay: Duration, control: &AddressWorkerControl) -> bool {
    let mut maintenance = control.subscribe_maintenance();
    let mut shutdown = control.subscribe_shutdown();
    tokio::select! {
        _ = sleep(delay) => true,
        _ = shutdown.changed() => false,
        changed = maintenance.changed() => {
            changed.is_ok() && control.maintenance_intent() != MaintenanceIntent::Retire
        }
    }
}

async fn wait_for_applied(
    events: &mut mpsc::UnboundedReceiver<ManagedSessionEvent>,
    revision: &str,
) {
    timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            if matches!(
                event,
                ManagedSessionEvent::Applied { revision: ref applied }
                    if applied == revision
            ) {
                return;
            }
        }
        panic!("event stream closed before applied {revision}");
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for applied {revision}"));
}

async fn wait_for_state_revision(metrics: &FixtureMetrics, revision: &str) {
    timeout(Duration::from_secs(5), async {
        loop {
            {
                let bodies = metrics.state_bodies.lock().unwrap();
                if bodies
                    .iter()
                    .any(|body| body.get("revision").and_then(Value::as_str) == Some(revision))
                {
                    return;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for state revision {revision}"));
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        loop {
            if predicate() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition should become true");
}

async fn wait_until_visitor_ok(public_addr: SocketAddr, backend_cert: &CertificateDer<'static>) {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = visitor_ping(public_addr, backend_cert).await {
                assert_eq!(response, *b"pong");
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("visitor traffic should succeed");
}

async fn visitor_ping(
    public_addr: SocketAddr,
    backend_cert: &CertificateDer<'static>,
) -> io::Result<[u8; 4]> {
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store_with(backend_cert))
            .with_no_client_auth(),
    ));
    let tcp = TcpStream::connect(public_addr).await?;
    let mut tls = connector
        .connect(ServerName::try_from(APP_HOSTNAME.to_owned()).unwrap(), tcp)
        .await?;
    tls.write_all(b"ping").await?;
    let mut response = [0_u8; 4];
    tls.read_exact(&mut response).await?;
    Ok(response)
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
            let Ok((tcp_stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls_stream) = acceptor.accept(tcp_stream).await else {
                    return;
                };
                let mut request = [0_u8; 4];
                if tls_stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                let _ = tls_stream.write_all(&response).await;
                let _ = tls_stream.shutdown().await;
            });
        }
    });
    (addr, task)
}

fn identity_from_cert_pem(cert_pem: &str) -> ClientIdentity {
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
    client_identity_from_certificate_der(cert.as_ref()).unwrap()
}

fn snapshot_sse(revision: &str, input: &str) -> String {
    format!("event: snapshot\ndata: {{\"revision\":\"{revision}\",\"input\":{input}}}\n\n")
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

fn build_server_acceptor(material: &ControlMtlsMaterial) -> TlsAcceptor {
    let ca_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(material.ca_cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).unwrap();
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let server_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(material.server_cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let server_key = PrivateKeyDer::from_pem_slice(material.server_key_pem.as_bytes()).unwrap();

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .unwrap();
    config.alpn_protocols = vec![CONTROL_ALPN_H2.to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

async fn handle_request(
    request: Request<Incoming>,
    metrics: Arc<FixtureMetrics>,
    snapshots: Arc<AsyncMutex<mpsc::UnboundedReceiver<String>>>,
) -> Result<Response<HttpBoxBody<Bytes, Infallible>>, hyper::Error> {
    let path = request.uri().path().to_owned();
    if path == CLIENT_EVENTS_PATH {
        // Poll the shared snapshot channel without holding the mutex across
        // awaits so a replaced Control connection can receive later snapshots.
        let body = HttpBoxBody::new(StreamBody::new(SnapshotFeedStream { snapshots }));
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(body)
            .unwrap());
    }
    if path == CLIENT_STATE_PATH {
        let body = request.collect().await?.to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        metrics.state_bodies.lock().unwrap().push(value);
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(HttpBoxBody::new(Empty::new()))
            .unwrap());
    }
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(HttpBoxBody::new(Empty::new()))
        .unwrap())
}

struct SnapshotFeedStream {
    snapshots: Arc<AsyncMutex<mpsc::UnboundedReceiver<String>>>,
}

impl Stream for SnapshotFeedStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
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
