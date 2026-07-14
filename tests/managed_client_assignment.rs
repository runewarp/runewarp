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
    AddressController, AddressWorkerControl, AssignmentConvergenceTracker, CLIENT_CERT_FILENAME,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, CONTROL_ALPN_H2, ClientAssignmentAdapter,
    ClientAssignmentApply, ClientConfig, ClientIdentity, ClientTlsMode, ControlAddress,
    ControlClientIdentityMaterial, ControlTrust, LogLevel, MaintenanceIntent, ManagedSession,
    ManagedSessionEvent, ManagedSessionRole, PreparedClient, PublicHostname, Server, ServerAddress,
    ServerAdmission, ServerAuthorization, ServerBindConfig, ServerHostname, ServerTunnelConfig,
    ServiceConfig, SessionMaterial, ShutdownMode, client_identity_from_certificate_der,
    events_path, make_server_quic_config_with_client_admission, state_path,
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
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use common::{ControlMtlsMaterial, generate_control_mtls_material, write_control_ca_and_certs};

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
    task: JoinHandle<io::Result<()>>,
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
    worker_count: Arc<Mutex<usize>>,
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
        let worker_count = Arc::new(Mutex::new(0usize));

        let mut controller = AddressController::new();
        controller.disable_client_ready_log();
        let convergence = AssignmentConvergenceTracker::new();
        let (apply_tx, mut apply_rx) = mpsc::unbounded_channel::<ClientAssignmentApply>();
        let mut adapter = ClientAssignmentAdapter::new(apply_tx);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();

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

        let worker_count_task = Arc::clone(&worker_count);
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
            let shutdown = controller.shutdown_handle();
            loop {
                let drive_workers = controller.has_inflight_workers();
                *worker_count_task.lock().unwrap() = controller.worker_count();
                tokio::select! {
                    biased;
                    apply = apply_rx.recv() => {
                        let Some(ClientAssignmentApply { addresses, done }) = apply else {
                            break;
                        };
                        let _ = convergence.set_assigned(&addresses);
                        controller.replace_intent(&addresses, {
                            let settings = Arc::clone(&settings);
                            let convergence = convergence.clone();
                            move |server_address, control| {
                                let settings = Arc::clone(&settings);
                                let convergence = Some(convergence.clone());
                                async move {
                                    run_test_address_worker(
                                        settings,
                                        server_address,
                                        localhost(0),
                                        control,
                                        convergence,
                                    )
                                    .await
                                }
                            }
                        });
                        let _ = done.send(Ok(()));
                    }
                    completion = controller.next_completion(), if drive_workers => {
                        match completion {
                            Some(Ok(_)) => {}
                            Some(Err((_address, error))) => {
                                shutdown.request();
                                let _ = session_runtime.await;
                                return Err(error);
                            }
                            None => {}
                        }
                    }
                    () = &mut session_runtime => {
                        shutdown.request();
                        controller.run_until_idle().await?;
                        return Ok(());
                    }
                }
            }
            shutdown.request();
            controller.run_until_idle().await
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
            worker_count,
        }
    }

    async fn spawn_server_node(&self) -> QuicServerNode {
        let authorization = ServerAuthorization::from_tunnels(
            &ServerHostname::try_from("localhost").unwrap(),
            &[ServerTunnelConfig {
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
        let task = tokio::spawn(async move { server.run().await });
        QuicServerNode {
            public_addr,
            tunnel_addr,
            task,
        }
    }

    fn push_assignment(&self, revision: &str, addresses: &[&str]) {
        let input = json!({ "server_addresses": addresses });
        self.control
            .push_snapshot(snapshot_sse(revision, &input.to_string()));
    }

    fn worker_count(&self) -> usize {
        *self.worker_count.lock().unwrap()
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

    // 3. Cancel the never-connected failing address; healthy traffic continues.
    harness.push_assignment("rev-1b", &[&addr_a]);
    wait_for_applied(&mut harness.event_rx, "rev-1b").await;
    wait_for_state_revision(&harness.control.metrics, "rev-1b").await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;
    wait_until(|| harness.worker_count() <= 1).await;

    // 4. Add a second healthy Server; both serve during convergence.
    let addr_b = format!("localhost:{}", server_b.tunnel_addr.port());
    harness.push_assignment("rev-2", &[&addr_a, &addr_b]);
    wait_for_applied(&mut harness.event_rx, "rev-2").await;
    wait_for_state_revision(&harness.control.metrics, "rev-2").await;
    wait_until_visitor_ok(server_b.public_addr, &harness.backend_cert).await;
    wait_until_visitor_ok(server_a.public_addr, &harness.backend_cert).await;

    // 5. Empty assignment applies immediately and reports without awaiting Retiring exit.
    harness.push_assignment("rev-empty", &[]);
    wait_for_applied(&mut harness.event_rx, "rev-empty").await;
    wait_for_state_revision(&harness.control.metrics, "rev-empty").await;

    // 6. Fresh assignment after empty starts a new independent worker.
    let server_c = harness.spawn_server_node().await;
    let addr_c = format!("localhost:{}", server_c.tunnel_addr.port());
    harness.push_assignment("rev-3", &[&addr_c]);
    wait_for_applied(&mut harness.event_rx, "rev-3").await;
    wait_until_visitor_ok(server_c.public_addr, &harness.backend_cert).await;

    server_a.task.abort();
    server_b.task.abort();
    server_c.task.abort();
    backend.1.abort();
    harness.shutdown().await;
}

async fn run_test_address_worker(
    settings: Arc<ClientConfig>,
    server_address: ServerAddress,
    local_bind_addr: SocketAddr,
    control: AddressWorkerControl,
    convergence: Option<AssignmentConvergenceTracker>,
) -> Result<(), String> {
    let mut maintenance = control.subscribe_maintenance();
    loop {
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
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
                    Ok(mut addrs) => addrs.next().ok_or_else(|| "no resolved address".to_owned()),
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

        if let Some(tracker) = convergence.as_ref() {
            let _ = tracker.mark_connected(&server_address);
        }

        let _run_result = client
            .run_until_shutdown({
                let control = control.clone();
                async move {
                    wait_for_shutdown(&control).await;
                    ShutdownMode::Graceful
                }
            })
            .await;

        if let Some(tracker) = convergence.as_ref() {
            let _ = tracker.mark_disconnected(&server_address);
        }

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
    let cert = certs(&mut cert_pem.as_bytes()).next().unwrap().unwrap();
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
    let mut reader = std::io::Cursor::new(material.ca_cert_pem.as_bytes());
    let ca_certs: Vec<_> = certs(&mut reader).map(|cert| cert.unwrap()).collect();
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).unwrap();
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let mut cert_reader = std::io::Cursor::new(material.server_cert_pem.as_bytes());
    let server_certs: Vec<_> = certs(&mut cert_reader).map(|cert| cert.unwrap()).collect();
    let mut key_reader = std::io::Cursor::new(material.server_key_pem.as_bytes());
    let server_key = pkcs8_private_keys(&mut key_reader).next().unwrap().unwrap();

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, PrivateKeyDer::Pkcs8(server_key))
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
    if path == events_path(ManagedSessionRole::Client) {
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(16);
        tokio::spawn(async move {
            let mut snapshots = snapshots.lock().await;
            while let Some(sse) = snapshots.recv().await {
                if tx.send(Ok(Frame::data(Bytes::from(sse)))).await.is_err() {
                    break;
                }
            }
        });
        let stream = ReceiverStream { receiver: rx };
        let body = HttpBoxBody::new(StreamBody::new(stream));
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(body)
            .unwrap());
    }
    if path == state_path(ManagedSessionRole::Client) {
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

struct ReceiverStream {
    receiver: mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
}

impl Stream for ReceiverStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_recv(cx)
    }
}
