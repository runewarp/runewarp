//! Black-box integration tests for Managed-session apply and state reporting (#154).

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::Stream;
use http::header::CONTENT_TYPE;
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody as HttpBoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use runewarp::{
    ApplyError, CONTROL_ALPN_H2, ClientManagedInput, ControlAddress, ControlClientIdentityMaterial,
    ControlTrust, DeferredClientAdapter, ManagedSession, ManagedSessionEvent, ManagedSessionRole,
    RoleAdapter, STATE_HEARTBEAT, SessionMaterial, events_path, state_path,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde_json::Value;
use std::sync::Mutex;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use common::{ControlMtlsMaterial, generate_control_mtls_material, write_control_ca_and_certs};

#[derive(Clone, Debug)]
enum StateBehavior {
    Success,
    FailOnceThenSuccess,
}

#[derive(Debug)]
struct FixtureMetrics {
    tls_accepts: AtomicUsize,
    request_paths: Mutex<Vec<String>>,
    state_bodies: Mutex<Vec<Value>>,
    state_statuses: Mutex<Vec<u16>>,
    concurrent_streams: AtomicUsize,
    max_concurrent_streams: AtomicUsize,
    state_fail_once: AtomicBool,
}

impl FixtureMetrics {
    fn new() -> Self {
        Self {
            tls_accepts: AtomicUsize::new(0),
            request_paths: Mutex::new(Vec::new()),
            state_bodies: Mutex::new(Vec::new()),
            state_statuses: Mutex::new(Vec::new()),
            concurrent_streams: AtomicUsize::new(0),
            max_concurrent_streams: AtomicUsize::new(0),
            state_fail_once: AtomicBool::new(false),
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
    snapshot_tx: tokio::sync::mpsc::UnboundedSender<String>,
    state_behavior: Arc<Mutex<StateBehavior>>,
    shutdown: Arc<Notify>,
    task: JoinHandle<()>,
}

impl ControlFixture {
    async fn start(material: &ControlMtlsMaterial, initial_snapshots: Vec<String>) -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = build_server_acceptor(material);
        let metrics = Arc::new(FixtureMetrics::new());
        let (snapshot_tx, snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
        for snapshot in initial_snapshots {
            snapshot_tx.send(snapshot).unwrap();
        }
        let snapshot_rx = Arc::new(AsyncMutex::new(snapshot_rx));
        let state_behavior = Arc::new(Mutex::new(StateBehavior::Success));
        let shutdown = Arc::new(Notify::new());
        let shutdown_wait = shutdown.clone();

        let metrics_task = metrics.clone();
        let snapshots_task = snapshot_rx.clone();
        let behavior_task = state_behavior.clone();
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
                let behavior = behavior_task.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    metrics.tls_accepts.fetch_add(1, Ordering::SeqCst);
                    let service = service_fn({
                        let metrics = metrics.clone();
                        let snapshots = snapshots.clone();
                        let behavior = behavior.clone();
                        move |request: Request<Incoming>| {
                            let metrics = metrics.clone();
                            let snapshots = snapshots.clone();
                            let behavior = behavior.clone();
                            async move { handle_request(request, metrics, snapshots, behavior).await }
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
            state_behavior,
            shutdown,
            task,
        }
    }

    fn control_address(&self) -> ControlAddress {
        ControlAddress::parse(&format!("localhost:{}", self.port)).unwrap()
    }

    fn push_snapshot(&self, sse: String) {
        self.snapshot_tx.send(sse).unwrap();
    }

    fn set_state_behavior(&self, behavior: StateBehavior) {
        if matches!(behavior, StateBehavior::FailOnceThenSuccess) {
            self.metrics.state_fail_once.store(true, Ordering::SeqCst);
        }
        *self.state_behavior.lock().unwrap() = behavior;
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.task.await;
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

fn snapshot_sse(revision: &str, input: &str) -> String {
    format!("event: snapshot\ndata: {{\"revision\":\"{revision}\",\"input\":{input}}}\n\n")
}

async fn handle_request(
    request: Request<Incoming>,
    metrics: Arc<FixtureMetrics>,
    snapshots: Arc<AsyncMutex<tokio::sync::mpsc::UnboundedReceiver<String>>>,
    behavior: Arc<Mutex<StateBehavior>>,
) -> Result<Response<ResponseBody>, Infallible> {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    metrics
        .request_paths
        .lock()
        .unwrap()
        .push(format!("{method} {path}"));

    if path == events_path(ManagedSessionRole::Client)
        || path == events_path(ManagedSessionRole::Server)
    {
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

    if path == state_path(ManagedSessionRole::Client)
        || path == state_path(ManagedSessionRole::Server)
    {
        metrics.begin_stream();
        let body = request.collect().await.unwrap().to_bytes();
        let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        metrics.state_bodies.lock().unwrap().push(parsed);

        let behavior = behavior.lock().unwrap().clone();
        let fail = match behavior {
            StateBehavior::Success => false,
            StateBehavior::FailOnceThenSuccess => {
                metrics.state_fail_once.swap(false, Ordering::SeqCst)
            }
        };
        metrics.end_stream();
        if fail {
            metrics.state_statuses.lock().unwrap().push(500);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    Full::new(Bytes::from_static(b"nope"))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap());
        }
        metrics.state_statuses.lock().unwrap().push(204);
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
    snapshots: Arc<AsyncMutex<tokio::sync::mpsc::UnboundedReceiver<String>>>,
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

fn session_material(
    ca_cert: &std::path::Path,
    client_cert: &std::path::Path,
    client_key: &std::path::Path,
) -> SessionMaterial {
    SessionMaterial {
        control_hostname: "localhost".to_owned(),
        trust: ControlTrust::CaFile(ca_cert.to_path_buf()),
        identity: ControlClientIdentityMaterial {
            cert_path: client_cert.to_path_buf(),
            key_path: client_key.to_path_buf(),
        },
    }
}

struct RecordingAdapter {
    applied: Mutex<Vec<ClientManagedInput>>,
}

impl RecordingAdapter {
    fn new() -> Self {
        Self {
            applied: Mutex::new(Vec::new()),
        }
    }
}

impl RoleAdapter for RecordingAdapter {
    type Input = ClientManagedInput;

    fn parse_input(input: &Value) -> Result<Self::Input, runewarp::InputError> {
        DeferredClientAdapter::parse_input(input)
    }

    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        self.applied.lock().unwrap().push(input);
        Ok(())
    }
}

/// Holds one apply until released so tests can observe mid-apply behavior.
struct GatedAdapter {
    applied_labels: Arc<Mutex<Vec<String>>>,
    gate_next: Arc<AtomicBool>,
    apply_started: Arc<Notify>,
    release: Arc<Notify>,
}

impl GatedAdapter {
    fn new() -> Self {
        Self {
            applied_labels: Arc::new(Mutex::new(Vec::new())),
            gate_next: Arc::new(AtomicBool::new(false)),
            apply_started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        }
    }

    fn label(input: &ClientManagedInput) -> String {
        input
            .server_addresses
            .first()
            .map(|address| address.hostname().as_str().to_owned())
            .unwrap_or_else(|| "empty".to_owned())
    }
}

impl RoleAdapter for GatedAdapter {
    type Input = ClientManagedInput;

    fn parse_input(input: &Value) -> Result<Self::Input, runewarp::InputError> {
        DeferredClientAdapter::parse_input(input)
    }

    async fn apply(&mut self, input: Self::Input) -> Result<(), ApplyError> {
        let label = Self::label(&input);
        if self.gate_next.swap(false, Ordering::SeqCst) {
            self.apply_started.notify_waiters();
            self.release.notified().await;
        }
        self.applied_labels.lock().unwrap().push(label);
        Ok(())
    }
}

#[tokio::test]
async fn apply_reports_revision_on_same_connection_with_exact_payload() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse("rev-1", "{\"server_addresses\":[]}")],
    )
    .await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = RecordingAdapter::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let runner = tokio::spawn(async move {
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
        adapter
    });

    let applied = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match event_rx.recv().await {
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-1" => break,
                Some(_) => {}
                None => panic!("event channel closed"),
            }
        }
    })
    .await;
    assert!(applied.is_ok(), "expected immediate apply of rev-1");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !fixture.metrics.state_bodies.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expected immediate state report");

    {
        let bodies = fixture.metrics.state_bodies.lock().unwrap();
        assert_eq!(bodies[0], serde_json::json!({"revision":"rev-1"}));
        assert_eq!(bodies[0].as_object().unwrap().len(), 1);
        let statuses = fixture.metrics.state_statuses.lock().unwrap();
        assert_eq!(statuses[0], 204);
        let paths = fixture.metrics.request_paths.lock().unwrap();
        assert!(
            paths
                .iter()
                .any(|path| path == &format!("GET {}", events_path(ManagedSessionRole::Client)))
        );
        assert!(
            paths
                .iter()
                .any(|path| path == &format!("PUT {}", state_path(ManagedSessionRole::Client)))
        );
        assert_eq!(fixture.metrics.tls_accepts.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .metrics
                .max_concurrent_streams
                .load(Ordering::SeqCst)
                >= 2
        );
    }

    let _ = stop_tx.send(());
    let adapter = runner.await.unwrap();
    assert_eq!(adapter.applied.lock().unwrap().len(), 1);
    fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn periodic_heartbeat_repeats_applied_revision_every_20_seconds() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse("rev-1", "{\"server_addresses\":[]}")],
    )
    .await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = DeferredClientAdapter;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let metrics = fixture.metrics.clone();
    let runner = tokio::spawn(async move {
        session
            .run(&mut adapter, |_event| async {}, async {
                let _ = stop_rx.await;
            })
            .await;
    });

    // Allow the immediate report (paused time does not auto-advance sleeps).
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !metrics.state_bodies.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("expected immediate state report");
    let after_immediate = metrics.state_bodies.lock().unwrap().len();
    assert!(after_immediate >= 1);

    let mut saw_heartbeat = false;
    for _ in 0..20 {
        if metrics.state_bodies.lock().unwrap().len() > after_immediate {
            saw_heartbeat = true;
            break;
        }
        // Advancing may race the session entering its heartbeat sleep; keep
        // advancing until the periodic report lands.
        tokio::time::advance(STATE_HEARTBEAT).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }
    assert!(saw_heartbeat, "expected heartbeat state report");

    {
        let bodies = metrics.state_bodies.lock().unwrap();
        assert!(bodies.len() >= 2);
        assert!(
            bodies
                .iter()
                .all(|body| body == &serde_json::json!({"revision":"rev-1"}))
        );
    }

    let _ = stop_tx.send(());
    let _ = runner.await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn state_report_failure_leaves_sse_open_and_retries_later() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse("rev-1", "{\"server_addresses\":[]}")],
    )
    .await;
    fixture.set_state_behavior(StateBehavior::FailOnceThenSuccess);
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = DeferredClientAdapter;
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let metrics = fixture.metrics.clone();
    let runner = tokio::spawn(async move {
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

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { .. })
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();

    // First report fails; SSE connection must remain the only TLS session.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.tls_accepts.load(Ordering::SeqCst), 1);

    // Push another snapshot while still on the same connection to prove SSE
    // survived the failed state write.
    fixture.push_snapshot(snapshot_sse("rev-2", "{\"server_addresses\":[]}"));

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-2"
            ) {
                break;
            }
        }
    })
    .await
    .expect("SSE must survive state-report failure");

    assert_eq!(metrics.tls_accepts.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ready = {
                let statuses = metrics.state_statuses.lock().unwrap();
                statuses.contains(&500) && statuses.contains(&204)
            };
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("failed report should retry successfully on a later write");

    let _ = stop_tx.send(());
    let _ = runner.await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn repeated_revision_skips_reconciliation_and_keeps_reporting() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse("rev-1", "{\"server_addresses\":[]}")],
    )
    .await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = RecordingAdapter::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let runner = tokio::spawn(async move {
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
        adapter
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { .. })
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();

    let reports_before = fixture.metrics.state_bodies.lock().unwrap().len();
    fixture.push_snapshot(snapshot_sse("rev-1", "{\"server_addresses\":[]}"));

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture.metrics.state_bodies.lock().unwrap().len() > reports_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("equal revision should still report");

    let _ = stop_tx.send(());
    let adapter = runner.await.unwrap();
    assert_eq!(
        adapter.applied.lock().unwrap().len(),
        1,
        "equal applied revision must not re-apply"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn invalid_input_is_not_acknowledged_and_preserves_prior_revision() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse("rev-1", "{\"server_addresses\":[]}")],
    )
    .await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = RecordingAdapter::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let runner = tokio::spawn(async move {
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
        adapter
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-1"
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();

    let reports_before = fixture.metrics.state_bodies.lock().unwrap().len();
    fixture.push_snapshot(snapshot_sse(
        "rev-bad",
        "{\"server_addresses\":[\"127.0.0.1\"]}",
    ));

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Rejected { revision }) if revision == "rev-bad"
            ) {
                break;
            }
        }
    })
    .await
    .expect("invalid input should be rejected locally");

    // Control keeps receiving the prior successfully applied revision on heartbeat
    // cadence; force an equal-revision resume report via another equal snapshot.
    fixture.push_snapshot(snapshot_sse("rev-1", "{\"server_addresses\":[]}"));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ready = {
                let bodies = fixture.metrics.state_bodies.lock().unwrap();
                bodies.len() > reports_before
                    && bodies
                        .iter()
                        .any(|body| body == &serde_json::json!({"revision":"rev-1"}))
            };
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    {
        let bodies = fixture.metrics.state_bodies.lock().unwrap();
        assert!(
            bodies
                .iter()
                .all(|body| body.get("revision").and_then(Value::as_str) != Some("rev-bad")),
            "rejected revision must not be acknowledged"
        );
    }

    let _ = stop_tx.send(());
    let adapter = runner.await.unwrap();
    assert_eq!(adapter.applied.lock().unwrap().len(), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn rollback_to_previously_applied_revision_is_applied() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse(
            "rev-a",
            "{\"server_addresses\":[\"a.example.test\"]}",
        )],
    )
    .await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = RecordingAdapter::new();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let runner = tokio::spawn(async move {
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
        adapter
    });

    for expected in ["rev-a"] {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    event_rx.recv().await,
                    Some(ManagedSessionEvent::Applied { revision }) if revision == expected
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    fixture.push_snapshot(snapshot_sse(
        "rev-b",
        "{\"server_addresses\":[\"b.example.test\"]}",
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-b"
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();

    fixture.push_snapshot(snapshot_sse(
        "rev-a",
        "{\"server_addresses\":[\"a.example.test\"]}",
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-a"
            ) {
                break;
            }
        }
    })
    .await
    .expect("previously applied revision remains a valid rollback candidate");

    let _ = stop_tx.send(());
    let adapter = runner.await.unwrap();
    assert_eq!(adapter.applied.lock().unwrap().len(), 3);
    fixture.shutdown().await;
}

#[tokio::test]
async fn mid_apply_keeps_prior_revision_reports_and_collapses_to_newest() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(
        &material,
        vec![snapshot_sse("rev-1", "{\"server_addresses\":[]}")],
    )
    .await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(&paths.ca_cert, &paths.client_cert, &paths.client_key);
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let mut adapter = GatedAdapter::new();
    let apply_started = adapter.apply_started.clone();
    let release = adapter.release.clone();
    let gate_next = adapter.gate_next.clone();
    let applied_labels = adapter.applied_labels.clone();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let runner = tokio::spawn(async move {
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

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-1"
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !fixture.metrics.state_bodies.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    gate_next.store(true, Ordering::SeqCst);
    fixture.push_snapshot(snapshot_sse(
        "rev-hold",
        "{\"server_addresses\":[\"hold.example.test\"]}",
    ));

    tokio::time::timeout(Duration::from_secs(5), async {
        apply_started.notified().await;
    })
    .await
    .expect("gated apply should start");

    // Pause only after the gated apply is in flight so heartbeat sleeps advance
    // deterministically without racing connection setup.
    tokio::time::pause();

    // While apply is held, Control must keep receiving the prior applied revision.
    let reports_before_heartbeat = fixture.metrics.state_bodies.lock().unwrap().len();
    for _ in 0..20 {
        if fixture.metrics.state_bodies.lock().unwrap().len() > reports_before_heartbeat {
            break;
        }
        tokio::time::advance(STATE_HEARTBEAT).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }
    {
        let bodies = fixture.metrics.state_bodies.lock().unwrap();
        assert!(
            bodies.len() > reports_before_heartbeat,
            "expected prior-revision heartbeat during in-flight apply"
        );
        assert!(
            bodies
                .iter()
                .all(|body| body == &serde_json::json!({"revision":"rev-1"})),
            "during apply, reports must stay on the prior successfully applied revision"
        );
    }

    // Supersede mid-apply: only the newest pending candidate should remain.
    fixture.push_snapshot(snapshot_sse(
        "rev-mid",
        "{\"server_addresses\":[\"mid.example.test\"]}",
    ));
    fixture.push_snapshot(snapshot_sse(
        "rev-newest",
        "{\"server_addresses\":[\"newest.example.test\"]}",
    ));
    // Invalid input must not displace the newest valid pending candidate.
    fixture.push_snapshot(snapshot_sse(
        "rev-bad",
        "{\"server_addresses\":[\"127.0.0.1\"]}",
    ));

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Rejected { revision }) if revision == "rev-bad"
            ) {
                break;
            }
        }
    })
    .await
    .expect("invalid mid-apply input should be rejected without ack");

    release.notify_waiters();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                event_rx.recv().await,
                Some(ManagedSessionEvent::Applied { revision }) if revision == "rev-newest"
            ) {
                break;
            }
        }
    })
    .await
    .expect("newest pending candidate should apply after the gated apply finishes");

    assert_eq!(
        *applied_labels.lock().unwrap(),
        vec![
            "empty".to_owned(),
            "hold.example.test".to_owned(),
            "newest.example.test".to_owned(),
        ],
        "superseded mid-apply candidate must be discarded"
    );

    let _ = stop_tx.send(());
    let _ = runner.await;
    fixture.shutdown().await;
}
