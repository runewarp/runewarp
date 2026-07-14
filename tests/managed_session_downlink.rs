//! Black-box integration tests for Managed-session Control downlinks (#153).

mod common;

use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::Stream;
use http::header::{CONTENT_TYPE, LOCATION};
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::BoxBody as HttpBoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use runewarp::{
    CONTROL_ALPN_H2, ConnectionError, ControlAddress, ControlClientIdentityMaterial, ControlTrust,
    DeferredClientAdapter, ManagedSession, ManagedSessionConnection, ManagedSessionEvent,
    ManagedSessionRole, SILENCE_TIMEOUT, SessionMaterial, events_path, load_control_tls_material,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use common::{
    ControlMtlsMaterial, generate_control_client_identity, generate_control_mtls_material,
    write_control_ca_and_certs,
};

const SNAPSHOT_SSE: &str =
    "event: snapshot\ndata: {\"revision\":\"rev-1\",\"input\":{\"server_addresses\":[]}}\n\n";
const REDIRECT_TARGET: &str = "/v1/client/events/redirect-target";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SseBehavior {
    SuccessSnapshot,
    Redirect,
    CloseAfterFirstByte,
    WrongContentType,
    NeverRespond,
}

#[derive(Debug)]
struct FixtureMetrics {
    tls_accepts: AtomicUsize,
    request_paths: Mutex<Vec<String>>,
    peer_cert_fingerprints: Mutex<Vec<String>>,
    concurrent_sse: AtomicUsize,
    max_concurrent_sse: AtomicUsize,
    redirect_target_hits: AtomicUsize,
    negotiated_alpn: Mutex<Vec<Option<Vec<u8>>>>,
}

impl FixtureMetrics {
    fn new() -> Self {
        Self {
            tls_accepts: AtomicUsize::new(0),
            request_paths: Mutex::new(Vec::new()),
            peer_cert_fingerprints: Mutex::new(Vec::new()),
            concurrent_sse: AtomicUsize::new(0),
            max_concurrent_sse: AtomicUsize::new(0),
            redirect_target_hits: AtomicUsize::new(0),
            negotiated_alpn: Mutex::new(Vec::new()),
        }
    }

    fn record_tls_accept(&self, alpn: Option<Vec<u8>>, peer_fingerprint: Option<String>) {
        self.tls_accepts.fetch_add(1, Ordering::SeqCst);
        if let Some(fingerprint) = peer_fingerprint {
            self.peer_cert_fingerprints
                .lock()
                .unwrap()
                .push(fingerprint);
        }
        self.negotiated_alpn.lock().unwrap().push(alpn);
    }

    async fn record_path(&self, path: &str) {
        self.request_paths.lock().unwrap().push(path.to_owned());
    }

    fn begin_sse(&self) {
        let current = self.concurrent_sse.fetch_add(1, Ordering::SeqCst) + 1;
        let mut max = self.max_concurrent_sse.load(Ordering::SeqCst);
        while current > max {
            match self.max_concurrent_sse.compare_exchange_weak(
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

    fn end_sse(&self) {
        self.concurrent_sse.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ControlFixture {
    port: u16,
    metrics: Arc<FixtureMetrics>,
    shutdown: Arc<Notify>,
    task: JoinHandle<()>,
}

impl ControlFixture {
    async fn start(material: &ControlMtlsMaterial, behavior: SseBehavior) -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = build_server_acceptor(material);
        let metrics = Arc::new(FixtureMetrics::new());
        let behavior = Arc::new(Mutex::new(behavior));
        let shutdown = Arc::new(Notify::new());
        let shutdown_wait = shutdown.clone();

        let metrics_task = metrics.clone();
        let behavior_task = behavior.clone();
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
                let behavior = behavior_task.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let (_, connection) = tls.get_ref();
                    let alpn = connection.alpn_protocol().map(|value| value.to_vec());
                    let peer_fingerprint = connection
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .map(cert_fingerprint);
                    metrics.record_tls_accept(alpn, peer_fingerprint);

                    let service = service_fn({
                        let metrics = metrics.clone();
                        let behavior = behavior.clone();
                        move |request: Request<Incoming>| {
                            let metrics = metrics.clone();
                            let behavior = behavior.clone();
                            async move { handle_request(request, metrics, behavior).await }
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
            shutdown,
            task,
        }
    }

    fn control_address(&self) -> ControlAddress {
        ControlAddress::parse(&format!("localhost:{}", self.port)).unwrap()
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.task.await;
    }
}

fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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
    let client_verifier = WebPkiClientVerifier::builder(roots.into()).build().unwrap();

    let server_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(material.server_cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let server_key = PrivateKeyDer::from_pem_slice(material.server_key_pem.as_bytes()).unwrap();

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
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

async fn handle_request(
    request: Request<Incoming>,
    metrics: Arc<FixtureMetrics>,
    behavior: Arc<Mutex<SseBehavior>>,
) -> Result<Response<ResponseBody>, Infallible> {
    let path = request.uri().path().to_owned();
    metrics.record_path(&path).await;

    if path == REDIRECT_TARGET {
        metrics.redirect_target_hits.fetch_add(1, Ordering::SeqCst);
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap());
    }

    if path != events_path(ManagedSessionRole::Client)
        && path != events_path(ManagedSessionRole::Server)
    {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap());
    }

    let behavior = *behavior.lock().unwrap();
    match behavior {
        SseBehavior::NeverRespond => std::future::pending().await,
        SseBehavior::Redirect => Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, REDIRECT_TARGET)
            .header(CONTENT_TYPE, "text/event-stream")
            .body(empty_body())
            .unwrap()),
        SseBehavior::WrongContentType => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(empty_body())
            .unwrap()),
        SseBehavior::CloseAfterFirstByte => {
            metrics.begin_sse();
            let metrics_drop = metrics.clone();
            let body = boxed_stream(CloseAfterFirstByteStream {
                sent_byte: false,
                metrics: Some(metrics_drop),
            });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/event-stream")
                .body(body)
                .unwrap())
        }
        SseBehavior::SuccessSnapshot => {
            metrics.begin_sse();
            let metrics_drop = metrics.clone();
            let body = boxed_stream(HoldAfterSnapshotStream {
                sent_snapshot: false,
                metrics: Some(metrics_drop),
            });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/event-stream")
                .body(body)
                .unwrap())
        }
    }
}

struct HoldAfterSnapshotStream {
    sent_snapshot: bool,
    metrics: Option<Arc<FixtureMetrics>>,
}

impl Stream for HoldAfterSnapshotStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.sent_snapshot {
            self.sent_snapshot = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(
                SNAPSHOT_SSE.as_bytes(),
            )))))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for HoldAfterSnapshotStream {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics.take() {
            metrics.end_sse();
        }
    }
}

struct CloseAfterFirstByteStream {
    sent_byte: bool,
    metrics: Option<Arc<FixtureMetrics>>,
}

impl Stream for CloseAfterFirstByteStream {
    type Item = Result<Frame<Bytes>, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.sent_byte {
            self.sent_byte = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"e")))))
        } else {
            Poll::Ready(None)
        }
    }
}

impl Drop for CloseAfterFirstByteStream {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics.take() {
            metrics.end_sse();
        }
    }
}

fn session_material(
    control_hostname: &str,
    ca_cert: &std::path::Path,
    client_cert: &std::path::Path,
    client_key: &std::path::Path,
) -> SessionMaterial {
    SessionMaterial {
        control_hostname: control_hostname.to_owned(),
        trust: ControlTrust::CaFile(ca_cert.to_path_buf()),
        identity: ControlClientIdentityMaterial {
            cert_path: client_cert.to_path_buf(),
            key_path: client_key.to_path_buf(),
        },
    }
}

#[test]
fn invalid_initial_tls_material_fails_session_construction() {
    let dir = tempdir().unwrap();
    let material = session_material(
        "localhost",
        &dir.path().join("missing-ca.crt"),
        &dir.path().join("missing-client.crt"),
        &dir.path().join("missing-client.key"),
    );
    let address = ControlAddress::parse("localhost:443").unwrap();

    assert!(
        ManagedSession::new(address, ManagedSessionRole::Client, material).is_err(),
        "invalid local material must fail initial startup"
    );
}

#[tokio::test]
async fn session_returns_shutdown_result_to_runtime() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let address = ControlAddress::parse("localhost:443").unwrap();
    let mut session =
        ManagedSession::new(address, ManagedSessionRole::Client, session_material).unwrap();

    let result = session
        .run(&mut DeferredClientAdapter, |_event| async {}, async {
            Err::<(), _>(std::io::Error::other("shutdown unavailable"))
        })
        .await;

    assert_eq!(result.unwrap_err().to_string(), "shutdown unavailable");
}

async fn connect_client(
    address: &ControlAddress,
    material: &SessionMaterial,
    role: ManagedSessionRole,
) -> ManagedSessionConnection {
    let tls = load_control_tls_material(material).unwrap();
    ManagedSessionConnection::connect(address, &tls, role)
        .await
        .unwrap()
}

#[tokio::test]
async fn mtls_peer_identity_is_observed_by_control_fixture() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );

    let _connection = connect_client(
        &fixture.control_address(),
        &session,
        ManagedSessionRole::Client,
    )
    .await;

    {
        let fingerprints = fixture.metrics.peer_cert_fingerprints.lock().unwrap();
        assert_eq!(fingerprints.len(), 1);
        let expected = cert_fingerprint(
            &CertificateDer::from_pem_slice(material.client_cert_pem.as_bytes()).unwrap(),
        );
        assert_eq!(fingerprints[0], expected);
    }

    fixture.shutdown().await;
}

#[tokio::test]
async fn http2_alpn_is_negotiated_on_fixture_and_client() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );

    let _connection = connect_client(
        &fixture.control_address(),
        &session,
        ManagedSessionRole::Client,
    )
    .await;

    {
        let alpn = fixture.metrics.negotiated_alpn.lock().unwrap();
        assert_eq!(alpn.len(), 1);
        assert_eq!(alpn[0].as_deref(), Some(CONTROL_ALPN_H2));
    }

    fixture.shutdown().await;
}

#[tokio::test]
async fn client_role_uses_exact_events_path_without_selectors() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );

    let _connection = connect_client(
        &fixture.control_address(),
        &session,
        ManagedSessionRole::Client,
    )
    .await;

    {
        let paths_seen = fixture.metrics.request_paths.lock().unwrap();
        assert_eq!(*paths_seen, vec![events_path(ManagedSessionRole::Client)]);
    }

    fixture.shutdown().await;
}

#[tokio::test]
async fn server_role_uses_exact_events_path_without_selectors() {
    let material = generate_control_mtls_material("runewarp-server-a");
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );

    let _connection = connect_client(
        &fixture.control_address(),
        &session,
        ManagedSessionRole::Server,
    )
    .await;

    {
        let paths_seen = fixture.metrics.request_paths.lock().unwrap();
        assert_eq!(*paths_seen, vec![events_path(ManagedSessionRole::Server)]);
    }

    fixture.shutdown().await;
}

#[tokio::test]
async fn exactly_one_sse_downlink_opens_per_connection() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );

    let _connection = connect_client(
        &fixture.control_address(),
        &session,
        ManagedSessionRole::Client,
    )
    .await;

    assert_eq!(fixture.metrics.concurrent_sse.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.metrics.max_concurrent_sse.load(Ordering::SeqCst), 1);

    fixture.shutdown().await;
}

#[tokio::test]
async fn redirects_are_not_followed_and_fail_the_session() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::Redirect).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let tls = load_control_tls_material(&session).unwrap();

    let error = match ManagedSessionConnection::connect(
        &fixture.control_address(),
        &tls,
        ManagedSessionRole::Client,
    )
    .await
    {
        Ok(_) => panic!("expected redirect to fail the SSE handshake"),
        Err(error) => error,
    };
    assert!(matches!(error, ConnectionError::SseRejected));

    {
        let paths_seen = fixture.metrics.request_paths.lock().unwrap();
        assert_eq!(*paths_seen, vec![events_path(ManagedSessionRole::Client)]);
        assert_eq!(
            fixture.metrics.redirect_target_hits.load(Ordering::SeqCst),
            0
        );
    }

    fixture.shutdown().await;
}

#[tokio::test]
async fn connection_is_ready_for_additional_streams_after_successful_sse() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );

    let connection = connect_client(
        &fixture.control_address(),
        &session,
        ManagedSessionRole::Client,
    )
    .await;

    assert!(connection.can_send_additional_request());

    fixture.shutdown().await;
}

#[tokio::test]
async fn sse_failure_establishes_a_new_tls_connection() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::CloseAfterFirstByte).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let address = fixture.control_address();

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut session_runner =
        ManagedSession::new(address, ManagedSessionRole::Client, session).unwrap();
    let metrics = fixture.metrics.clone();
    let runner = tokio::spawn(async move {
        session_runner
            .run(&mut DeferredClientAdapter, |_event| async {}, async {
                let _ = stop_rx.await;
            })
            .await;
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics.tls_accepts.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("expected a second TLS handshake after SSE failure");

    let _ = stop_tx.send(());
    let _ = runner.await;
    assert!(fixture.metrics.tls_accepts.load(Ordering::SeqCst) >= 2);

    fixture.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn response_header_stall_reconnects_after_first_snapshot_deadline() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::NeverRespond).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let runner = tokio::spawn(async move {
        session
            .run(
                &mut DeferredClientAdapter,
                move |event| {
                    let event_tx = event_tx.clone();
                    async move {
                        let _ = event_tx.send(event);
                    }
                },
                std::future::pending::<()>(),
            )
            .await;
    });

    let event = tokio::time::timeout(Duration::from_secs(61), event_rx.recv())
        .await
        .expect("connection establishment should time out")
        .expect("session should emit a reconnect event");
    assert!(matches!(event, ManagedSessionEvent::Reconnecting { .. }));

    runner.abort();
    let _ = runner.await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn silence_after_snapshot_reconnects_the_session() {
    let material = generate_control_mtls_material("runewarp-client-a");
    // SuccessSnapshot sends one valid snapshot, then holds the SSE body open with
    // no further bytes (including no keepalive comments).
    let fixture = ControlFixture::start(&material, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session_material = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let mut session = ManagedSession::new(
        fixture.control_address(),
        ManagedSessionRole::Client,
        session_material,
    )
    .unwrap();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let runner = tokio::spawn(async move {
        session
            .run(
                &mut DeferredClientAdapter,
                move |event| {
                    let event_tx = event_tx.clone();
                    async move {
                        let _ = event_tx.send(event);
                    }
                },
                std::future::pending::<()>(),
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
    .expect("first snapshot should apply before silence starts");

    let accepts_after_apply = fixture.metrics.tls_accepts.load(Ordering::SeqCst);
    assert_eq!(accepts_after_apply, 1);

    // Pause only after apply so connection setup uses real I/O timing.
    tokio::time::pause();
    tokio::time::advance(SILENCE_TIMEOUT + Duration::from_secs(1)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match event_rx.recv().await {
                Some(ManagedSessionEvent::Reconnecting { .. }) => break,
                Some(_) => {}
                None => panic!("event channel closed before silence reconnect"),
            }
        }
    })
    .await
    .expect("60s silence after a valid snapshot must fail the session");

    // Resume for the replacement TLS handshake after silence failure.
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture.metrics.tls_accepts.load(Ordering::SeqCst) > accepts_after_apply {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("silence failure must replace the whole Managed-session TLS connection");

    runner.abort();
    let _ = runner.await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn wrong_content_type_is_treated_as_session_failure() {
    let material = generate_control_mtls_material("runewarp-client-a");
    let fixture = ControlFixture::start(&material, SseBehavior::WrongContentType).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let tls = load_control_tls_material(&session).unwrap();

    let error = match ManagedSessionConnection::connect(
        &fixture.control_address(),
        &tls,
        ManagedSessionRole::Client,
    )
    .await
    {
        Ok(_) => panic!("expected wrong content type to fail the SSE handshake"),
        Err(error) => error,
    };
    assert!(matches!(error, ConnectionError::SseRejected));

    fixture.shutdown().await;
}

#[tokio::test]
async fn reloading_identity_files_presents_new_client_certificate() {
    let material_a = generate_control_mtls_material("runewarp-client-a");
    let (client_b_cert_pem, client_b_key_pem) =
        generate_control_client_identity(&material_a, "runewarp-client-b");
    let fixture = ControlFixture::start(&material_a, SseBehavior::SuccessSnapshot).await;
    let dir = tempdir().unwrap();
    let paths = write_control_ca_and_certs(dir.path(), &material_a);
    let session = session_material(
        "localhost",
        &paths.ca_cert,
        &paths.client_cert,
        &paths.client_key,
    );
    let address = fixture.control_address();

    let _first = connect_client(&address, &session, ManagedSessionRole::Client).await;
    let first_fingerprint = {
        let fingerprints = fixture.metrics.peer_cert_fingerprints.lock().unwrap();
        fingerprints[0].clone()
    };
    drop(_first);

    fs::write(&paths.client_cert, &client_b_cert_pem).unwrap();
    fs::write(&paths.client_key, &client_b_key_pem).unwrap();

    let _second = connect_client(&address, &session, ManagedSessionRole::Client).await;
    {
        let fingerprints = fixture.metrics.peer_cert_fingerprints.lock().unwrap();
        assert_eq!(fingerprints.len(), 2);
        assert_ne!(fingerprints[0], fingerprints[1]);
        assert_eq!(fingerprints[0], first_fingerprint);
        let expected_b = cert_fingerprint(
            &CertificateDer::from_pem_slice(client_b_cert_pem.as_bytes()).unwrap(),
        );
        assert_eq!(fingerprints[1], expected_b);
    }

    fixture.shutdown().await;
}
