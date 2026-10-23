//! PROTOTYPE — throwaway. Not production code, not a protocol specification.
//!
//! Question: can Runewarp's ordinary-HTTP/3 Tunnel signaling and a Visitor byte carrier be
//! built on UNMODIFIED upstream `hyperium/h3` + `h3-quinn` (Quinn 0.11, rustls 0.23)?
//!
//! Everything runs in-process on loopback with in-memory certificates and required mTLS.
//! Results are written up in `docs/research/stock-h3-prototype.md`.
//!
//! Run: `cargo run --example prototype_stock_h3_signaling` (add `--release` for release timings).

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt::Debug,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future;
use h3::error::{Code, ConnectionError, StreamError};
use h3_quinn::quinn::{self, Endpoint, TransportConfig};
use http::{Method, Request, Response, StatusCode, header};
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{Level, field::Field};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

const SERVER_NAME: &str = "stock-h3.prototype";
const EVENTS_PATH: &str = "/v1/tunnel/events";
const WITHDRAWAL_PATH: &str = "/v1/tunnel/withdrawal";
const SLOTS_PATH: &str = "/v1/tunnel/slots";
const HOLD_PATH: &str = "/v1/test/hold";
const PROTOCOL_VERSION: u32 = 1;
const KEEPALIVE: Duration = Duration::from_millis(100);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
/// Stand-in for a PROXY v2 header: 16-byte magic followed by a big-endian u16 payload length.
const PROXY_STANDIN: &[u8; 16] = b"RWPXv2-STANDIN\r\n";

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type SrvStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type SrvSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type SrvRecv = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type SrvConn = h3::server::Connection<h3_quinn::Connection, Bytes>;
type CliStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type CliSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type CliRecv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

// ---------------------------------------------------------------------------------------------
// Wire observation: stock h3 `tracing` feature logs every decoded GOAWAY frame on the client.
// ---------------------------------------------------------------------------------------------

static H3_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct H3Capture;

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for H3Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        if let Ok(mut log) = H3_LOG.lock() {
            log.push(visitor.0);
        }
    }
}

/// Stream IDs of every GOAWAY the h3 client decoded since the last call.
fn take_client_goaways() -> Vec<u64> {
    let Ok(mut log) = H3_LOG.lock() else {
        return Vec::new();
    };
    let ids = log
        .iter()
        .filter_map(|line| line.split("graceful shutdown, last: StreamId(").nth(1))
        .filter_map(|rest| rest.split(')').next())
        .filter_map(|id| id.parse().ok())
        .collect();
    log.clear();
    ids
}

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

/// Deviations from the target contract that stock h3 exhibits but that do not stop the run.
static PARTIALS: Mutex<Vec<(&'static str, String)>> = Mutex::new(Vec::new());

fn partial(experiment: &'static str, finding: String) {
    println!("    PARTIAL: {finding}");
    if let Ok(mut partials) = PARTIALS.lock() {
        partials.push((experiment, finding));
    }
}

fn require(condition: bool, label: &str) -> Res<()> {
    condition
        .then_some(())
        .ok_or_else(|| format!("prototype assertion failed: {label}").into())
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn stream_code(error: &StreamError) -> String {
    match error {
        StreamError::RemoteTerminate { code, .. } => format!("RemoteTerminate({code:?})"),
        StreamError::StreamError { code, .. } => format!("StreamError({code:?})"),
        // `RemoteClosing` and `ConnectionError(_)` are `#[non_exhaustive]` unit/tuple variants,
        // so stock h3 does not let downstream code match them; fall back to Debug.
        other => format!("{other:?}"),
    }
}

fn is_remote_code(error: &StreamError, expected: Code) -> bool {
    matches!(error, StreamError::RemoteTerminate { code, .. } if *code == expected)
}

fn h3_varint(code: Code) -> Res<quinn::VarInt> {
    Ok(quinn::VarInt::from_u64(code.value())?)
}

fn ms(duration: Duration) -> String {
    format!("{:.3}ms", duration.as_secs_f64() * 1000.0)
}

struct Material {
    server_certificate: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    client_certificate: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
}

impl Material {
    fn new() -> Res<Self> {
        let server = generate_simple_self_signed(vec![SERVER_NAME.to_owned()])?;
        let client = generate_simple_self_signed(vec!["runewarp-client.prototype".to_owned()])?;
        Ok(Self {
            server_certificate: CertificateDer::from(server.cert),
            server_key: PrivatePkcs8KeyDer::from(server.signing_key.serialize_der()).into(),
            client_certificate: CertificateDer::from(client.cert),
            client_key: PrivatePkcs8KeyDer::from(client.signing_key.serialize_der()).into(),
        })
    }

    fn server_config(&self) -> Res<quinn::ServerConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.client_certificate.clone())?;
        // Default WebPkiClientVerifier builder requires a client certificate.
        let verifier = WebPkiClientVerifier::builder(roots.into()).build()?;
        let mut tls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.server_certificate.clone()],
                self.server_key.clone_key(),
            )?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        // Application 0-RTT disabled: tickets never advertise early data.
        tls.max_early_data_size = 0;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        config.transport = Arc::new(TransportConfig::default());
        Ok(config)
    }

    fn client_config(&self, early_data: bool) -> Res<quinn::ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.server_certificate.clone())?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![self.client_certificate.clone()],
                self.client_key.clone_key(),
            )?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = early_data;
        Ok(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        )))
    }
}

// ---------------------------------------------------------------------------------------------
// Event-stream state
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct EventState {
    version: u32,
    generation: String,
    replacing: bool,
}

impl EventState {
    fn sse(&self) -> Res<Bytes> {
        Ok(Bytes::from(format!(
            "event: state\ndata: {}\n\n",
            serde_json::to_string(self)?
        )))
    }

    fn is_valid(&self) -> bool {
        self.version == PROTOCOL_VERSION && self.generation.len() == 32
    }
}

// ---------------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------------

struct Instance {
    endpoint: Endpoint,
    addr: SocketAddr,
    generation: String,
    state: Arc<watch::Sender<EventState>>,
    conns: tokio::sync::Mutex<mpsc::UnboundedReceiver<Arc<ServerConn>>>,
}

impl Instance {
    fn start(material: &Material, name: &'static str) -> Res<Arc<Self>> {
        let endpoint = Endpoint::server(material.server_config()?, localhost(0))?;
        let addr = endpoint.local_addr()?;
        // Opaque random runtime generation; 128 bits rendered as hex.
        let generation = format!("{:032x}", rand::random::<u128>());
        let state = Arc::new(watch::Sender::new(EventState {
            version: PROTOCOL_VERSION,
            generation: generation.clone(),
            replacing: false,
        }));
        let (conn_tx, conn_rx) = mpsc::unbounded_channel();
        let accept_endpoint = endpoint.clone();
        let accept_state = state.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let conn_tx = conn_tx.clone();
                let state = accept_state.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(name, incoming, state, conn_tx).await {
                        println!("  [{name}] connection setup failed: {error}");
                    }
                });
            }
        });
        Ok(Arc::new(Self {
            endpoint,
            addr,
            generation,
            state,
            conns: tokio::sync::Mutex::new(conn_rx),
        }))
    }

    async fn next_conn(&self) -> Res<Arc<ServerConn>> {
        let mut conns = self.conns.lock().await;
        Ok(timeout(IO_TIMEOUT, conns.recv())
            .await?
            .ok_or("server accept loop ended")?)
    }

    fn set_replacing(&self, replacing: bool) {
        self.state.send_modify(|state| state.replacing = replacing);
    }
}

struct IdleSlot {
    kind: &'static str,
    stream: SrvStream,
}

enum Cmd {
    /// Graceful drain: stock `shutdown(1)`, then end event streams and reject idle slots.
    Drain(oneshot::Sender<Res<u64>>),
}

struct ServerConn {
    name: &'static str,
    peer_certificates: usize,
    peer_leaf_bytes: usize,
    quinn: quinn::Connection,
    slots: Mutex<VecDeque<IdleSlot>>,
    slot_added: Notify,
    withdrawn: AtomicBool,
    active: watch::Sender<usize>,
    draining: watch::Sender<bool>,
    cmd: mpsc::UnboundedSender<Cmd>,
    notes: Mutex<Vec<String>>,
    note_added: Notify,
    closed: watch::Sender<Option<String>>,
}

impl ServerConn {
    fn note(&self, note: String) {
        if let Ok(mut notes) = self.notes.lock() {
            notes.push(note);
        }
        self.note_added.notify_waiters();
    }

    async fn wait_note(&self, needle: &str) -> Res<String> {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let notified = self.note_added.notified();
            if let Some(note) = self
                .notes
                .lock()
                .map_err(|_| "poisoned")?
                .iter()
                .find(|note| note.contains(needle))
            {
                return Ok(note.clone());
            }
            timeout(deadline.saturating_duration_since(Instant::now()), notified)
                .await
                .map_err(|_| format!("[{}] note {needle:?} never arrived", self.name))?;
        }
    }

    fn idle_slots(&self) -> usize {
        self.slots.lock().map(|slots| slots.len()).unwrap_or(0)
    }

    async fn wait_idle_slots(&self, count: usize) -> Res<()> {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let notified = self.slot_added.notified();
            if self.idle_slots() >= count {
                return Ok(());
            }
            timeout(deadline.saturating_duration_since(Instant::now()), notified)
                .await
                .map_err(|_| format!("[{}] never reached {count} idle slots", self.name))?;
        }
    }

    /// Visitor placement: take one idle Client-provided slot and send response HEADERS plus
    /// the PROXY stand-in and buffered ClientHello immediately, without waiting on the Client.
    async fn assign(self: &Arc<Self>, client_hello: &[u8]) -> Res<ActiveVisitor> {
        if self.withdrawn.load(Ordering::SeqCst) || *self.draining.borrow() {
            return Err("placement refused: connection withdrawn or draining".into());
        }
        let slot = self
            .slots
            .lock()
            .map_err(|_| "poisoned")?
            .pop_front()
            .ok_or("no idle slot")?;
        self.active.send_modify(|active| *active += 1);
        let guard = ActiveGuard(self.clone());
        let started = Instant::now();
        let mut stream = slot.stream;
        let stream_id = stream.id().into_inner();
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let mut first = BytesMut::with_capacity(PROXY_STANDIN.len() + 2 + client_hello.len());
        first.extend_from_slice(PROXY_STANDIN);
        first.extend_from_slice(&u16::try_from(client_hello.len())?.to_be_bytes());
        first.extend_from_slice(client_hello);
        stream.send_data(first.freeze()).await?;
        let (send, recv) = stream.split();
        Ok(ActiveVisitor {
            kind: slot.kind,
            stream_id,
            started,
            send,
            recv,
            _guard: guard,
        })
    }
}

struct ActiveGuard(Arc<ServerConn>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.send_modify(|active| *active -= 1);
    }
}

struct ActiveVisitor {
    kind: &'static str,
    stream_id: u64,
    started: Instant,
    send: SrvSend,
    recv: SrvRecv,
    _guard: ActiveGuard,
}

async fn server_read_to_end(recv: &mut SrvRecv) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    while let Some(mut chunk) = recv.recv_data().await? {
        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok(out)
}

async fn serve_connection(
    name: &'static str,
    incoming: quinn::Incoming,
    state: Arc<watch::Sender<EventState>>,
    conn_tx: mpsc::UnboundedSender<Arc<ServerConn>>,
) -> Res<()> {
    let quinn_conn = timeout(IO_TIMEOUT, incoming).await??;
    let peer = quinn_conn
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or("mTLS peer identity missing")?;
    require(!peer.is_empty(), "non-empty mTLS peer chain")?;
    let mut h3_conn: SrvConn = h3::server::builder()
        .build(h3_quinn::Connection::new(quinn_conn.clone()))
        .await?;
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let conn = Arc::new(ServerConn {
        name,
        peer_certificates: peer.len(),
        peer_leaf_bytes: peer[0].len(),
        quinn: quinn_conn,
        slots: Mutex::new(VecDeque::new()),
        slot_added: Notify::new(),
        withdrawn: AtomicBool::new(false),
        active: watch::Sender::new(0),
        draining: watch::Sender::new(false),
        cmd: cmd_tx,
        notes: Mutex::new(Vec::new()),
        note_added: Notify::new(),
        closed: watch::Sender::new(None),
    });
    conn_tx.send(conn.clone()).map_err(|_| "instance dropped")?;

    // Requests are resolved inline so the loop knows the last stream ID that stock h3 counted
    // as accepted; that is what `shutdown(n)` uses to compute the GOAWAY identifier.
    let mut last_accepted: Option<u64> = None;
    let mut goaway: Option<u64> = None;
    let reason = loop {
        tokio::select! {
            accepted = h3_conn.accept() => match accepted {
                Ok(Some(resolver)) => {
                    let (request, mut stream) =
                        match timeout(IO_TIMEOUT, resolver.resolve_request()).await {
                            Ok(Ok(resolved)) => resolved,
                            Ok(Err(error)) => {
                                conn.note(format!("request resolve failed: {}", stream_code(&error)));
                                continue;
                            }
                            Err(_) => {
                                conn.note("request header timeout".to_owned());
                                continue;
                            }
                        };
                    let id = stream.id().into_inner();
                    last_accepted = Some(id);
                    // Stock h3 rejects only IDs strictly greater than its GOAWAY ID; enforce the
                    // RFC 9114 exclusive boundary for the ID equal to it.
                    if goaway.is_some_and(|boundary| id >= boundary) {
                        stream.stop_sending(Code::H3_REQUEST_REJECTED);
                        stream.stop_stream(Code::H3_REQUEST_REJECTED);
                        conn.note(format!("app-rejected boundary stream {id}"));
                        continue;
                    }
                    let conn = conn.clone();
                    let state = state.subscribe();
                    tokio::spawn(async move { dispatch(conn, request, stream, state).await });
                }
                Ok(None) => break "accept returned None".to_owned(),
                Err(error) => break format!("accept error {error:?} (h3_no_error={})", error.is_h3_no_error()),
            },
            Some(cmd) = cmd_rx.recv() => match cmd {
                Cmd::Drain(reply) => {
                    let result = h3_conn.shutdown(1).await;
                    let boundary = last_accepted.map_or(0, |id| id + 4);
                    goaway = Some(boundary);
                    conn.draining.send_replace(true);
                    let idle: Vec<IdleSlot> = conn.slots.lock().map(|mut s| s.drain(..).collect()).unwrap_or_default();
                    for mut slot in idle {
                        slot.stream.stop_sending(Code::H3_REQUEST_REJECTED);
                        slot.stream.stop_stream(Code::H3_REQUEST_REJECTED);
                    }
                    let _ = reply.send(result.map(|()| boundary).map_err(Into::into));
                }
            },
        }
    };
    conn.note(format!("connection ended: {reason}"));
    conn.closed.send_replace(Some(reason));
    Ok(())
}

async fn dispatch(
    conn: Arc<ServerConn>,
    request: Request<()>,
    mut stream: SrvStream,
    state: watch::Receiver<EventState>,
) {
    let result: Res<()> = async {
        match (request.method(), request.uri().path()) {
            (&Method::GET, EVENTS_PATH) => event_stream(&conn, stream, state).await,
            (&Method::CONNECT, _) => park_slot(&conn, "CONNECT", stream),
            (&Method::POST, SLOTS_PATH) => park_slot(&conn, "POST", stream),
            (&Method::PUT, WITHDRAWAL_PATH) => withdrawal(&conn, stream).await,
            (&Method::GET, HOLD_PATH) => {
                stream
                    .send_response(Response::builder().status(StatusCode::OK).body(())?)
                    .await?;
                Ok(stream.finish().await?)
            }
            _ => {
                stream
                    .send_response(Response::builder().status(StatusCode::NOT_FOUND).body(())?)
                    .await?;
                Ok(stream.finish().await?)
            }
        }
    }
    .await;
    if let Err(error) = result {
        conn.note(format!("dispatch error: {error}"));
    }
}

fn park_slot(conn: &ServerConn, kind: &'static str, mut stream: SrvStream) -> Res<()> {
    if conn.withdrawn.load(Ordering::SeqCst) || *conn.draining.borrow() {
        stream.stop_sending(Code::H3_REQUEST_REJECTED);
        stream.stop_stream(Code::H3_REQUEST_REJECTED);
        return Ok(());
    }
    conn.slots
        .lock()
        .map_err(|_| "poisoned")?
        .push_back(IdleSlot { kind, stream });
    conn.slot_added.notify_waiters();
    Ok(())
}

async fn event_stream(
    conn: &ServerConn,
    mut stream: SrvStream,
    mut state: watch::Receiver<EventState>,
) -> Res<()> {
    let id = stream.id().into_inner();
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-store")
                .body(())?,
        )
        .await?;
    let initial = state.borrow_and_update().sse()?;
    stream.send_data(initial).await?;
    let mut draining = conn.draining.subscribe();
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await;
    loop {
        // Only the trigger is raced; the send itself is never cancelled mid-write (see h3 #360).
        let frame = tokio::select! {
            changed = state.changed() => {
                changed?;
                state.borrow_and_update().sse()?
            }
            _ = keepalive.tick() => Bytes::from_static(b": keepalive\n\n"),
            _ = async { draining.wait_for(|draining| *draining).await.map(|_| ()) } => {
                stream.finish().await?;
                conn.note(format!("event stream {id} finished for drain"));
                return Ok(());
            }
        };
        if let Err(error) = stream.send_data(frame).await {
            conn.note(format!("event stream {id} ended: {}", stream_code(&error)));
            return Ok(());
        }
    }
}

async fn withdrawal(conn: &ServerConn, mut stream: SrvStream) -> Res<()> {
    let received = Instant::now();
    let body = stream.recv_data().await?;
    if body.is_some() {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())?,
            )
            .await?;
        return Ok(stream.finish().await?);
    }
    conn.withdrawn.store(true, Ordering::SeqCst);
    let active_at_commit = *conn.active.borrow();
    conn.note(format!(
        "withdrawal committed with {active_at_commit} active visitor(s)"
    ));
    conn.active
        .subscribe()
        .wait_for(|active| *active == 0)
        .await?;
    let quiescent = Instant::now();
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
        )
        .await?;
    stream.finish().await?;
    conn.note(format!(
        "withdrawal 204 sent; request->quiescent {}, quiescent->204+FIN {}",
        ms(quiescent - received),
        ms(quiescent.elapsed())
    ));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------------------------

struct TunnelClient {
    endpoint: Endpoint,
    quinn: quinn::Connection,
    sender: Sender,
    driver: JoinHandle<ConnectionError>,
    setup: Duration,
}

impl TunnelClient {
    /// Every Tunnel connection uses a new Quinn endpoint, i.e. a new UDP socket and 4-tuple.
    async fn connect(material: &Material, addr: SocketAddr) -> Res<Self> {
        let mut endpoint = Endpoint::client(localhost(0))?;
        endpoint.set_default_client_config(material.client_config(false)?);
        let started = Instant::now();
        let quinn = timeout(IO_TIMEOUT, endpoint.connect(addr, SERVER_NAME)?).await??;
        let (mut driver, sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(quinn.clone()))
            .await?;
        let setup = started.elapsed();
        let driver = tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });
        Ok(Self {
            endpoint,
            quinn,
            sender,
            driver,
            setup,
        })
    }

    async fn subscribe(&self) -> Res<EventSub> {
        let mut sender = self.sender.clone();
        let mut stream = sender
            .send_request(
                Request::get(format!("https://{SERVER_NAME}{EVENTS_PATH}"))
                    .header(header::ACCEPT, "text/event-stream")
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let response = timeout(IO_TIMEOUT, stream.recv_response()).await??;
        require(response.status() == StatusCode::OK, "event stream 200")?;
        require(
            response.headers().get(header::CONTENT_TYPE)
                == Some(&header::HeaderValue::from_static("text/event-stream")),
            "event stream content type",
        )?;
        let (items_tx, items) = mpsc::unbounded_channel();
        let (cancel, cancel_rx) = oneshot::channel();
        tokio::spawn(event_reader(stream, items_tx, cancel_rx));
        Ok(EventSub {
            items,
            cancel: Some(cancel),
        })
    }

    async fn close(self, reason: &'static [u8]) -> Res<ConnectionError> {
        self.quinn.close(h3_varint(Code::H3_NO_ERROR)?, reason);
        let driver_error = timeout(IO_TIMEOUT, self.driver).await??;
        self.endpoint.wait_idle().await;
        Ok(driver_error)
    }
}

#[derive(Debug)]
enum SseItem {
    State(EventState),
    Keepalive,
    Ended(String),
}

struct EventSub {
    items: mpsc::UnboundedReceiver<SseItem>,
    cancel: Option<oneshot::Sender<bool>>,
}

impl EventSub {
    async fn next(&mut self) -> Res<SseItem> {
        Ok(timeout(IO_TIMEOUT, self.items.recv())
            .await?
            .ok_or("event reader ended")?)
    }

    async fn next_state(&mut self) -> Res<(EventState, usize)> {
        let mut keepalives = 0;
        loop {
            match self.next().await? {
                SseItem::State(state) => return Ok((state, keepalives)),
                SseItem::Keepalive => keepalives += 1,
                SseItem::Ended(reason) => {
                    return Err(format!("event stream ended: {reason}").into());
                }
            }
        }
    }

    async fn next_keepalive(&mut self) -> Res<()> {
        loop {
            match self.next().await? {
                SseItem::Keepalive => return Ok(()),
                SseItem::State(_) => {}
                SseItem::Ended(reason) => {
                    return Err(format!("event stream ended: {reason}").into());
                }
            }
        }
    }

    async fn ended(&mut self) -> Res<String> {
        loop {
            if let SseItem::Ended(reason) = self.next().await? {
                return Ok(reason);
            }
        }
    }

    /// Client-side reset: the GET already sent FIN, so STOP_SENDING is the only signal.
    /// `flush` keeps polling the receive half after `stop_sending`, which lets h3-quinn's
    /// in-flight read complete (on the next keepalive) and apply the deferred stop code.
    fn reset(&mut self, flush: bool) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(flush);
        }
    }
}

async fn event_reader(
    mut stream: CliStream,
    items: mpsc::UnboundedSender<SseItem>,
    mut cancel: oneshot::Receiver<bool>,
) {
    let mut buffer = String::new();
    loop {
        let chunk = tokio::select! {
            flush = &mut cancel => {
                let flush = flush.unwrap_or(false);
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                if flush {
                    let _ = timeout(KEEPALIVE * 3, stream.recv_data()).await;
                }
                let _ = items.send(SseItem::Ended(format!(
                    "client STOP_SENDING H3_REQUEST_CANCELLED (flush={})",
                    flush
                )));
                return;
            }
            chunk = stream.recv_data() => match chunk {
                Ok(Some(mut chunk)) => chunk.copy_to_bytes(chunk.remaining()),
                Ok(None) => {
                    let _ = items.send(SseItem::Ended("server FIN".to_owned()));
                    return;
                }
                Err(error) => {
                    let _ = items.send(SseItem::Ended(stream_code(&error)));
                    return;
                }
            },
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buffer.find("\n\n") {
            let block: String = buffer.drain(..end + 2).collect();
            let item = parse_sse_block(&block);
            if items.send(item).is_err() {
                return;
            }
        }
    }
}

fn parse_sse_block(block: &str) -> SseItem {
    let mut data = None;
    for line in block.lines() {
        if line.starts_with(':') {
            return SseItem::Keepalive;
        }
        if let Some(value) = line.strip_prefix("data: ") {
            data = Some(value);
        }
    }
    match data.map(serde_json::from_str::<EventState>) {
        Some(Ok(state)) if state.is_valid() => SseItem::State(state),
        other => SseItem::Ended(format!("invalid event block: {other:?}")),
    }
}

#[derive(Clone, Copy, Debug)]
enum SlotKind {
    Connect,
    Post,
}

struct SlotPool {
    sender: Sender,
    kind: SlotKind,
    replenish: AtomicBool,
    opened: AtomicUsize,
    assigned: mpsc::UnboundedSender<ClientVisitor>,
}

struct ClientVisitor {
    stream_id: u64,
    received: Instant,
    proxy_len: usize,
    client_hello: Vec<u8>,
    send: CliSend,
    recv: CliRecv,
}

/// Pre-open one receive slot. The request HEADERS go out immediately; the request body stays
/// open. When the Server assigns the slot, the response is read and the slot is replenished.
fn open_slot(pool: Arc<SlotPool>) -> BoxFuture<Res<u64>> {
    Box::pin(async move {
        let request = match pool.kind {
            SlotKind::Connect => Request::builder()
                .method(Method::CONNECT)
                .uri(format!("{SERVER_NAME}:443"))
                .body(())?,
            SlotKind::Post => Request::post(format!("https://{SERVER_NAME}{SLOTS_PATH}"))
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(())?,
        };
        let mut sender = pool.sender.clone();
        let mut stream = sender.send_request(request).await?;
        let stream_id = stream.id().into_inner();
        pool.opened.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let Ok(response) = stream.recv_response().await else {
                return;
            };
            if response.status() != StatusCode::OK {
                return;
            }
            if pool.replenish.load(Ordering::SeqCst) {
                let _ = open_slot(pool.clone()).await;
            }
            let mut first = BytesMut::new();
            let need = |first: &BytesMut| {
                (first.len() >= PROXY_STANDIN.len() + 2).then(|| {
                    PROXY_STANDIN.len()
                        + 2
                        + usize::from(u16::from_be_bytes([first[16], first[17]]))
                })
            };
            while need(&first).is_none_or(|need| first.len() < need) {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        first.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()))
                    }
                    _ => return,
                }
            }
            let received = Instant::now();
            let total = need(&first).unwrap_or(0);
            if first.len() != total || &first[..16] != PROXY_STANDIN {
                return;
            }
            let (send, recv) = stream.split();
            let _ = pool.assigned.send(ClientVisitor {
                stream_id,
                received,
                proxy_len: PROXY_STANDIN.len() + 2,
                client_hello: first[18..].to_vec(),
                send,
                recv,
            });
        });
        Ok(stream_id)
    })
}

/// Stock h3 exposes peer STOP_SENDING only as a write error (hyperium/h3#350), so probe by
/// writing one byte every 5ms for up to 250ms.
async fn server_write_until_error(send: &mut SrvSend) -> Result<(), StreamError> {
    for _ in 0..50 {
        send.send_data(Bytes::from_static(b"x")).await?;
        sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

async fn client_write_until_error(send: &mut CliSend) -> Result<(), StreamError> {
    for _ in 0..50 {
        send.send_data(Bytes::from_static(b"y")).await?;
        sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

async fn client_read_to_end(recv: &mut CliRecv) -> Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    while let Some(mut chunk) = recv.recv_data().await? {
        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Experiments
// ---------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Res<()> {
    tracing_subscriber::registry()
        .with(
            H3Capture.with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                meta.target().starts_with("h3") && *meta.level() <= Level::INFO
            })),
        )
        .init();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    println!("PROTOTYPE — stock hyperium/h3 signaling ({profile} build, loopback)");
    let material = Material::new()?;
    let outcomes = [
        ("1 build+mTLS+no-0RTT", exp1(&material).await),
        ("2 GOAWAY", exp2(&material).await),
        ("3 event stream", exp3(&material).await),
        (
            "4 slots CONNECT (+5 withdrawal)",
            exp4(&material, SlotKind::Connect).await,
        ),
        ("4 slots POST", exp4(&material, SlotKind::Post).await),
        ("6 replacement via forwarder", exp6(&material).await),
    ];
    println!("\n== Result matrix");
    let partials = PARTIALS.lock().map_err(|_| "poisoned")?.clone();
    let mut failed = false;
    for (name, outcome) in &outcomes {
        let findings: Vec<&String> = partials
            .iter()
            .filter(|(experiment, _)| name.starts_with(experiment))
            .map(|(_, finding)| finding)
            .collect();
        match outcome {
            Err(error) => {
                failed = true;
                println!("RESULT {name}: FAIL {error}");
            }
            Ok(()) if findings.is_empty() => println!("RESULT {name}: PASS"),
            Ok(()) => println!("RESULT {name}: PARTIAL ({} finding(s))", findings.len()),
        }
    }
    require(!failed, "no experiment failed")
}

async fn exp1(material: &Material) -> Res<()> {
    println!("\n== 1: stock h3 + h3-quinn, ALPN h3, required mTLS, application 0-RTT disabled");
    let server = Instance::start(material, "exp1")?;

    // A Client without a certificate must be refused by the required-mTLS verifier.
    let mut roots = RootCertStore::empty();
    roots.add(material.server_certificate.clone())?;
    let mut anonymous = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    anonymous.alpn_protocols = vec![b"h3".to_vec()];
    let mut anon_endpoint = Endpoint::client(localhost(0))?;
    anon_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(anonymous)?,
    )));
    let anon = timeout(IO_TIMEOUT, anon_endpoint.connect(server.addr, SERVER_NAME)?).await?;
    // TLS 1.3 client auth failure surfaces after the client-side handshake completes.
    let anon_refused = match anon {
        Err(error) => format!("handshake error: {error}"),
        Ok(connection) => format!("closed: {}", connection.closed().await),
    };
    println!("  no-client-cert connection: {anon_refused}");
    require(
        anon_refused.contains("certificate"),
        "anonymous client refused",
    )?;

    let client = TunnelClient::connect(material, server.addr).await?;
    let conn = server.next_conn().await?;
    let alpn = client
        .quinn
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .ok_or("negotiated ALPN missing")?;
    println!(
        "  ALPN={:?} peer chain certs={} leaf={}B authenticated h3 setup {}",
        String::from_utf8_lossy(&alpn),
        conn.peer_certificates,
        conn.peer_leaf_bytes,
        ms(client.setup)
    );
    require(alpn == b"h3", "ALPN h3")?;
    client.close(b"done").await?;

    // 0-RTT probe: a Client willing to send early data resumes; the server ticket must refuse it.
    let mut probe = Endpoint::client(localhost(0))?;
    probe.set_default_client_config(material.client_config(true)?);
    let first = timeout(IO_TIMEOUT, probe.connect(server.addr, SERVER_NAME)?).await??;
    sleep(Duration::from_millis(50)).await; // allow NewSessionTicket delivery
    first.close(0_u8.into(), b"ticket");
    let second = probe.connect(server.addr, SERVER_NAME)?;
    let zero_rtt = match second.into_0rtt() {
        Ok((connection, _accepted)) => {
            connection.close(0_u8.into(), b"");
            "0-RTT offered (unexpected)"
        }
        Err(connecting) => {
            let resumed = timeout(IO_TIMEOUT, connecting).await??;
            resumed.close(0_u8.into(), b"");
            "0-RTT unavailable on resumed connection (ticket max_early_data=0)"
        }
    };
    println!("  early-data-enabled probe client: {zero_rtt}");
    require(
        zero_rtt.starts_with("0-RTT unavailable"),
        "no application 0-RTT",
    )?;
    probe.wait_idle().await;
    server.endpoint.close(0_u8.into(), b"");
    Ok(())
}

struct GoawayCase {
    label: &'static str,
    requests: usize,
    max_requests: usize,
    /// Reject IDs >= the GOAWAY ID in the application (stock h3 only rejects IDs > it).
    app_guard: bool,
    /// Keep calling `accept()` after it returns `None` (stock docs suggest stopping).
    accept_after_none: bool,
}

/// Manual server loop: accept two requests, then call stock `shutdown(max_requests)` while the
/// rest are queued at Quinn, and record what stock h3 hands to the application afterwards.
async fn goaway_case(material: &Material, case: GoawayCase) -> Res<()> {
    let endpoint = Endpoint::server(material.server_config()?, localhost(0))?;
    let addr = endpoint.local_addr()?;
    let (sent_tx, sent_rx) = oneshot::channel::<()>();
    let server_endpoint = endpoint.clone();
    let server = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.ok_or("no incoming")?;
        let quinn_conn = timeout(IO_TIMEOUT, incoming).await??;
        let mut h3_conn: SrvConn = h3::server::builder()
            .build(h3_quinn::Connection::new(quinn_conn.clone()))
            .await?;
        let mut held = Vec::new();
        for _ in 0..2 {
            let resolver = h3_conn.accept().await?.ok_or("early None")?;
            let (_, stream) = resolver.resolve_request().await?;
            held.push(stream);
        }
        sent_rx.await?;
        sleep(Duration::from_millis(50)).await; // every request stream is at Quinn now
        let last = held
            .last()
            .map(|s| s.id().into_inner())
            .ok_or("none held")?;
        h3_conn.shutdown(case.max_requests).await?;
        // Mirrors upstream: `last_accepted_stream + max_requests` (StreamId + n adds n indices).
        let boundary = last + 4 * u64::try_from(case.max_requests)?;
        let mut seen = Vec::new();
        for mut stream in held {
            seen.push(format!(
                "{}:accepted-before-GOAWAY",
                stream.id().into_inner()
            ));
            stream
                .send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            stream.finish().await?;
        }
        let mut nones = 0;
        loop {
            match timeout(Duration::from_millis(200), h3_conn.accept()).await {
                Ok(Ok(Some(resolver))) => {
                    let (_, mut stream) = resolver.resolve_request().await?;
                    let id = stream.id().into_inner();
                    if case.app_guard && id >= boundary {
                        stream.stop_sending(Code::H3_REQUEST_REJECTED);
                        stream.stop_stream(Code::H3_REQUEST_REJECTED);
                        seen.push(format!("{id}:handed-to-app,app-rejected"));
                    } else {
                        seen.push(format!("{id}:handed-to-app,processed"));
                        stream
                            .send_response(Response::builder().status(StatusCode::OK).body(())?)
                            .await?;
                        stream.finish().await?;
                    }
                }
                Ok(Ok(None)) => {
                    nones += 1;
                    seen.push("accept()=None".to_owned());
                    if !case.accept_after_none || nones == 3 {
                        break;
                    }
                }
                Ok(Err(error)) => {
                    seen.push(format!("accept() error {error:?}"));
                    break;
                }
                Err(_) => {
                    seen.push("accept() pending 200ms".to_owned());
                    break;
                }
            }
        }
        sleep(Duration::from_millis(50)).await;
        drop(h3_conn); // stock Drop closes QUIC with H3_NO_ERROR
        Ok::<_, Box<dyn Error + Send + Sync>>((boundary, seen))
    });

    let client = TunnelClient::connect(material, addr).await?;
    take_client_goaways();
    let mut streams = Vec::new();
    let mut sender = client.sender.clone();
    for _ in 0..case.requests {
        let mut stream = sender
            .send_request(Request::get(format!("https://{SERVER_NAME}{HOLD_PATH}")).body(())?)
            .await?;
        stream.finish().await?;
        streams.push(stream);
    }
    let _ = sent_tx.send(());
    let mut outcomes = Vec::new();
    for mut stream in streams {
        let id = stream.id().into_inner();
        let outcome = match timeout(IO_TIMEOUT, stream.recv_response()).await? {
            Ok(response) => format!("{id}:{}", response.status().as_u16()),
            Err(error) => format!("{id}:{}", stream_code(&error)),
        };
        outcomes.push((id, outcome));
    }
    sleep(Duration::from_millis(20)).await;
    let goaways = take_client_goaways();
    let after = match sender
        .send_request(Request::get(format!("https://{SERVER_NAME}{HOLD_PATH}")).body(())?)
        .await
    {
        Ok(stream) => format!("opened stream {} (unexpected)", stream.id().into_inner()),
        Err(error) => format!("refused locally: {}", stream_code(&error)),
    };
    let (boundary, seen) = server.await??;
    let driver = timeout(IO_TIMEOUT, client.driver).await??;
    println!(
        "  [{}] {} requests, accept 0,4, shutdown({}) -> computed GOAWAY {boundary}",
        case.label, case.requests, case.max_requests
    );
    println!("    client decoded GOAWAY ids (stock h3 tracing): {goaways:?}");
    println!("    server view: {seen:?}");
    println!(
        "    client outcomes: {:?}",
        outcomes.iter().map(|(_, o)| o).collect::<Vec<_>>()
    );
    println!("    new request after GOAWAY: {after}");
    println!("    client driver ended: {driver:?}");
    require(goaways.first() == Some(&boundary), "GOAWAY id observed")?;
    require(after.starts_with("refused locally"), "no new requests")?;
    require(outcomes[0].1 == "0:200", "stream 0 complete")?;
    require(outcomes[1].1 == "4:200", "stream 4 complete")?;
    let final_goaway = *goaways.last().unwrap_or(&boundary);
    let mut violations = Vec::new();
    for (id, outcome) in &outcomes {
        let processed = outcome.ends_with(":200");
        let rejected = outcome.contains("H3_REQUEST_REJECTED");
        if *id >= final_goaway && processed {
            violations.push(format!(
                "stream {id} processed although final GOAWAY({final_goaway}) declares it unprocessed"
            ));
        }
        if *id >= final_goaway && !rejected && !processed {
            violations.push(format!(
                "stream {id} not explicitly rejected ({outcome}); client must infer from GOAWAY id it cannot read via API"
            ));
        }
    }
    if goaways.len() > 1 {
        violations.push(format!("GOAWAY lowered after the fact: {goaways:?}"));
    }
    for violation in &violations {
        partial("2 GOAWAY", format!("[{}] {violation}", case.label));
    }
    endpoint.close(0_u8.into(), b"");
    Ok(())
}

async fn exp2(material: &Material) -> Res<()> {
    println!("\n== 2: GOAWAY via stock server::Connection::shutdown(n)");
    goaway_case(
        material,
        GoawayCase {
            label: "A stock shutdown(1), stop on None",
            requests: 5,
            max_requests: 1,
            app_guard: false,
            accept_after_none: false,
        },
    )
    .await?;
    goaway_case(
        material,
        GoawayCase {
            label: "B stock shutdown(1) + app guard + accept after None",
            requests: 5,
            max_requests: 1,
            app_guard: true,
            accept_after_none: true,
        },
    )
    .await?;
    goaway_case(
        material,
        GoawayCase {
            label: "C stock shutdown(0)",
            requests: 2,
            max_requests: 0,
            app_guard: false,
            accept_after_none: false,
        },
    )
    .await
}

async fn exp3(material: &Material) -> Res<()> {
    println!("\n== 3: GET {EVENTS_PATH} text/event-stream");
    let server = Instance::start(material, "exp3")?;
    let client = TunnelClient::connect(material, server.addr).await?;
    let conn = server.next_conn().await?;
    let started = Instant::now();
    let mut events = client.subscribe().await?;
    let (initial, _) = events.next_state().await?;
    let initial_latency = started.elapsed();
    println!("  initial state after {}: {initial:?}", ms(initial_latency));
    require(
        initial.is_valid() && !initial.replacing && initial.generation == server.generation,
        "initial state",
    )?;
    events.next_keepalive().await?;
    events.next_keepalive().await?;
    println!("  received comment keepalives");
    let pushed_at = Instant::now();
    server.set_replacing(true);
    let (pushed, keepalives) = events.next_state().await?;
    println!(
        "  pushed state after {} ({keepalives} keepalive(s) between): {pushed:?}",
        ms(pushed_at.elapsed())
    );
    require(
        pushed.replacing && pushed.generation == initial.generation,
        "pushed replacing:true",
    )?;
    events.reset(false);
    println!("  client: {}", events.ended().await?);
    let server_saw = conn.wait_note("event stream 0 ended").await?;
    println!("  server (detects only on its next keepalive write): {server_saw}");
    if !server_saw.contains("H3_REQUEST_CANCELLED") {
        partial(
            "3 event stream",
            format!(
                "client stop_sending(H3_REQUEST_CANCELLED) deferred behind h3-quinn's in-flight read; peer saw {server_saw:?} (Quinn drop default, hyperium/h3#361)"
            ),
        );
    }
    require(client.quinn.close_reason().is_none(), "connection survives")?;
    let mut again = client.subscribe().await?;
    let (current, _) = again.next_state().await?;
    println!("  resubscribed on same connection: {current:?}");
    require(current == pushed, "resubscribe gets current state")?;
    again.next_keepalive().await?;
    // Workaround probe: keep polling after stop_sending so the deferred code is applied.
    again.reset(true);
    println!("  client: {}", again.ended().await?);
    let flushed = conn.wait_note("event stream 4 ended").await?;
    println!("  server: {flushed}");
    require(
        flushed.contains("H3_REQUEST_CANCELLED"),
        "flush workaround delivers H3_REQUEST_CANCELLED",
    )?;
    let driver = client.close(b"done").await?;
    println!("  client close -> driver {driver:?}");
    let reason = conn
        .closed
        .subscribe()
        .wait_for(Option::is_some)
        .await?
        .clone();
    println!("  server: {reason:?}");
    server.endpoint.close(0_u8.into(), b"");
    Ok(())
}

async fn exp4(material: &Material, kind: SlotKind) -> Res<()> {
    println!("\n== 4: receive slots via {kind:?}");
    const SLOTS: usize = 4;
    let server = Instance::start(material, "exp4")?;
    let client = TunnelClient::connect(material, server.addr).await?;
    let conn = server.next_conn().await?;

    // Gate: no availability before the first valid event-stream state.
    let mut events = client.subscribe().await?;
    let (state, _) = events.next_state().await?;
    require(state.is_valid(), "gate on valid initial state")?;
    require(conn.idle_slots() == 0, "no slots before gate")?;
    let (assigned_tx, mut assigned) = mpsc::unbounded_channel();
    let pool = Arc::new(SlotPool {
        sender: client.sender.clone(),
        kind,
        replenish: AtomicBool::new(true),
        opened: AtomicUsize::new(0),
        assigned: assigned_tx,
    });
    let preopen = Instant::now();
    let mut ids = Vec::new();
    for _ in 0..SLOTS {
        ids.push(open_slot(pool.clone()).await?);
    }
    conn.wait_idle_slots(SLOTS).await?;
    println!(
        "  gated on generation {}..; pre-opened slots {ids:?} parked at server in {}",
        &state.generation[..8],
        ms(preopen.elapsed())
    );

    let mut visitors = Vec::new();
    for index in 0..4 {
        let hello = format!("CLIENTHELLO-{index}").into_bytes();
        let server_side = conn.assign(&hello).await?;
        let client_side = timeout(IO_TIMEOUT, assigned.recv())
            .await?
            .ok_or("assignment channel closed")?;
        let latency = client_side.received.duration_since(server_side.started);
        println!(
            "  visitor {index}: server {} slot {} -> client stream {} got {}B proxy + {:?} after {} (no client round trip)",
            server_side.kind,
            server_side.stream_id,
            client_side.stream_id,
            client_side.proxy_len,
            String::from_utf8_lossy(&client_side.client_hello),
            ms(latency)
        );
        require(client_side.client_hello == hello, "buffered ClientHello")?;
        require(
            client_side.stream_id == server_side.stream_id,
            "same stream",
        )?;
        visitors.push((server_side, client_side));
    }
    conn.wait_idle_slots(SLOTS).await?;
    println!(
        "  replenished: {} idle slots at server, {} opened in total",
        conn.idle_slots(),
        pool.opened.load(Ordering::SeqCst)
    );

    let mut v3 = visitors.pop().ok_or("v3")?;
    let mut v2 = visitors.pop().ok_or("v2")?;
    let mut v1 = visitors.pop().ok_or("v1")?;
    let mut v0 = visitors.pop().ok_or("v0")?;

    let label = match kind {
        SlotKind::Connect => "4 slots CONNECT",
        SlotKind::Post => "4 slots POST",
    };

    // Visitor 2: Client (backend side) cancels in both directions after receiving bytes.
    v2.1.recv.stop_sending(Code::H3_REQUEST_CANCELLED);
    v2.1.send.stop_stream(Code::H3_REQUEST_CANCELLED);
    let server_recv = server_read_to_end(&mut v2.0.recv).await;
    let server_send = server_write_until_error(&mut v2.0.send).await;
    println!(
        "  client-cancel: server recv {:?}, server send within 250ms {:?}",
        server_recv.as_ref().err().map(stream_code),
        server_send.as_ref().err().map(stream_code)
    );
    require(
        server_recv
            .as_ref()
            .is_err_and(|e| is_remote_code(e, Code::H3_REQUEST_CANCELLED)),
        "server saw RESET_STREAM(H3_REQUEST_CANCELLED)",
    )?;
    if !server_send
        .as_ref()
        .is_err_and(|e| is_remote_code(e, Code::H3_REQUEST_CANCELLED))
    {
        drop(v2.1);
        let after_drop = server_write_until_error(&mut v2.0.send).await;
        let code = after_drop.as_ref().err().map(stream_code);
        println!("  client-cancel: after client drops its stream, server send {code:?}");
        partial(
            label,
            format!(
                "client stop_sending(H3_REQUEST_CANCELLED) after reading never reached the wire; dropping the stream sent {code:?} (hyperium/h3#361)"
            ),
        );
    }
    drop(v2.0);

    // Visitor 3: Server (Visitor side) cancels in both directions after reading Client bytes.
    v3.1.send
        .send_data(Bytes::from_static(b"pre-cancel"))
        .await?;
    let _ = timeout(IO_TIMEOUT, v3.0.recv.recv_data()).await??;
    v3.0.recv.stop_sending(Code::H3_REQUEST_CANCELLED);
    v3.0.send.stop_stream(Code::H3_REQUEST_CANCELLED);
    let client_recv = client_read_to_end(&mut v3.1.recv).await;
    let client_send = client_write_until_error(&mut v3.1.send).await;
    println!(
        "  server-cancel: client recv {:?}, client send within 250ms {:?}",
        client_recv.as_ref().err().map(stream_code),
        client_send.as_ref().err().map(stream_code)
    );
    require(
        client_recv
            .as_ref()
            .is_err_and(|e| is_remote_code(e, Code::H3_REQUEST_CANCELLED)),
        "client saw RESET_STREAM(H3_REQUEST_CANCELLED)",
    )?;
    if !client_send
        .as_ref()
        .is_err_and(|e| is_remote_code(e, Code::H3_REQUEST_CANCELLED))
    {
        // Workaround probe: poll the stopped receive half once more; the Client's writes complete
        // h3-quinn's in-flight read, which then applies the deferred STOP_SENDING code.
        let _ = timeout(Duration::from_millis(50), v3.0.recv.recv_data()).await;
        let flushed = client_write_until_error(&mut v3.1.send).await;
        let flushed = flushed.as_ref().err().map(stream_code);
        println!(
            "  server-cancel: after server polls its stopped recv half once, client send {flushed:?}"
        );
        partial(
            label,
            format!(
                "server stop_sending(H3_REQUEST_CANCELLED) after reading is deferred until the app polls recv again (then {flushed:?}) (hyperium/h3#361)"
            ),
        );
    }
    drop(v3);

    // Visitor 0: Client half-closes first, Server keeps sending afterwards.
    v0.1.send
        .send_data(Bytes::from_static(b"backend-0"))
        .await?;
    v0.1.send.finish().await?;
    let got = server_read_to_end(&mut v0.0.recv).await?;
    v0.0.send
        .send_data(Bytes::from_static(b"after-client-fin"))
        .await?;
    v0.0.send.finish().await?;
    let back = client_read_to_end(&mut v0.1.recv).await?;
    println!(
        "  client-FIN-first: server got {:?} then FIN; client got {:?} then FIN",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&back)
    );
    require(
        got == b"backend-0" && back == b"after-client-fin",
        "client FIN first",
    )?;
    drop(v0);

    // Visitor 1: Server half-closes first, Client keeps sending afterwards.
    v1.0.send
        .send_data(Bytes::from_static(b"visitor-bye"))
        .await?;
    v1.0.send.finish().await?;
    let got = client_read_to_end(&mut v1.1.recv).await?;
    v1.1.send
        .send_data(Bytes::from_static(b"late-backend"))
        .await?;
    v1.1.send.finish().await?;
    let back = server_read_to_end(&mut v1.0.recv).await?;
    println!(
        "  server-FIN-first: client got {:?} then FIN; server got {:?} then FIN",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&back)
    );
    require(
        got == b"visitor-bye" && back == b"late-backend",
        "server FIN first",
    )?;
    drop(v1);

    events.next_keepalive().await?;
    require(client.quinn.close_reason().is_none(), "connection alive")?;
    require(*conn.active.borrow() == 0, "no active visitors")?;
    println!(
        "  after cancellations: connection alive, event stream alive, {} idle slots",
        conn.idle_slots()
    );

    // Bulk transfer through one slot to touch flow control (default Quinn windows).
    let ActiveVisitor {
        send: mut bulk_send,
        recv: mut bulk_recv,
        _guard: bulk_guard,
        ..
    } = conn.assign(b"bulk").await?;
    let mut bulk_client = timeout(IO_TIMEOUT, assigned.recv()).await?.ok_or("bulk")?;
    let payload = Bytes::from(vec![0x5a; 4 * 1024 * 1024]);
    let started = Instant::now();
    let writer = tokio::spawn(async move {
        bulk_send.send_data(payload).await?;
        bulk_send.finish().await
    });
    let received = client_read_to_end(&mut bulk_client.recv).await?;
    writer.await??;
    println!(
        "  4 MiB server->client through one slot (single send_data, default windows): {} B in {}",
        received.len(),
        ms(started.elapsed())
    );
    require(received.len() == 4 * 1024 * 1024, "bulk length")?;
    bulk_client.send.finish().await?;
    server_read_to_end(&mut bulk_recv).await?;
    drop((bulk_client, bulk_guard));

    if matches!(kind, SlotKind::Connect) {
        exp5(&client, &conn, &pool, &mut assigned).await?;
    }
    let driver = client.close(b"done").await?;
    let reason = conn
        .closed
        .subscribe()
        .wait_for(Option::is_some)
        .await?
        .clone();
    println!("  client closed with H3_NO_ERROR -> driver {driver:?}; server {reason:?}");
    require(
        reason
            .as_deref()
            .is_some_and(|r| r.contains("h3_no_error=true")),
        "server saw H3_NO_ERROR close",
    )?;
    server.endpoint.close(0_u8.into(), b"");
    Ok(())
}

async fn exp5(
    client: &TunnelClient,
    conn: &Arc<ServerConn>,
    pool: &Arc<SlotPool>,
    assigned: &mut mpsc::UnboundedReceiver<ClientVisitor>,
) -> Res<()> {
    println!("\n== 5: PUT {WITHDRAWAL_PATH} on the CONNECT-slot connection");
    let mut active = (
        conn.assign(b"long-visitor").await?,
        timeout(IO_TIMEOUT, assigned.recv()).await?.ok_or("long")?,
    );
    pool.replenish.store(false, Ordering::SeqCst);
    let mut sender = client.sender.clone();
    let sent = Instant::now();
    let mut withdrawal = sender
        .send_request(Request::put(format!("https://{SERVER_NAME}{WITHDRAWAL_PATH}")).body(())?)
        .await?;
    withdrawal.finish().await?;
    println!("  {}", conn.wait_note("withdrawal committed").await?);
    let refused = conn.assign(b"late").await.err().map(|e| e.to_string());
    println!("  placement after commit: {refused:?}");
    require(refused.is_some(), "no placement after withdrawal")?;
    let early = timeout(Duration::from_millis(100), withdrawal.recv_response()).await;
    require(early.is_err(), "204 withheld while a visitor is active")?;
    println!("  204 withheld while visitor active (waited 100ms)");
    active.1.send.finish().await?;
    server_read_to_end(&mut active.0.recv).await?;
    active.0.send.finish().await?;
    client_read_to_end(&mut active.1.recv).await?;
    drop(active);
    let response = timeout(IO_TIMEOUT, withdrawal.recv_response()).await??;
    let body = withdrawal.recv_data().await?;
    println!(
        "  client got {} bodyless={} after {}; {}",
        response.status().as_u16(),
        body.is_none(),
        ms(sent.elapsed()),
        conn.wait_note("withdrawal 204 sent").await?
    );
    require(
        response.status() == StatusCode::NO_CONTENT && body.is_none(),
        "bodyless 204 + FIN",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Experiment 6: tuple-pinned UDP forwarder and replacement
// ---------------------------------------------------------------------------------------------

struct Forwarder {
    addr: SocketAddr,
    target: Arc<AtomicUsize>,
    sessions: Arc<Mutex<Vec<(SocketAddr, SocketAddr)>>>,
}

impl Forwarder {
    async fn start(upstreams: [SocketAddr; 2]) -> Res<Self> {
        let socket = Arc::new(UdpSocket::bind(localhost(0)).await?);
        let addr = socket.local_addr()?;
        let target = Arc::new(AtomicUsize::new(0));
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let (loop_target, loop_sessions) = (target.clone(), sessions.clone());
        tokio::spawn(async move {
            let mut pinned: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buffer = vec![0; 65_535];
            while let Ok((length, source)) = socket.recv_from(&mut buffer).await {
                let upstream = match pinned.get(&source) {
                    Some(upstream) => upstream.clone(),
                    None => {
                        // Session keyed on Client source address; upstream chosen once, here.
                        let chosen = upstreams[loop_target.load(Ordering::SeqCst)];
                        let Ok(upstream) = UdpSocket::bind(localhost(0)).await else {
                            continue;
                        };
                        if upstream.connect(chosen).await.is_err() {
                            continue;
                        }
                        let upstream = Arc::new(upstream);
                        if let Ok(mut sessions) = loop_sessions.lock() {
                            sessions.push((source, chosen));
                        }
                        let (reply, back) = (socket.clone(), upstream.clone());
                        tokio::spawn(async move {
                            let mut buffer = vec![0; 65_535];
                            while let Ok(length) = back.recv(&mut buffer).await {
                                let _ = reply.send_to(&buffer[..length], source).await;
                            }
                        });
                        pinned.insert(source, upstream.clone());
                        upstream
                    }
                };
                let _ = upstream.send(&buffer[..length]).await;
            }
        });
        Ok(Self {
            addr,
            target,
            sessions,
        })
    }
}

async fn exp6(material: &Material) -> Res<()> {
    println!("\n== 6: replacement through a tuple-pinned UDP forwarder");
    let a = Instance::start(material, "A")?;
    let b = Instance::start(material, "B")?;
    let forwarder = Forwarder::start([a.addr, b.addr]).await?;
    println!(
        "  A gen {}.. at {}, B gen {}.. at {}, forwarder {} -> A",
        &a.generation[..8],
        a.addr,
        &b.generation[..8],
        b.addr,
        forwarder.addr
    );

    let primary = TunnelClient::connect(material, forwarder.addr).await?;
    let a_primary = a.next_conn().await?;
    let mut primary_events = primary.subscribe().await?;
    let (primary_state, _) = primary_events.next_state().await?;
    let (assigned_tx, mut primary_assigned) = mpsc::unbounded_channel();
    let primary_pool = Arc::new(SlotPool {
        sender: primary.sender.clone(),
        kind: SlotKind::Connect,
        replenish: AtomicBool::new(true),
        opened: AtomicUsize::new(0),
        assigned: assigned_tx,
    });
    for _ in 0..2 {
        open_slot(primary_pool.clone()).await?;
    }
    a_primary.wait_idle_slots(2).await?;

    a.set_replacing(true);
    let (replacing, _) = primary_events.next_state().await?;
    require(replacing.replacing, "primary sees replacing:true")?;
    println!("  primary on A got replacing:true; opening candidates");

    let mut attempt = 0;
    let (candidate, mut candidate_events, candidate_state) = loop {
        attempt += 1;
        if attempt == 3 {
            forwarder.target.store(1, Ordering::SeqCst);
            println!("  forwarder toggled: new sessions -> B");
        }
        let candidate = TunnelClient::connect(material, forwarder.addr).await?;
        let mut events = candidate.subscribe().await?;
        let (state, _) = events.next_state().await?;
        let local = candidate.endpoint.local_addr()?;
        if state.generation == primary_state.generation {
            println!(
                "  candidate {attempt} from {local}: generation {}.. == primary; rejected before offering slots",
                &state.generation[..8]
            );
            drop(events);
            candidate.close(b"same generation").await?;
            // Primary unaffected between attempts: a Visitor still flows on A.
            let mut visitor = (
                a_primary.assign(b"during-replacement").await?,
                timeout(IO_TIMEOUT, primary_assigned.recv())
                    .await?
                    .ok_or("primary visitor")?,
            );
            visitor.1.send.finish().await?;
            visitor.0.send.finish().await?;
            client_read_to_end(&mut visitor.1.recv).await?;
            server_read_to_end(&mut visitor.0.recv).await?;
            require(primary.quinn.close_reason().is_none(), "primary alive")?;
            sleep(Duration::from_millis(20)).await;
            continue;
        }
        println!(
            "  candidate {attempt} from {local}: generation {}.. != primary; accepted",
            &state.generation[..8]
        );
        break (candidate, events, state);
    };
    require(candidate_state.generation == b.generation, "candidate on B")?;
    let b_conn = b.next_conn().await?;
    let (candidate_tx, mut candidate_assigned) = mpsc::unbounded_channel();
    let candidate_pool = Arc::new(SlotPool {
        sender: candidate.sender.clone(),
        kind: SlotKind::Connect,
        replenish: AtomicBool::new(true),
        opened: AtomicUsize::new(0),
        assigned: candidate_tx,
    });
    for _ in 0..2 {
        open_slot(candidate_pool.clone()).await?;
    }
    b_conn.wait_idle_slots(2).await?;
    require(primary.quinn.close_reason().is_none(), "primary alive")?;
    println!(
        "  candidate offers 2 slots on B; primary still alive with {} idle slots on A",
        a_primary.idle_slots()
    );

    // A drains the primary: GOAWAY, event stream FIN, idle slots rejected, then close.
    take_client_goaways();
    let (reply, drained) = oneshot::channel();
    a_primary
        .cmd
        .send(Cmd::Drain(reply))
        .map_err(|_| "drain cmd")?;
    let boundary = drained.await??;
    let ended = primary_events.ended().await?;
    sleep(Duration::from_millis(50)).await;
    println!(
        "  A drain: GOAWAY {boundary}, client decoded {:?}; primary event stream: {ended}",
        take_client_goaways()
    );
    // Stock server accept() does not complete after its own GOAWAY; the application closes once
    // its own request tracking shows nothing outstanding.
    require(*a_primary.active.borrow() == 0, "A quiescent")?;
    a_primary
        .quinn
        .close(h3_varint(Code::H3_NO_ERROR)?, b"drained");
    let primary_driver = timeout(IO_TIMEOUT, primary.driver).await??;
    println!(
        "  primary closed: {primary_driver:?} (h3_no_error={}); candidate becomes primary",
        primary_driver.is_h3_no_error()
    );

    let mut visitor = (
        b_conn.assign(b"after-promotion").await?,
        timeout(IO_TIMEOUT, candidate_assigned.recv())
            .await?
            .ok_or("promoted visitor")?,
    );
    require(
        visitor.1.client_hello == b"after-promotion",
        "promoted carries visitors",
    )?;
    visitor.1.send.finish().await?;
    visitor.0.send.finish().await?;
    client_read_to_end(&mut visitor.1.recv).await?;
    server_read_to_end(&mut visitor.0.recv).await?;
    drop(visitor);
    candidate_events.next_keepalive().await?;
    let sessions = forwarder.sessions.lock().map_err(|_| "poisoned")?.clone();
    println!("  forwarder sessions (client src -> pinned upstream): {sessions:?}");
    println!("  visitor placed on B through promoted connection");
    candidate.close(b"done").await?;
    a.endpoint.close(0_u8.into(), b"");
    b.endpoint.close(0_u8.into(), b"");
    Ok(())
}
