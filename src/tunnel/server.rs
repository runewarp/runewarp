//! Server side of an HTTP/3 Tunnel connection.

use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use h3::error::{Code, StreamError};
use h3::server::RequestStream;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, interval_at, sleep, timeout, timeout_at};

use crate::quic::{HANDSHAKE_TIMEOUT, peer_client_identity, with_handshake_timeout};
use crate::{ClientIdentity, ServerHostname};

use super::events::{KEEPALIVE_COMMENT, ServerTunnelEvents};
use super::stream::{ServerTunnelStream, TunnelStream};
use super::{
    OwnedTask, TUNNEL_EVENTS_PATH, TUNNEL_SESSION_PATH, TUNNEL_WITHDRAWAL_PATH, TunnelError,
    TunnelTiming, close_connection,
};

type ServerConnection = h3_webtransport::server::ServerConnection<h3_quinn::Connection, Bytes>;
type SessionAcceptor = h3_webtransport::server::Acceptor<h3_quinn::Connection, Bytes>;
type ServerSession = h3_webtransport::server::Session<h3_quinn::Connection, Bytes>;
type ServerRequestStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Server-owned HTTP/3 Tunnel connection.
///
/// Serves the Tunnel event stream and opens one WebTransport stream per placed Visitor using
/// permit-backed QUIC credit. One detached WebTransport session owns connection lifetime.
/// A valid placement withdrawal permanently ends new placement and is answered with `204` once
/// no Visitor work remains; the Server closes the connection a fixed time later if the Client
/// has not. Other signaling requests get bodyless statuses. Dropping the handle closes the
/// connection immediately with `H3_NO_ERROR`.
pub struct ServerTunnel {
    connection: quinn::Connection,
    client_identity: ClientIdentity,
    shared: Arc<Shared>,
    begin_shutdown: Mutex<Option<oneshot::Sender<()>>>,
    _task: OwnedTask,
}

/// Why no Tunnel stream could be opened on a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenTunnelStreamError {
    /// No WebTransport stream credit arrived before the deadline.
    TimedOut,
    /// GOAWAY was sent, the Client withdrew placement, or the connection ended; it accepts no
    /// new Visitors.
    Closed,
}

impl fmt::Display for OpenTunnelStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TimedOut => "no Visitor stream credit became available before the deadline",
            Self::Closed => "tunnel connection accepts no new visitors",
        })
    }
}

impl std::error::Error for OpenTunnelStreamError {}

/// Only fixed classifications and numeric protocol codes cross the diagnostic boundary.
/// Peer-provided reason strings and opaque transport errors can contain private data.
struct OpenFailure {
    outcome: OpenTunnelStreamError,
    reason: &'static str,
    code: Option<u64>,
}
impl OpenFailure {
    fn closed(reason: &'static str) -> Self {
        Self {
            outcome: OpenTunnelStreamError::Closed,
            reason,
            code: None,
        }
    }
    fn session(error: h3::error::StreamError) -> Self {
        use h3::error::StreamError;
        let (reason, code) = match error {
            StreamError::StreamError { code, .. } => ("session-stream-error", Some(code.value())),
            StreamError::RemoteTerminate { code, .. } => {
                ("session-remote-terminate", Some(code.value()))
            }
            StreamError::ConnectionError(_) => ("session-connection-error", None),
            StreamError::HeaderTooBig { .. } => ("session-header-too-big", None),
            StreamError::RemoteClosing => ("session-remote-closing", None),
            StreamError::Undefined(_) => ("session-transport-error", None),
            _ => ("session-other-error", None),
        };
        Self {
            outcome: OpenTunnelStreamError::Closed,
            reason,
            code,
        }
    }
}

/// State shared by the connection's accept loop and its request handlers.
struct Shared {
    connection: quinn::Connection,
    acceptor: SessionAcceptor,
    server_hostname: ServerHostname,
    events: ServerTunnelEvents,
    timing: TunnelTiming,
    /// Published once GOAWAY seals request intake.
    goaway: watch::Sender<bool>,
    /// Incremented by each event-stream subscription; an older subscription ends when it changes.
    subscriptions: watch::Sender<u64>,
    /// Ordinary request handlers, pending Visitor opens and active Tunnel streams. The session
    /// itself does not prolong graceful drain.
    requests_in_flight: Arc<watch::Sender<usize>>,
    /// Pending Visitor opens and active Tunnel streams; quiescence waits for zero.
    visitor_work: Arc<watch::Sender<usize>>,
    /// Published once a valid withdrawal commits. Placement commitment reads it under the same
    /// lock, so a Visitor either commits before withdrawal or is never placed.
    withdrawn: watch::Sender<bool>,
    /// Valid withdrawal requests still waiting to send their `204`.
    withdrawal_waiters: Arc<watch::Sender<usize>>,
    /// Published when the first `204` completes locally, starting the post-quiescence close.
    confirmed: watch::Sender<bool>,
    #[cfg(test)]
    handlers_spawned: std::sync::atomic::AtomicUsize,
    session: watch::Sender<Option<Arc<ServerSession>>>,
}

fn reject_unprocessed(stream: &mut ServerRequestStream) {
    stream.stop_sending(Code::H3_REQUEST_REJECTED);
    stream.stop_stream(Code::H3_REQUEST_REJECTED);
}

impl ServerTunnel {
    /// Start HTTP/3 on an authenticated Tunnel connection whose event stream follows `events`.
    /// Requests must target `server_hostname`.
    pub async fn establish(
        connection: quinn::Connection,
        server_hostname: ServerHostname,
        events: impl Into<ServerTunnelEvents>,
    ) -> Result<Self, TunnelError> {
        Self::establish_with_timing(connection, server_hostname, events, TunnelTiming::default())
            .await
    }

    pub(crate) async fn establish_with_timing(
        connection: quinn::Connection,
        server_hostname: ServerHostname,
        events: impl Into<ServerTunnelEvents>,
        timing: TunnelTiming,
    ) -> Result<Self, TunnelError> {
        let client_identity =
            peer_client_identity(&connection).ok_or(TunnelError::MissingClientIdentity)?;
        let h3_connection = with_handshake_timeout(
            async {
                h3::server::builder()
                    .max_field_section_size(super::config::MAX_FIELD_SECTION_SIZE)
                    .enable_webtransport(true)
                    .enable_extended_connect(true)
                    .enable_datagram(true)
                    .max_webtransport_sessions(1)
                    .webtransport_drafts([h3::ext::WebTransportDraft::Draft07])
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .map_err(TunnelError::Setup)
            },
            HANDSHAKE_TIMEOUT,
            || TunnelError::SetupTimeout,
        )
        .await?;

        let (h3_connection, acceptor) = h3_webtransport::server::new(
            h3_connection,
            h3_webtransport::server::Limits {
                // Keep the WebTransport session limit at one regardless of fork defaults.
                sessions: std::num::NonZeroUsize::MIN,
                ..Default::default()
            },
        );
        let shared = Arc::new(Shared {
            connection: connection.clone(),
            acceptor,
            server_hostname,
            events: events.into(),
            timing,
            goaway: watch::Sender::new(false),
            subscriptions: watch::Sender::new(0),
            requests_in_flight: Arc::new(watch::Sender::new(0)),
            visitor_work: Arc::new(watch::Sender::new(0)),
            withdrawn: watch::Sender::new(false),
            withdrawal_waiters: Arc::new(watch::Sender::new(0)),
            confirmed: watch::Sender::new(false),
            #[cfg(test)]
            handlers_spawned: std::sync::atomic::AtomicUsize::new(0),
            session: watch::Sender::new(None),
        });
        let (begin_shutdown, shutdown_requested) = oneshot::channel();
        let task = OwnedTask::spawn(serve_connection(
            connection.clone(),
            h3_connection,
            shared.clone(),
            shutdown_requested,
        ));

        Ok(Self {
            connection,
            client_identity,
            shared,
            begin_shutdown: Mutex::new(Some(begin_shutdown)),
            _task: task,
        })
    }

    /// Pinned Client identity authenticated by this connection.
    pub fn client_identity(&self) -> &ClientIdentity {
        &self.client_identity
    }

    /// Whether this connection has established its WebTransport session and is still open: the
    /// point at which a Client offers Visitor credit. Managed Servers report these connections.
    pub(crate) fn has_open_session(&self) -> bool {
        self.shared.session.borrow().is_some() && self.connection.close_reason().is_none()
    }

    /// Resolve once [`Self::has_open_session`] may have changed: when the WebTransport session
    /// is established and when the connection closes. Calls `changed` after each. Holds no handle
    /// that keeps the connection open.
    pub(crate) fn watch_open_session(
        &self,
        changed: impl Fn() + Send + 'static,
    ) -> impl Future<Output = ()> + Send + 'static {
        let mut session = self.shared.session.subscribe();
        let connection = self.connection.clone();
        async move {
            tokio::select! {
                _ = session.wait_for(Option::is_some) => changed(),
                _ = connection.closed() => {}
            }
            let _ = connection.closed().await;
            changed();
        }
    }

    /// Whether new Visitors may be placed here: no withdrawal, GOAWAY or connection end.
    ///
    /// Withdrawal is permanent, so a withdrawn connection never regains eligibility, including
    /// across Authorization changes that move it to another Tunnel pool.
    pub fn accepts_visitors(&self) -> bool {
        !*self.shared.withdrawn.borrow()
            && !*self.shared.goaway.borrow()
            && self.connection.close_reason().is_none()
    }

    /// Open one Server-assigned Visitor stream, waiting for permit-backed QUIC credit until
    /// `deadline`. The session opener writes its prefix immediately. Callers then write the
    /// PROXY v2 envelope and buffered ClientHello without a per-Visitor acceptance exchange.
    pub async fn open_tunnel_stream(
        &self,
        deadline: Duration,
    ) -> Result<ServerTunnelStream, OpenTunnelStreamError> {
        let result = self.open_visitor_stream(deadline).await;
        match result {
            Ok(stream) => Ok(stream),
            Err(failure) => {
                crate::runtime_log::server_tunnel_stream_open_failed(failure.reason, failure.code);
                #[cfg(test)]
                crate::capacity_benchmark::record_open_error(format!(
                    "reason={} code={:?}",
                    failure.reason, failure.code
                ));
                Err(failure.outcome)
            }
        }
    }

    async fn open_visitor_stream(
        &self,
        deadline: Duration,
    ) -> Result<ServerTunnelStream, OpenFailure> {
        use h3::quic::{BidiStream, RecvStream, SendStream};
        let mut goaway = self.shared.goaway.subscribe();
        let mut withdrawn = self.shared.withdrawn.subscribe();
        if !self.accepts_visitors() {
            return Err(OpenFailure::closed("connection-not-accepting"));
        }
        // Pending opens count toward graceful drain, including those awaiting session readiness.
        let work = VisitorWork {
            _request: InFlightRequest::start(&self.shared.requests_in_flight),
            _visitor: InFlightRequest::start(&self.shared.visitor_work),
        };
        let opening = async {
            let mut session = self.shared.session.subscribe();
            let opener = session
                .wait_for(|opener| opener.is_some())
                .await
                .map_err(|_| OpenFailure::closed("session-unavailable"))?
                .as_ref()
                .expect("wait_for observed an established session")
                .clone();
            let mut stream = opener
                .opener()
                .open_bi()
                .await
                .map_err(OpenFailure::session)?;
            if *self.shared.goaway.borrow() {
                stream.reset(Code::H3_REQUEST_REJECTED.value());
                stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
                return Err(OpenFailure::closed("goaway-after-open"));
            }
            // Placement commitment. Holding this read lock excludes the withdrawal commit, so
            // credit the Server already held is never used after withdrawal commits.
            let withdrawn = self.shared.withdrawn.borrow();
            if *withdrawn {
                stream.reset(Code::H3_REQUEST_REJECTED.value());
                stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
                return Err(OpenFailure::closed("withdrawn-after-open"));
            }
            let (send, recv) = stream.split();
            let stream = TunnelStream::new(recv, send, Arc::new(work));
            drop(withdrawn);
            Ok(stream)
        };
        tokio::select! {
            result = timeout(deadline, opening) => result.map_err(|_| {
                #[cfg(test)]
                crate::capacity_benchmark::OPEN_TIMEOUTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                OpenFailure { outcome: OpenTunnelStreamError::TimedOut, reason: "stream-open-timeout", code: None }
            })?,
            _ = self.connection.closed() => Err(OpenFailure::closed("connection-closed")),
            _ = async { goaway.wait_for(|closed| *closed).await.ok(); } => Err(OpenFailure::closed("goaway")),
            _ = async { withdrawn.wait_for(|withdrawn| *withdrawn).await.ok(); } => Err(OpenFailure::closed("withdrawn")),
        }
    }

    /// Total request-handler tasks spawned, excluding header resolution.
    #[cfg(test)]
    pub(crate) fn handlers_spawned(&self) -> usize {
        self.shared
            .handlers_spawned
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Weak reference that upgrades only while connection state is still retained.
    #[cfg(test)]
    pub(crate) fn shared_state_for_test(&self) -> std::sync::Weak<impl Sized + use<>> {
        Arc::downgrade(&self.shared)
    }

    /// Orderly shutdown: send GOAWAY carrying the first unprocessed request-stream ID, reject
    /// requests at or above it with `H3_REQUEST_REJECTED`, seal new Visitor opens, end the
    /// event stream, then ask the Client to drain once local Visitors and earlier requests finish.
    /// The Client releases its Visitors and sends CLOSE before the whole Tunnel ends with
    /// `H3_NO_ERROR`. Closes immediately when `deadline` expires.
    pub async fn shutdown(&self, deadline: Duration) {
        let signal = self
            .begin_shutdown
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(signal) = signal {
            let _ = signal.send(());
        }
        let _ = timeout(deadline, self.connection.closed()).await;
        self.close(b"server shutdown");
    }

    /// Close immediately, including revocation and fast shutdown.
    pub fn close(&self, reason: &[u8]) {
        self.connection
            .close(quinn::VarInt::from_u32(0x100), reason);
    }

    /// Wait for the underlying connection to end.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
    }

    #[cfg(test)]
    pub(crate) fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }
}

impl Drop for ServerTunnel {
    fn drop(&mut self) {
        close_connection(&self.connection, Code::H3_NO_ERROR);
    }
}

async fn serve_connection(
    connection: quinn::Connection,
    mut h3_connection: ServerConnection,
    shared: Arc<Shared>,
    mut shutdown_requested: oneshot::Receiver<()>,
) {
    let mut requests_in_flight = shared.requests_in_flight.subscribe();
    // Resolve headers concurrently in the driver. Invalid or oversized headers never spawn a
    // request handler, and a slow header section cannot block intake on other streams. QUIC
    // request-stream credit bounds these futures; each retains the original request deadline.
    let mut resolving = FuturesUnordered::new();
    let mut shutting_down = false;
    let mut drain_sent = false;
    let mut handlers = JoinSet::new();
    let period = shared.timing.request_deadline;
    let mut prefix_deadline = interval_at(Instant::now() + period, period);
    let post_quiescence_close = close_after_quiescence(&shared);
    tokio::pin!(post_quiescence_close);

    loop {
        tokio::select! {
            _ = &mut shutdown_requested, if !shutting_down => {
                shutting_down = true;
                h3_connection.evict_pending_streams();
                send_goaway(&mut h3_connection, &shared).await;
            }
            _ = async { requests_in_flight.wait_for(|count| *count == 0).await.map(|_| ()) },
                if shutting_down && !drain_sent => {
                    drain_sent = true;
                    let session = shared.session.borrow().clone();
                    if let Some(session) = session {
                        // FIN only queues bytes. Keep the session live until the Client releases
                        // its Visitors, including any final bytes it has not consumed yet.
                        if session.drain().await.is_err() { break; }
                    } else {
                        break;
                    }
                },
            _ = connection.closed() => break,
            _ = &mut post_quiescence_close => break,
            _ = prefix_deadline.tick() => { h3_connection.evict_pending_streams(); }
            _ = handlers.join_next(), if !handlers.is_empty() => {}
            resolved = resolving.next(), if !resolving.is_empty() => {
                if let Some(Some((http_request, stream, request, deadline, admitted))) = resolved {
                    #[cfg(test)]
                    shared.handlers_spawned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    handlers.spawn(handle_request(
                        http_request, stream, shared.clone(), request, deadline, admitted,
                    ));
                }
            }
            accepted = h3_connection.accept() => match accepted {
                Ok(Some(resolver)) => {
                    let admitted = !shutting_down;
                    let request = InFlightRequest::start(&shared.requests_in_flight);
                    let deadline = Instant::now() + shared.timing.request_deadline;
                    resolving.push(async move {
                        let (http_request, stream) =
                            timeout_at(deadline, resolver.resolve_request()).await.ok()?.ok()?;
                        Some((http_request, stream, request, deadline, admitted))
                    });
                }
                Ok(None) | Err(_) => break,
            },
        }
    }

    h3_connection.evict_pending_streams();
    close_connection(&connection, Code::H3_NO_ERROR);
}

/// Seal intake and send the fork's first-unprocessed request ID with stock `shutdown(1)`.
///
/// The detached driver accepts and classifies raw streams independently, so returned resolvers
/// need not be consecutive or ordered. Evict its pending classifiers before shutdown. Resolvers
/// already returned may finish under their original deadlines; every later resolver is rejected,
/// including the boundary ID stock h3 otherwise permits. This follows the actual intake boundary
/// without reconstructing stream IDs from a count of classified requests.
async fn send_goaway(h3_connection: &mut ServerConnection, shared: &Shared) {
    shared.goaway.send_replace(true);
    let _ = h3_connection.shutdown(1).await;
}

/// Wait until a withdrawn connection is quiescent and the Client has had the fixed
/// post-quiescence time to close it.
///
/// The timer starts when the first `204` completes locally, or once every valid waiter has
/// given up before any `204` could complete. Later duplicates never restart it. Server shutdown
/// still closes at its own deadline, so this never extends shutdown.
async fn close_after_quiescence(shared: &Shared) {
    let _ = shared
        .withdrawn
        .subscribe()
        .wait_for(|withdrawn| *withdrawn)
        .await;
    let _ = shared
        .visitor_work
        .subscribe()
        .wait_for(|work| *work == 0)
        .await;
    let mut confirmed = shared.confirmed.subscribe();
    let mut waiters = shared.withdrawal_waiters.subscribe();
    while !*confirmed.borrow_and_update() && *waiters.borrow_and_update() > 0 {
        tokio::select! {
            _ = confirmed.changed() => {}
            _ = waiters.changed() => {}
        }
    }
    sleep(shared.timing.post_quiescence_close).await;
}

/// Accounting for one ordinary request or Visitor open, retained through its handler or both
/// active Tunnel stream halves.
struct InFlightRequest {
    count: Arc<watch::Sender<usize>>,
}

impl InFlightRequest {
    fn start(count: &Arc<watch::Sender<usize>>) -> Self {
        count.send_modify(|count| *count += 1);
        Self {
            count: count.clone(),
        }
    }
}

impl super::stream::StreamResource for InFlightRequest {}

/// One pending or committed Visitor: counted for both graceful drain and withdrawal quiescence.
struct VisitorWork {
    _request: InFlightRequest,
    _visitor: InFlightRequest,
}

impl super::stream::StreamResource for VisitorWork {}

impl Drop for InFlightRequest {
    fn drop(&mut self) {
        self.count.send_modify(|count| *count -= 1);
    }
}

async fn handle_request(
    http_request: Request<()>,
    mut stream: ServerRequestStream,
    shared: Arc<Shared>,
    request: InFlightRequest,
    request_deadline: Instant,
    admitted: bool,
) {
    let shared = shared.as_ref();

    if !admitted {
        reject_unprocessed(&mut stream);
        return;
    }

    match route(&http_request, &shared.server_hostname) {
        Route::Events => {
            let content_length = declared_content_length(http_request.headers())
                .ok()
                .flatten();
            match timeout_at(request_deadline, read_bodyless_request(&mut stream)).await {
                Ok(Ok(BodylessRequest::Complete)) => serve_events(stream, shared).await,
                Ok(Ok(BodylessRequest::Content)) if content_length == Some(0) => {
                    reset_malformed(&mut stream);
                }
                Ok(Ok(BodylessRequest::Content | BodylessRequest::Trailers)) => {
                    send_bodyless_status(stream, StatusCode::BAD_REQUEST, None, shared.timing)
                        .await;
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    send_bodyless_status(stream, StatusCode::REQUEST_TIMEOUT, None, shared.timing)
                        .await;
                }
            }
        }
        Route::Session => {
            // WebTransport CONNECT owns connection lifetime and does not prolong Visitor drain.
            let session = timeout_at(
                request_deadline,
                shared.acceptor.accept(http_request, stream),
            )
            .await;
            drop(request);
            if let Ok(Ok(session)) = session {
                let session = Arc::new(session);
                shared.session.send_replace(Some(session.clone()));
                loop {
                    tokio::select! {
                        _ = session.closed() => break,
                        stream = session.accept_bi() => match stream {
                            Some(mut stream) => {
                                use h3::quic::{RecvStream, SendStream};
                                stream.reset(Code::H3_REQUEST_REJECTED.value());
                                stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
                            }
                            // Unlike closed(), this also observes a close capsule without peer FIN.
                            None => break,
                        },
                        _ = shared.connection.closed() => return,
                    }
                }
                if shared.connection.close_reason().is_none() {
                    close_connection(&shared.connection, Code::H3_NO_ERROR);
                }
            }
        }
        Route::Withdrawal => {
            let content_length = declared_content_length(http_request.headers())
                .ok()
                .flatten();
            match timeout_at(request_deadline, read_bodyless_request(&mut stream)).await {
                Ok(Ok(BodylessRequest::Complete)) => serve_withdrawal(stream, shared).await,
                Ok(Ok(BodylessRequest::Content)) if content_length == Some(0) => {
                    reset_malformed(&mut stream);
                }
                Ok(Ok(BodylessRequest::Content | BodylessRequest::Trailers)) => {
                    reject_withdrawal(stream, StatusCode::BAD_REQUEST, shared.timing).await;
                }
                // Cancellation before validation never commits.
                Ok(Err(_)) => {}
                Err(_) => {
                    reject_withdrawal(stream, StatusCode::REQUEST_TIMEOUT, shared.timing).await;
                }
            }
        }
        Route::Status(status) => {
            send_bodyless_status(stream, status, None, shared.timing).await;
        }
        Route::MethodNotAllowed { allow } => {
            send_bodyless_status(
                stream,
                StatusCode::METHOD_NOT_ALLOWED,
                Some(allow),
                shared.timing,
            )
            .await;
        }
        Route::Malformed => reset_malformed(&mut stream),
    }
}

/// Malformed HTTP message: a stream error of type `H3_MESSAGE_ERROR`, not an HTTP response.
fn reset_malformed(stream: &mut ServerRequestStream) {
    stream.stop_sending(Code::H3_MESSAGE_ERROR);
    stream.stop_stream(Code::H3_MESSAGE_ERROR);
}

/// How a request that must be bodyless ended.
enum BodylessRequest {
    /// Request FIN with no content or trailers.
    Complete,
    /// At least one content byte arrived.
    Content,
    /// A trailer section arrived.
    Trailers,
}

/// Read request intake to its end; the caller bounds how long this may take.
async fn read_bodyless_request(
    stream: &mut ServerRequestStream,
) -> Result<BodylessRequest, StreamError> {
    while let Some(chunk) = stream.recv_data().await? {
        if chunk.has_remaining() {
            return Ok(BodylessRequest::Content);
        }
    }
    Ok(match stream.recv_trailers().await? {
        Some(_) => BodylessRequest::Trailers,
        None => BodylessRequest::Complete,
    })
}

#[derive(Debug, Eq, PartialEq)]
enum Route {
    Events,
    Withdrawal,
    Session,
    Status(StatusCode),
    /// Known resource with another method: `405` carrying `Allow`.
    MethodNotAllowed {
        allow: &'static str,
    },
    /// Malformed message, answered with `H3_MESSAGE_ERROR` instead of a status.
    Malformed,
}

/// Map a signaling request to its resource or a bodyless status.
///
/// Only the normalized `:authority` host binds to the Server hostname; any port is ignored so
/// NAT and port mapping cannot cause false mismatches.
fn route(request: &Request<()>, server_hostname: &ServerHostname) -> Route {
    let uri = request.uri();
    let authority_matches = uri
        .authority()
        .and_then(|authority| ServerHostname::try_from(authority.host()).ok())
        .is_some_and(|host| &host == server_hostname);
    if !authority_matches {
        return Route::Status(StatusCode::MISDIRECTED_REQUEST);
    }
    if request.method() == Method::CONNECT {
        return match request.extensions().get::<h3::ext::Protocol>() {
            None => Route::Status(StatusCode::BAD_REQUEST),
            Some(protocol) if *protocol == h3::ext::Protocol::WEB_TRANSPORT => {
                if uri.scheme_str() != Some("https") {
                    Route::Status(StatusCode::BAD_REQUEST)
                } else if uri.path() != TUNNEL_SESSION_PATH {
                    Route::Status(StatusCode::NOT_FOUND)
                } else {
                    Route::Session
                }
            }
            Some(_) => Route::Status(StatusCode::BAD_REQUEST),
        };
    }
    if uri.scheme_str() != Some("https") {
        return Route::Status(StatusCode::BAD_REQUEST);
    }
    let (method, resource, allow) = match uri.path() {
        TUNNEL_EVENTS_PATH => (Method::GET, Route::Events, "GET"),
        TUNNEL_WITHDRAWAL_PATH => (Method::PUT, Route::Withdrawal, "PUT"),
        _ => return Route::Status(StatusCode::NOT_FOUND),
    };
    if request.method() != method {
        return Route::MethodNotAllowed { allow };
    }
    match declared_content_length(request.headers()) {
        Err(MalformedContentLength) => Route::Malformed,
        Ok(Some(length)) if length > 0 => Route::Status(StatusCode::BAD_REQUEST),
        Ok(_) => resource,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct MalformedContentLength;

/// Declared `content-length`, if any.
///
/// Every field line and comma-separated element must be a decimal length, and all must agree;
/// anything else makes the message malformed.
fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, MalformedContentLength> {
    let mut declared = None;
    for value in headers.get_all(header::CONTENT_LENGTH) {
        let value = value.to_str().map_err(|_| MalformedContentLength)?;
        for element in value.split(',') {
            let element = element.trim();
            if element.is_empty() || !element.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(MalformedContentLength);
            }
            let length = element.parse::<u64>().map_err(|_| MalformedContentLength)?;
            if declared.is_some_and(|declared| declared != length) {
                return Err(MalformedContentLength);
            }
            declared = Some(length);
        }
    }
    Ok(declared)
}

/// Send a bodyless response; returns the stream when HEADERS and FIN completed locally.
async fn send_bodyless_status(
    mut stream: ServerRequestStream,
    status: StatusCode,
    allow: Option<&'static str>,
    timing: TunnelTiming,
) -> Option<ServerRequestStream> {
    let mut response = Response::builder().status(status);
    if let Some(allow) = allow {
        response = response.header(header::ALLOW, allow);
    }
    let response = response
        .body(())
        .expect("a status with static headers forms a valid response");
    let sent = bounded_write(timing, async {
        stream.send_response(response).await?;
        stream.finish().await
    })
    .await;
    if !sent {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        return None;
    }
    Some(stream)
}

/// Answer an invalid or timed-out withdrawal request, then stop any still-open request intake
/// without resetting the completed response.
async fn reject_withdrawal(stream: ServerRequestStream, status: StatusCode, timing: TunnelTiming) {
    if let Some(mut stream) = send_bodyless_status(stream, status, None, timing).await {
        stream.stop_sending(Code::H3_REQUEST_CANCELLED);
    }
}

/// Commit placement withdrawal, wait for quiescence, then confirm with bodyless `204` and FIN.
///
/// Commit is irreversible: cancelling this request afterwards does not restore placement. Every
/// valid request, including concurrent and later duplicates, joins the same quiescence point.
async fn serve_withdrawal(stream: ServerRequestStream, shared: &Shared) {
    // Register before committing so the close timer cannot start while this waiter is pending.
    let waiter = InFlightRequest::start(&shared.withdrawal_waiters);
    shared
        .withdrawn
        .send_if_modified(|withdrawn| !std::mem::replace(withdrawn, true));
    let _ = shared
        .visitor_work
        .subscribe()
        .wait_for(|work| *work == 0)
        .await;
    if send_bodyless_status(stream, StatusCode::NO_CONTENT, None, shared.timing)
        .await
        .is_some()
    {
        shared
            .confirmed
            .send_if_modified(|confirmed| !std::mem::replace(confirmed, true));
    }
    drop(waiter);
}

/// Serve one Tunnel event-stream subscription.
///
/// Sends the full current snapshot first, then a new full snapshot whenever it changes, and
/// comment keepalives while quiet. Changes published during a blocked write coalesce, so the next
/// write carries only the latest snapshot. Ends with FIN when a newer subscription supersedes it
/// or GOAWAY has been sent. A write blocked past its deadline cancels the stream. The request's
/// `Accept` header is ignored: the resource has one representation.
async fn serve_events(mut stream: ServerRequestStream, shared: &Shared) {
    shared.subscriptions.send_modify(|count| *count += 1);
    let mut superseded = shared.subscriptions.subscribe();
    let mut goaway = shared.goaway.subscribe();
    let mut snapshots = shared.events.subscribe();
    let timing = shared.timing;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(())
        .expect("static event-stream response headers are valid");
    let initial = snapshots.borrow_and_update().encode_sse();
    if !bounded_write(timing, stream.send_response(response)).await
        || !bounded_write(timing, stream.send_data(initial)).await
    {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        return;
    }

    let interval = timing.keepalive_comment_interval;
    let mut keepalive = interval_at(Instant::now() + interval, interval);
    loop {
        let frame = tokio::select! {
            _ = keepalive.tick() => Bytes::from_static(KEEPALIVE_COMMENT),
            Ok(()) = snapshots.changed() => snapshots.borrow_and_update().encode_sse(),
            _ = superseded.changed() => break,
            _ = async { goaway.wait_for(|sent| *sent).await.map(|_| ()) } => break,
        };
        if !bounded_write(timing, stream.send_data(frame)).await {
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
            return;
        }
    }
    let _ = bounded_write(timing, stream.finish()).await;
}

/// Run one stream write under the blocked-write deadline; `true` when it completed.
async fn bounded_write(
    timing: TunnelTiming,
    write: impl Future<Output = Result<(), StreamError>>,
) -> bool {
    matches!(
        timeout(timing.blocked_write_deadline, write).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use http::{Method, Request, StatusCode, header};

    use super::{MalformedContentLength, Route, declared_content_length, route};
    use crate::ServerHostname;

    fn server_hostname() -> ServerHostname {
        ServerHostname::try_from("tunnel.example.test").expect("valid hostname")
    }

    fn request(method: Method, uri: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(())
            .expect("valid request")
    }

    #[test]
    fn declared_content_length_accepts_agreeing_decimal_values_only() {
        let parse = |values: &[&str]| {
            let mut headers = http::HeaderMap::new();
            for value in values {
                headers.append(header::CONTENT_LENGTH, value.parse().expect("valid header"));
            }
            declared_content_length(&headers)
        };

        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(parse(&["0"]), Ok(Some(0)));
        assert_eq!(parse(&["00"]), Ok(Some(0)));
        assert_eq!(parse(&["7, 7", "7"]), Ok(Some(7)));
        for malformed in [
            &["abc"][..],
            &["-1"],
            &["+1"],
            &[""],
            &["1,"],
            &["1", "2"],
            &["99999999999999999999"],
        ] {
            assert_eq!(
                parse(malformed),
                Err(MalformedContentLength),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn routes_the_event_stream_on_the_server_hostname_with_any_port() {
        for uri in [
            "https://tunnel.example.test/v1/tunnel/events",
            "https://TUNNEL.example.test.:8443/v1/tunnel/events",
        ] {
            assert_eq!(
                route(&request(Method::GET, uri), &server_hostname()),
                Route::Events,
                "{uri}"
            );
        }
    }

    #[test]
    fn routes_bodyless_withdrawal_puts_and_maps_other_withdrawal_requests() {
        let uri = "https://tunnel.example.test:8443/v1/tunnel/withdrawal";
        let mut with_content = request(Method::PUT, uri);
        with_content
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "1".parse().expect("valid header"));
        let mut malformed_content = request(Method::PUT, uri);
        malformed_content
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "x".parse().expect("valid header"));
        let mut zero_content = request(Method::PUT, uri);
        zero_content
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "0".parse().expect("valid header"));

        for (request, expected) in [
            (request(Method::PUT, uri), Route::Withdrawal),
            (zero_content, Route::Withdrawal),
            (
                request(Method::POST, uri),
                Route::MethodNotAllowed { allow: "PUT" },
            ),
            (
                request(Method::GET, uri),
                Route::MethodNotAllowed { allow: "PUT" },
            ),
            (
                request(
                    Method::PUT,
                    "https://other.example.test/v1/tunnel/withdrawal",
                ),
                Route::Status(StatusCode::MISDIRECTED_REQUEST),
            ),
            (
                request(
                    Method::PUT,
                    "https://tunnel.example.test/v1/tunnel/withdraw",
                ),
                Route::Status(StatusCode::NOT_FOUND),
            ),
            (with_content, Route::Status(StatusCode::BAD_REQUEST)),
            (malformed_content, Route::Malformed),
        ] {
            let summary = format!("{} {}", request.method(), request.uri());
            assert_eq!(route(&request, &server_hostname()), expected, "{summary}");
        }
    }

    #[test]
    fn maps_other_requests_to_bodyless_statuses() {
        let mut with_content = request(Method::GET, "https://tunnel.example.test/v1/tunnel/events");
        with_content
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "3".parse().expect("valid header"));
        let mut malformed_content =
            request(Method::GET, "https://tunnel.example.test/v1/tunnel/events");
        malformed_content
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "abc".parse().expect("valid header"));
        let mut zero_content = request(Method::GET, "https://tunnel.example.test/v1/tunnel/events");
        zero_content
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "0".parse().expect("valid header"));

        for (request, expected) in [
            (
                request(Method::GET, "https://other.example.test/v1/tunnel/events"),
                Route::Status(StatusCode::MISDIRECTED_REQUEST),
            ),
            (
                request(Method::GET, "http://tunnel.example.test/v1/tunnel/events"),
                Route::Status(StatusCode::BAD_REQUEST),
            ),
            (
                request(Method::GET, "https://tunnel.example.test/v1/unknown"),
                Route::Status(StatusCode::NOT_FOUND),
            ),
            (
                request(Method::PUT, "https://tunnel.example.test/v1/tunnel/events"),
                Route::MethodNotAllowed { allow: "GET" },
            ),
            (with_content, Route::Status(StatusCode::BAD_REQUEST)),
            (malformed_content, Route::Malformed),
            (zero_content, Route::Events),
        ] {
            let summary = format!("{} {}", request.method(), request.uri());
            assert_eq!(route(&request, &server_hostname()), expected, "{summary}");
        }
    }
    #[test]
    fn opaque_open_errors_do_not_expose_their_payload() {
        let error = h3::error::StreamError::Undefined(Box::new(std::io::Error::other(
            "private peer details",
        )));
        let failure = super::OpenFailure::session(error);
        assert_eq!(failure.reason, "session-transport-error");
        assert_eq!(failure.code, None);
    }
}
