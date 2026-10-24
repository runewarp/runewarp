//! Server side of an HTTP/3 Tunnel connection.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use h3::server::{RequestResolver, RequestStream};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use tokio::sync::{Notify, oneshot, watch};
use tokio::time::{Instant, interval_at, timeout, timeout_at};

use crate::quic::{HANDSHAKE_TIMEOUT, peer_client_identity, with_handshake_timeout};
use crate::{ClientIdentity, ServerHostname};

use super::events::{KEEPALIVE_COMMENT, ServerRuntimeGeneration, TunnelEventState};
use super::stream::{ServerTunnelStream, TunnelStream};
use super::{
    MAX_IDLE_RECEIVE_SLOTS, OwnedTask, TUNNEL_EVENTS_PATH, TunnelH3Error, TunnelH3Timing,
    close_connection,
};

type ServerH3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type ServerRequestStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerRequestResolver = RequestResolver<h3_quinn::Connection, Bytes>;

/// Distance between consecutive Client-initiated bidirectional QUIC stream IDs.
const CLIENT_BIDI_STREAM_ID_STEP: u64 = 4;

/// Server-owned HTTP/3 Tunnel connection.
///
/// Serves the Tunnel event stream, queues Client receive slots, and opens one Tunnel stream per
/// placed Visitor on a queued slot. Other signaling requests get bodyless statuses. Dropping the
/// handle closes the connection immediately with `H3_NO_ERROR`.
pub struct ServerTunnelH3 {
    connection: quinn::Connection,
    client_identity: ClientIdentity,
    shared: Arc<Shared>,
    begin_shutdown: Option<oneshot::Sender<()>>,
    task: OwnedTask,
}

/// Why no Tunnel stream could be opened on a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenTunnelStreamError {
    /// No usable receive slot arrived before the deadline.
    TimedOut,
    /// GOAWAY was sent or the connection ended; it accepts no new Visitors.
    Closed,
}

impl fmt::Display for OpenTunnelStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TimedOut => "no receive slot became available before the deadline",
            Self::Closed => "tunnel connection accepts no new visitors",
        })
    }
}

impl std::error::Error for OpenTunnelStreamError {}

/// One idle receive slot: a Client-opened CONNECT whose response has not started.
struct IdleSlot {
    stream: ServerRequestStream,
    request: InFlightRequest,
}

#[derive(Default)]
struct SlotQueue {
    idle: VecDeque<IdleSlot>,
    /// Set once GOAWAY is sent; later slots are rejected.
    closed: bool,
}

/// State shared by the connection's accept loop and its request handlers.
struct Shared {
    server_hostname: ServerHostname,
    state: TunnelEventState,
    timing: TunnelH3Timing,
    /// First unprocessed request-stream ID once GOAWAY has been sent.
    goaway_boundary: watch::Sender<Option<u64>>,
    /// Incremented by each event-stream subscription; an older subscription ends when it changes.
    subscriptions: watch::Sender<u64>,
    /// Request handlers, idle slots, and Tunnel streams that have not yet finished.
    requests_in_flight: watch::Sender<usize>,
    slots: Mutex<SlotQueue>,
    /// Signalled when a receive slot is queued or the queue closes.
    slot_offered: Notify,
}

impl Shared {
    fn slots(&self) -> MutexGuard<'_, SlotQueue> {
        self.slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue a receive slot, or reject it once closed or over the idle cap.
    fn offer_slot(&self, mut slot: IdleSlot) {
        let mut slots = self.slots();
        if slots.closed || slots.idle.len() >= MAX_IDLE_RECEIVE_SLOTS {
            drop(slots);
            reject_unprocessed(&mut slot.stream);
            return;
        }
        slots.idle.push_back(slot);
        drop(slots);
        self.slot_offered.notify_one();
    }

    /// Stop accepting slots and reject every idle one.
    fn close_slots(&self) {
        let idle = {
            let mut slots = self.slots();
            slots.closed = true;
            std::mem::take(&mut slots.idle)
        };
        for mut slot in idle {
            reject_unprocessed(&mut slot.stream);
        }
        self.slot_offered.notify_waiters();
    }
}

fn reject_unprocessed(stream: &mut ServerRequestStream) {
    stream.stop_sending(Code::H3_REQUEST_REJECTED);
    stream.stop_stream(Code::H3_REQUEST_REJECTED);
}

impl ServerTunnelH3 {
    /// Start HTTP/3 on an authenticated Tunnel connection for the Server running
    /// `server_generation`. Requests must target `server_hostname`.
    pub async fn establish(
        connection: quinn::Connection,
        server_hostname: ServerHostname,
        server_generation: ServerRuntimeGeneration,
    ) -> Result<Self, TunnelH3Error> {
        Self::establish_with_timing(
            connection,
            server_hostname,
            server_generation,
            TunnelH3Timing::default(),
        )
        .await
    }

    pub(crate) async fn establish_with_timing(
        connection: quinn::Connection,
        server_hostname: ServerHostname,
        server_generation: ServerRuntimeGeneration,
        timing: TunnelH3Timing,
    ) -> Result<Self, TunnelH3Error> {
        let client_identity =
            peer_client_identity(&connection).ok_or(TunnelH3Error::MissingClientIdentity)?;
        let h3_connection = with_handshake_timeout(
            async {
                h3::server::builder()
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .map_err(TunnelH3Error::Setup)
            },
            HANDSHAKE_TIMEOUT,
            || TunnelH3Error::SetupTimeout,
        )
        .await?;

        let shared = Arc::new(Shared {
            server_hostname,
            state: TunnelEventState::current(server_generation),
            timing,
            goaway_boundary: watch::Sender::new(None),
            subscriptions: watch::Sender::new(0),
            requests_in_flight: watch::Sender::new(0),
            slots: Mutex::new(SlotQueue::default()),
            slot_offered: Notify::new(),
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
            begin_shutdown: Some(begin_shutdown),
            task,
        })
    }

    /// Pinned Client identity authenticated by this connection.
    pub fn client_identity(&self) -> &ClientIdentity {
        &self.client_identity
    }

    /// Open a Tunnel stream for one placed Visitor on the oldest queued receive slot.
    ///
    /// Completes the slot's response immediately; the caller then writes the Tunnel framing and
    /// buffered ClientHello as the first DATA, so assignment needs no Client round trip. Waits up
    /// to `deadline` for a slot. A slot the Client already abandoned fails its response and the
    /// next one is tried, because a peer STOP_SENDING is only observed on write.
    pub async fn open_tunnel_stream(
        &self,
        deadline: Duration,
    ) -> Result<ServerTunnelStream, OpenTunnelStreamError> {
        let deadline = Instant::now() + deadline;
        loop {
            let offered = self.shared.slot_offered.notified();
            tokio::pin!(offered);
            offered.as_mut().enable();

            let slot = {
                let mut slots = self.shared.slots();
                if slots.closed || self.connection.close_reason().is_some() {
                    return Err(OpenTunnelStreamError::Closed);
                }
                slots.idle.pop_front()
            };
            let Some(mut slot) = slot else {
                timeout_at(deadline, offered)
                    .await
                    .map_err(|_| OpenTunnelStreamError::TimedOut)?;
                continue;
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("a bare 200 response is valid");
            match timeout_at(deadline, slot.stream.send_response(response)).await {
                Ok(Ok(())) => {
                    let (send, recv) = slot.stream.split();
                    return Ok(TunnelStream::new(recv, send, Arc::new(slot.request)));
                }
                Ok(Err(_)) => {}
                Err(_) => return Err(OpenTunnelStreamError::TimedOut),
            }
        }
    }

    /// Receive slots queued and not yet assigned.
    #[cfg(test)]
    pub(crate) fn idle_receive_slots(&self) -> usize {
        self.shared.slots().idle.len()
    }

    /// Orderly shutdown: send GOAWAY carrying the first unprocessed request-stream ID, reject
    /// requests at or above it and every idle receive slot with `H3_REQUEST_REJECTED`, end the
    /// event stream, and close with `H3_NO_ERROR` once open Tunnel streams and earlier requests
    /// finish. Closes immediately when `deadline` expires.
    pub async fn shutdown(mut self, deadline: Duration) {
        if let Some(begin_shutdown) = self.begin_shutdown.take() {
            let _ = begin_shutdown.send(());
        }
        let _ = timeout(deadline, &mut self.task.0).await;
    }
}

impl Drop for ServerTunnelH3 {
    fn drop(&mut self) {
        close_connection(&self.connection, Code::H3_NO_ERROR);
    }
}

async fn serve_connection(
    connection: quinn::Connection,
    mut h3_connection: ServerH3Connection,
    shared: Arc<Shared>,
    mut shutdown_requested: oneshot::Receiver<()>,
) {
    let mut requests_in_flight = shared.requests_in_flight.subscribe();
    let mut accepted_requests: u64 = 0;
    let mut shutting_down = false;

    loop {
        tokio::select! {
            _ = &mut shutdown_requested, if !shutting_down => {
                shutting_down = true;
                send_goaway(&mut h3_connection, &shared, accepted_requests).await;
            }
            _ = async { requests_in_flight.wait_for(|count| *count == 0).await.map(|_| ()) },
                if shutting_down => break,
            accepted = h3_connection.accept() => match accepted {
                Ok(Some(resolver)) => {
                    accepted_requests += 1;
                    let request = InFlightRequest::start(shared.clone());
                    tokio::spawn(handle_request(resolver, request));
                }
                Ok(None) | Err(_) => break,
            },
        }
    }

    close_connection(&connection, Code::H3_NO_ERROR);
}

/// Send the final GOAWAY and publish its boundary to request handlers.
///
/// Client-initiated bidirectional stream IDs are 0, 4, 8, … and Quinn accepts them in ID order,
/// so after `accepted_requests` accepts the first unprocessed ID is `4 * accepted_requests`. That
/// is the value stock `shutdown(1)` derives from the last accepted stream. Stock h3 rejects only
/// IDs above it, so the boundary ID itself is rejected by [`handle_request`].
async fn send_goaway(
    h3_connection: &mut ServerH3Connection,
    shared: &Shared,
    accepted_requests: u64,
) {
    shared
        .goaway_boundary
        .send_replace(Some(goaway_boundary(accepted_requests)));
    shared.close_slots();
    let _ = h3_connection.shutdown(1).await;
}

fn goaway_boundary(accepted_requests: u64) -> u64 {
    accepted_requests.saturating_mul(CLIENT_BIDI_STREAM_ID_STEP)
}

/// Accounting for one accepted request, released when its handler ends.
struct InFlightRequest {
    shared: Arc<Shared>,
}

impl InFlightRequest {
    fn start(shared: Arc<Shared>) -> Self {
        shared.requests_in_flight.send_modify(|count| *count += 1);
        Self { shared }
    }
}

impl Drop for InFlightRequest {
    fn drop(&mut self) {
        self.shared
            .requests_in_flight
            .send_modify(|count| *count -= 1);
    }
}

async fn handle_request(resolver: ServerRequestResolver, request: InFlightRequest) {
    let shared = request.shared.clone();
    let shared = shared.as_ref();
    let request_deadline = Instant::now() + shared.timing.request_deadline;
    let Ok(Ok((http_request, mut stream))) =
        timeout_at(request_deadline, resolver.resolve_request()).await
    else {
        return;
    };

    let stream_id = stream.id().into_inner();
    if shared
        .goaway_boundary
        .borrow()
        .is_some_and(|boundary| stream_id >= boundary)
    {
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
                    send_bodyless_status(stream, StatusCode::BAD_REQUEST, shared.timing).await;
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    send_bodyless_status(stream, StatusCode::REQUEST_TIMEOUT, shared.timing).await;
                }
            }
        }
        Route::ReceiveSlot => shared.offer_slot(IdleSlot { stream, request }),
        Route::Status(status) => send_bodyless_status(stream, status, shared.timing).await,
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
    /// Plain CONNECT to the Server hostname: one unit of Visitor-assignment availability.
    ReceiveSlot,
    Status(StatusCode),
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
        // Extended CONNECT is reserved for future extensions; base signaling never uses it.
        return if request.extensions().get::<h3::ext::Protocol>().is_some() {
            Route::Status(StatusCode::BAD_REQUEST)
        } else {
            Route::ReceiveSlot
        };
    }
    if uri.scheme_str() != Some("https") {
        return Route::Status(StatusCode::BAD_REQUEST);
    }
    if uri.path() != TUNNEL_EVENTS_PATH {
        return Route::Status(StatusCode::NOT_FOUND);
    }
    if request.method() != Method::GET {
        return Route::Status(StatusCode::METHOD_NOT_ALLOWED);
    }
    match declared_content_length(request.headers()) {
        Err(MalformedContentLength) => Route::Malformed,
        Ok(Some(length)) if length > 0 => Route::Status(StatusCode::BAD_REQUEST),
        Ok(_) => Route::Events,
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

async fn send_bodyless_status(
    mut stream: ServerRequestStream,
    status: StatusCode,
    timing: TunnelH3Timing,
) {
    let mut response = Response::builder().status(status);
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response = response.header(header::ALLOW, "GET");
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
    }
}

/// Serve one Tunnel event-stream subscription.
///
/// Sends full current state first, then comment keepalives. Ends with FIN when a newer
/// subscription supersedes it or GOAWAY has been sent. A write blocked past its deadline cancels
/// the stream.
async fn serve_events(mut stream: ServerRequestStream, shared: &Shared) {
    shared.subscriptions.send_modify(|count| *count += 1);
    let mut superseded = shared.subscriptions.subscribe();
    let mut goaway_boundary = shared.goaway_boundary.subscribe();
    let timing = shared.timing;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(())
        .expect("static event-stream response headers are valid");
    if !bounded_write(timing, stream.send_response(response)).await
        || !bounded_write(timing, stream.send_data(shared.state.encode_sse())).await
    {
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        return;
    }

    let interval = timing.keepalive_comment_interval;
    let mut keepalive = interval_at(Instant::now() + interval, interval);
    loop {
        let frame = tokio::select! {
            _ = keepalive.tick() => Bytes::from_static(KEEPALIVE_COMMENT),
            _ = superseded.changed() => break,
            _ = async { goaway_boundary.wait_for(Option::is_some).await.map(|_| ()) } => break,
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
    timing: TunnelH3Timing,
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

    use super::{MalformedContentLength, Route, declared_content_length, goaway_boundary, route};
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
    fn goaway_boundary_is_the_first_unaccepted_client_request_stream_id() {
        assert_eq!(goaway_boundary(0), 0);
        assert_eq!(goaway_boundary(1), 4);
        assert_eq!(goaway_boundary(2), 8);
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
                Route::Status(StatusCode::METHOD_NOT_ALLOWED),
            ),
            (with_content, Route::Status(StatusCode::BAD_REQUEST)),
            (malformed_content, Route::Malformed),
            (zero_content, Route::Events),
        ] {
            let summary = format!("{} {}", request.method(), request.uri());
            assert_eq!(route(&request, &server_hostname()), expected, "{summary}");
        }
    }
}
