//! Client side of an HTTP/3 Tunnel connection.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use futures_util::FutureExt;
use h3::client::{RequestStream, SendRequest};
use h3::error::{Code, StreamError};
use http::{HeaderMap, Method, Request, StatusCode, header};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::{sleep, timeout};

use crate::ServerHostname;
use crate::quic::{HANDSHAKE_TIMEOUT, with_handshake_timeout};
use crate::sse::{SseParseItem, SseParser};

use super::events::{ServerRuntimeGeneration, TUNNEL_EVENT_SSE_LIMITS, TunnelEventState};
use super::stream::{ClientTunnelStream, TunnelStream};
use super::{
    MAX_IDLE_VISITOR_CREDIT, OwnedTask, TUNNEL_EVENTS_PATH, TUNNEL_SESSION_PATH,
    TUNNEL_WITHDRAWAL_PATH, TunnelH3Error, TunnelH3Timing, close_connection,
};

type ClientSendRequest = SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientRequestStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Client-owned HTTP/3 Tunnel connection whose Server passed the event-stream gate.
///
/// Establishment waits for the Server's first valid snapshot and WebTransport session CONNECT, so a
/// caller may offer availability as soon as it holds this handle. The subscription follows the
/// connection lifetime: it resubscribes after an end, failure, or silence while the connection
/// remains usable, and stops once GOAWAY forbids new requests. An incompatible event or a changed
/// generation closes the connection with `H3_GENERAL_PROTOCOL_ERROR`.
///
/// After the gate and WebTransport session establishment it keeps up to [`MAX_IDLE_VISITOR_CREDIT`]
/// idle credits reserved, each holding one permit from the Client-instance stream budget, and
/// replenishes credit as permits become available until WebTransport DRAIN releases idle capacity.
/// GOAWAY alone preserves reservations for committed Visitors. Visitor streams are delivered by
/// [`ClientTunnelH3::accept_tunnel_stream`]. [`ClientTunnelH3::withdrawal`] withdraws the
/// connection from placement during graceful Client shutdown.
///
/// Dropping the handle closes the connection immediately with `H3_NO_ERROR`.
pub struct ClientTunnelH3 {
    connection: quinn::Connection,
    state: watch::Receiver<TunnelEventState>,
    assigned: mpsc::UnboundedReceiver<ClientTunnelStream>,
    /// `h3` closes the connection when its last request sender drops, so the handle keeps one
    /// for its lifetime; background tasks that stop after GOAWAY must not end placed Visitors.
    send_request: ClientSendRequest,
    withdrawal_uri: String,
    withdrawal_confirmed: Arc<watch::Sender<bool>>,
    _driver: OwnedTask,
    _events: OwnedTask,
    credits: Arc<super::credit::VisitorCredits>,
    _session: OwnedTask,
}

impl ClientTunnelH3 {
    /// Start HTTP/3 on an authenticated Tunnel connection to `server_hostname`, wait for the
    /// Server's first valid event-stream state, establish a WebTransport session, then offer credit.
    ///
    /// `stream_budget` is the Client-instance stream-handler budget shared by every Tunnel
    /// connection; each idle credit or active stream holds one permit until its Tunnel stream drops.
    pub async fn establish(
        connection: quinn::Connection,
        server_hostname: &ServerHostname,
        stream_budget: Arc<Semaphore>,
    ) -> Result<Self, TunnelH3Error> {
        Self::establish_with_timing(
            connection,
            server_hostname,
            stream_budget,
            TunnelH3Timing::default(),
        )
        .await
    }

    pub(crate) async fn establish_with_budget_observer(
        connection: quinn::Connection,
        server_hostname: &ServerHostname,
        stream_budget: Arc<Semaphore>,
        observer: Arc<dyn Fn(bool) + Send + Sync>,
    ) -> Result<Self, TunnelH3Error> {
        Self::establish_internal(
            connection,
            server_hostname,
            stream_budget,
            TunnelH3Timing::default(),
            Some(observer),
        )
        .await
    }

    pub(crate) async fn establish_with_timing(
        connection: quinn::Connection,
        server_hostname: &ServerHostname,
        stream_budget: Arc<Semaphore>,
        timing: TunnelH3Timing,
    ) -> Result<Self, TunnelH3Error> {
        Self::establish_internal(connection, server_hostname, stream_budget, timing, None).await
    }

    async fn establish_internal(
        connection: quinn::Connection,
        server_hostname: &ServerHostname,
        stream_budget: Arc<Semaphore>,
        timing: TunnelH3Timing,
        budget_observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    ) -> Result<Self, TunnelH3Error> {
        let (driver, send_request) = with_handshake_timeout(
            async {
                h3::client::builder()
                    .max_field_section_size(super::config::MAX_FIELD_SECTION_SIZE)
                    .enable_webtransport(true)
                    .enable_extended_connect(true)
                    .enable_datagram(true)
                    .max_webtransport_sessions(1)
                    .webtransport_drafts([h3::ext::WebTransportDraft::Draft07])
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .map_err(TunnelH3Error::Setup)
            },
            HANDSHAKE_TIMEOUT,
            || TunnelH3Error::SetupTimeout,
        )
        .await?;
        let visitor_queue_limit =
            std::num::NonZeroUsize::new(MAX_IDLE_VISITOR_CREDIT).expect("nonzero idle credit");
        let (mut driver, mut client) = h3_webtransport::client::new(
            driver,
            send_request,
            h3_webtransport::client::Limits {
                // Keep the WebTransport session limit at one regardless of fork defaults.
                sessions: std::num::NonZeroUsize::MIN,
                incoming: visitor_queue_limit,
                pending_prefixes: visitor_queue_limit,
                streams_per_session: visitor_queue_limit,
            },
        );
        let mut send_request = client.send_request();
        let driver = OwnedTask::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let events_uri = format!("https://{server_hostname}{TUNNEL_EVENTS_PATH}");
        let (initial, subscription) = match timeout(
            timing.initial_state_deadline,
            subscribe(&mut send_request, &events_uri),
        )
        .await
        {
            Ok(Ok(subscribed)) => subscribed,
            Ok(Err(error)) => {
                if let Some(error) = connection.close_reason() {
                    return Err(TunnelH3Error::Transport(error));
                }
                close_after_failure(&connection, &error);
                return Err(error);
            }
            Err(_) => {
                close_connection(&connection, Code::H3_NO_ERROR);
                return Err(TunnelH3Error::InitialStateTimeout);
            }
        };

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{server_hostname}{TUNNEL_SESSION_PATH}"))
            .body(())
            .expect("a Server hostname forms a valid WebTransport session URI");
        // Apply the same duration policy separately to the event gate and WebTransport CONNECT.
        let session = match timeout(timing.initial_state_deadline, client.connect(request)).await {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                if let Some(error) = connection.close_reason() {
                    return Err(TunnelH3Error::Transport(error));
                }
                close_connection(&connection, Code::H3_NO_ERROR);
                return Err(TunnelH3Error::SessionConnect(error));
            }
            Err(_) => {
                close_connection(&connection, Code::H3_NO_ERROR);
                return Err(TunnelH3Error::SessionConnectTimeout);
            }
        };
        // Intake never waits for handlers. Every queued stream owns a budget permit, which
        // bounds this queue by the Client-instance budget despite its unbounded channel API.
        let (assigned_sender, assigned) = mpsc::unbounded_channel();
        let credits =
            super::credit::VisitorCredits::new(connection.clone(), stream_budget, budget_observer);
        let session_connection = connection.clone();
        let maintenance = super::credit::CreditMaintenance(credits.clone());
        let session = OwnedTask::spawn(async move {
            // Retain a pending semaphore acquisition across arrivals to preserve queue fairness
            // between connections. Session intake never waits for a handler or budget permit.
            let credits = &maintenance.0;
            let mut draining = false;
            let mut idle_stopped = false;
            let acquisition = Some(credits.budget().acquire_owned());
            tokio::pin!(acquisition);
            loop {
                let needs_idle = credits.needs_idle();
                if needs_idle && credits.budget().available_permits() == 0 {
                    credits.note_budget(false);
                }
                let stream = tokio::select! {
                    _ = session.closed() => break,
                    stream = session.accept_bi() => stream,
                    _ = session.draining(), if !draining => {
                        draining = true;
                        // Drop even a pending acquisition so it retains no semaphore queue
                        // position or reserved permit while this connection finishes Visitors.
                        acquisition.set(None);
                        credits.stop_idle();
                        // draining() can also mean termination. Keep polling intake/closed
                        // below so CLOSE without peer FIN still terminates immediately.
                        continue;
                    }
                    _ = credits.idle_stopped(), if !idle_stopped => {
                        // Withdrawal or DRAIN stopped idle maintenance. Drop even a pending
                        // acquisition so it retains no semaphore queue position or permit.
                        idle_stopped = true;
                        acquisition.set(None);
                        continue;
                    }
                    _ = credits.drained(), if draining => {
                        // draining() also wakes on termination. closed() can observe CLOSE but
                        // remain pending awaiting FIN. Check intake after those CONNECT polls:
                        // None means immediate termination, even if the peer withholds FIN.
                        match session.accept_bi().now_or_never() {
                            Some(stream) => stream,
                            None => {
                                let _ = session.close(0, "").await;
                                // The Server owns whole-Tunnel close after our completion ack.
                                session_connection.closed().await;
                                break;
                            }
                        }
                    },
                    permit = async {
                        acquisition.as_mut().as_pin_mut()
                            .expect("idle maintenance owns an acquisition").await
                    }, if needs_idle => {
                        match permit {
                            Ok(permit) => credits.offer(permit),
                            Err(_) => break,
                        }
                        acquisition.set(Some(credits.budget().acquire_owned()));
                        continue;
                    }
                    _ = session_connection.closed() => break,
                };
                let Some(mut stream) = stream else {
                    break;
                };
                use h3::quic::{BidiStream, RecvStream, SendStream};
                if let Some(permit) = credits.assign() {
                    let (send, recv) = stream.split();
                    if assigned_sender
                        .send(TunnelStream::new(recv, send, permit))
                        .is_err()
                    {
                        break;
                    }
                } else {
                    stream.reset(Code::H3_REQUEST_REJECTED.value());
                    stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
                }
            }
            if session_connection.close_reason().is_none() {
                close_connection(&session_connection, Code::H3_NO_ERROR);
            }
        });

        let (state_sender, state) = watch::channel(initial);
        let events = OwnedTask::spawn(follow_events(
            EventFollower {
                connection: connection.clone(),
                send_request: send_request.clone(),
                events_uri,
                state: state_sender,
                timing,
            },
            subscription,
        ));

        #[cfg(test)]
        crate::capacity_benchmark::CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Self {
            connection,
            state,
            assigned,
            send_request,
            withdrawal_uri: format!("https://{server_hostname}{TUNNEL_WITHDRAWAL_PATH}"),
            withdrawal_confirmed: Arc::new(watch::Sender::new(false)),
            _driver: driver,
            _events: events,
            credits,
            _session: session,
        })
    }

    /// Wait for a Server-opened Visitor stream on this connection's WebTransport session.
    ///
    /// Returns `None` once the connection closes or session intake ends. GOAWAY alone keeps the
    /// session alive so already-placed Visitors can finish.
    pub async fn accept_tunnel_stream(&mut self) -> Option<ClientTunnelStream> {
        tokio::select! {
            stream = self.assigned.recv() => stream,
            _ = self.connection.closed() => None,
        }
    }

    /// Withdraw this connection from placement and close it.
    ///
    /// Idle Visitor credit replenishment stops at once, but offered credit stays reserved so
    /// Visitors the Server commits before its withdrawal commit keep their permits. The returned
    /// future sends bodyless `PUT /v1/tunnel/withdrawal`, retrying once on a fresh request stream
    /// after a response-less failure or `408`. A bodyless `204` with FIN is recorded at once (see
    /// [`Self::withdrawal_confirmed`]) and releases idle permits to the Client-instance budget;
    /// the future then waits for local Visitor leases to drain, so final bytes already in flight
    /// reach their handlers. It always ends by closing the connection with `H3_NO_ERROR`; dropping
    /// it early leaves closing to the caller.
    pub fn withdrawal(&self) -> impl Future<Output = WithdrawalOutcome> + Send + 'static + use<> {
        self.credits.stop_replenishing();
        let connection = self.connection.clone();
        let credits = self.credits.clone();
        let confirmed = self.withdrawal_confirmed.clone();
        let mut send_request = self.send_request.clone();
        let uri = self.withdrawal_uri.clone();
        async move {
            let mut retry_available = true;
            let outcome = loop {
                let attempt = tokio::select! {
                    attempt = withdrawal_attempt(&mut send_request, &uri) => attempt,
                    _ = connection.closed() => WithdrawalAttempt::ConnectionLost,
                };
                let attempt = match attempt {
                    WithdrawalAttempt::NoResponse if connection.close_reason().is_some() => {
                        WithdrawalAttempt::ConnectionLost
                    }
                    attempt => attempt,
                };
                match attempt.next_step(retry_available) {
                    WithdrawalStep::Retry => retry_available = false,
                    WithdrawalStep::Done(outcome) => break outcome,
                }
            };
            if outcome == WithdrawalOutcome::Confirmed {
                confirmed.send_replace(true);
                credits.stop_idle();
                tokio::select! {
                    _ = credits.drained() => {}
                    _ = connection.closed() => {}
                }
            }
            close_connection(&connection, Code::H3_NO_ERROR);
            outcome
        }
    }

    /// Whether the Server has confirmed withdrawal quiescence with `204`, even if local Visitor
    /// leases are still draining.
    pub fn withdrawal_confirmed(&self) -> bool {
        *self.withdrawal_confirmed.borrow()
    }

    /// Close immediately when the Client runtime stops.
    pub fn close(&self) {
        close_connection(&self.connection, Code::H3_NO_ERROR);
    }

    /// Runtime generation of the Server this connection reached.
    pub fn server_generation(&self) -> ServerRuntimeGeneration {
        self.state.borrow().server_generation
    }

    /// Latest Server event-stream state.
    pub fn event_state(&self) -> watch::Receiver<TunnelEventState> {
        self.state.clone()
    }

    /// Wait until the connection closes for any reason.
    pub fn closed(&self) -> impl Future<Output = quinn::ConnectionError> + Send + 'static + use<> {
        let connection = self.connection.clone();
        async move { connection.closed().await }
    }

    #[cfg(test)]
    pub(crate) fn send_request_for_test(&self) -> ClientSendRequest {
        self.send_request.clone()
    }

    #[cfg(test)]
    pub(crate) fn visitor_credit_counts(&self) -> (usize, usize) {
        self.credits.counts()
    }

    #[cfg(test)]
    pub(crate) fn guard_rejections(&self) -> usize {
        self.credits
            .guard_rejections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Observe task completion while retaining the handle, without aborting the observer on drop.
    #[cfg(test)]
    pub(crate) async fn session_observer_stopped_for_test(&mut self) {
        (&mut self._session.0)
            .await
            .expect("WebTransport session observer task");
    }
}

impl Drop for ClientTunnelH3 {
    fn drop(&mut self) {
        close_connection(&self.connection, Code::H3_NO_ERROR);
    }
}

/// How placement withdrawal on one connection ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawalOutcome {
    /// The Server confirmed quiescence with a bodyless `204`.
    Confirmed,
    /// Quiescence was not confirmed; active Visitors may have been terminated.
    Unconfirmed(UnconfirmedDrain),
    /// The Server rejected a correct request or sent a malformed confirmation.
    ProtocolFailure(ProtocolFailure),
}

/// Why a withdrawal drain stayed unconfirmed. Ordinary network uncertainty, not a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnconfirmedDrain {
    /// The connection closed before confirmation, including Server revocation and shutdown.
    ConnectionLost,
    /// The one same-connection retry also failed without a response or with `408`.
    RetryExhausted,
    /// GOAWAY forbids new requests on this connection.
    RequestsForbidden,
    /// The Client-instance graceful-shutdown deadline expired.
    Deadline,
    /// Fast shutdown superseded the withdrawal.
    FastShutdown,
}

/// A withdrawal protocol-contract violation by the Server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolFailure {
    /// A final status other than `204` or a retryable `408`.
    Status(u16),
    /// A `204` that carried content or trailers.
    MalformedConfirmation,
}

impl fmt::Display for UnconfirmedDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConnectionLost => "connection-lost",
            Self::RetryExhausted => "retry-exhausted",
            Self::RequestsForbidden => "goaway",
            Self::Deadline => "deadline",
            Self::FastShutdown => "fast-shutdown",
        })
    }
}

impl fmt::Display for ProtocolFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(status) => write!(formatter, "unexpected status {status}"),
            Self::MalformedConfirmation => formatter.write_str("malformed 204 confirmation"),
        }
    }
}

/// Result of one withdrawal request stream.
#[derive(Debug, Eq, PartialEq)]
enum WithdrawalAttempt {
    /// Bodyless `204` followed by response FIN.
    Confirmed,
    /// Another well-formed final status.
    Status(StatusCode),
    /// `204` carrying content or trailers.
    MalformedConfirmation,
    /// The stream failed without a usable response while the connection may still be usable.
    NoResponse,
    /// GOAWAY forbids opening the request.
    RequestsForbidden,
    ConnectionLost,
}

enum WithdrawalStep {
    Retry,
    Done(WithdrawalOutcome),
}

impl WithdrawalAttempt {
    /// Response-less failures and `408` share one retry; every other status is final.
    fn next_step(self, retry_available: bool) -> WithdrawalStep {
        use WithdrawalOutcome::{Confirmed, ProtocolFailure as Failure, Unconfirmed};
        WithdrawalStep::Done(match self {
            Self::Confirmed => Confirmed,
            Self::NoResponse | Self::Status(StatusCode::REQUEST_TIMEOUT) if retry_available => {
                return WithdrawalStep::Retry;
            }
            Self::NoResponse | Self::Status(StatusCode::REQUEST_TIMEOUT) => {
                Unconfirmed(UnconfirmedDrain::RetryExhausted)
            }
            Self::Status(status) => Failure(ProtocolFailure::Status(status.as_u16())),
            Self::MalformedConfirmation => Failure(ProtocolFailure::MalformedConfirmation),
            Self::RequestsForbidden => Unconfirmed(UnconfirmedDrain::RequestsForbidden),
            Self::ConnectionLost => Unconfirmed(UnconfirmedDrain::ConnectionLost),
        })
    }
}

/// Send one bodyless withdrawal request on a fresh request stream and classify its response.
async fn withdrawal_attempt(send_request: &mut ClientSendRequest, uri: &str) -> WithdrawalAttempt {
    let Ok(request) = Request::put(uri).body(()) else {
        return WithdrawalAttempt::NoResponse;
    };
    let mut stream = match send_request.send_request(request).await {
        Ok(stream) => stream,
        Err(StreamError::RemoteClosing) => return WithdrawalAttempt::RequestsForbidden,
        Err(StreamError::ConnectionError { .. }) => return WithdrawalAttempt::ConnectionLost,
        Err(_) => return WithdrawalAttempt::NoResponse,
    };
    let response = match stream.finish().await {
        Ok(()) => stream.recv_response().await,
        Err(error) => Err(error),
    };
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            return WithdrawalAttempt::NoResponse;
        }
    };
    if response.status() != StatusCode::NO_CONTENT {
        return WithdrawalAttempt::Status(response.status());
    }
    // A `204` must not declare content: that is a malformed message, not a confirmation.
    let headers = response.headers();
    let declares_content = headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .any(|value| value.as_bytes().iter().any(|byte| *byte != b'0'));
    if declares_content {
        stream.stop_sending(Code::H3_MESSAGE_ERROR);
        return WithdrawalAttempt::MalformedConfirmation;
    }
    // Confirmation needs response FIN with no content or trailers.
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) if chunk.has_remaining() => {
                stream.stop_sending(Code::H3_MESSAGE_ERROR);
                return WithdrawalAttempt::MalformedConfirmation;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => return WithdrawalAttempt::NoResponse,
        }
    }
    match stream.recv_trailers().await {
        Ok(None) => WithdrawalAttempt::Confirmed,
        Ok(Some(_)) => WithdrawalAttempt::MalformedConfirmation,
        Err(_) => WithdrawalAttempt::NoResponse,
    }
}

fn close_after_failure(connection: &quinn::Connection, error: &TunnelH3Error) {
    let code = match error {
        TunnelH3Error::Incompatible(_) => Code::H3_GENERAL_PROTOCOL_ERROR,
        _ => Code::H3_NO_ERROR,
    };
    close_connection(connection, code);
}

/// Open one subscription and read until its first valid snapshot.
///
/// Comment keepalives before the first state do not satisfy the gate.
async fn subscribe(
    send_request: &mut ClientSendRequest,
    events_uri: &str,
) -> Result<(TunnelEventState, EventSubscription), TunnelH3Error> {
    let request = Request::get(events_uri)
        .header(header::ACCEPT, "text/event-stream")
        .body(())
        .map_err(|_| TunnelH3Error::Incompatible("invalid-server-hostname"))?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(TunnelH3Error::EventStream)?;
    stream.finish().await.map_err(TunnelH3Error::EventStream)?;
    let response = stream
        .recv_response()
        .await
        .map_err(TunnelH3Error::EventStream)?;
    if response.status() != StatusCode::OK {
        return Err(TunnelH3Error::Incompatible("unexpected-status"));
    }
    if !is_event_stream(response.headers()) {
        return Err(TunnelH3Error::Incompatible("unexpected-content-type"));
    }

    let mut subscription = EventSubscription {
        stream,
        parser: SseParser::new(TUNNEL_EVENT_SSE_LIMITS),
        pending: VecDeque::new(),
    };
    loop {
        match subscription.next().await? {
            EventItem::State(state) => return Ok((state, subscription)),
            EventItem::Keepalive => {}
            EventItem::Ended => return Err(TunnelH3Error::EventStreamEnded),
        }
    }
}

fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
}

struct EventSubscription {
    stream: ClientRequestStream,
    parser: SseParser,
    pending: VecDeque<SseParseItem>,
}

enum EventItem {
    State(TunnelEventState),
    Keepalive,
    Ended,
}

impl EventSubscription {
    /// Next decoded item. Incompatible framing or events return [`TunnelH3Error::Incompatible`].
    async fn next(&mut self) -> Result<EventItem, TunnelH3Error> {
        loop {
            if let Some(item) = self.pending.pop_front() {
                return match item {
                    SseParseItem::Comment => Ok(EventItem::Keepalive),
                    // A blank line after a comment dispatches an empty event.
                    SseParseItem::Event(event)
                        if event.event_type.is_none() && event.data.is_empty() =>
                    {
                        Ok(EventItem::Keepalive)
                    }
                    SseParseItem::Event(event) => {
                        TunnelEventState::decode(event.event_type.as_deref(), &event.data)
                            .map(EventItem::State)
                            .map_err(|error| TunnelH3Error::Incompatible(error.as_str()))
                    }
                };
            }

            let Some(mut chunk) = self
                .stream
                .recv_data()
                .await
                .map_err(TunnelH3Error::EventStream)?
            else {
                return Ok(EventItem::Ended);
            };
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            let items = self
                .parser
                .push(&bytes)
                .map_err(|_| TunnelH3Error::Incompatible("invalid-sse-framing"))?;
            self.pending.extend(items);
        }
    }
}

struct EventFollower {
    connection: quinn::Connection,
    send_request: ClientSendRequest,
    events_uri: String,
    state: watch::Sender<TunnelEventState>,
    timing: TunnelH3Timing,
}

/// Why one subscription stopped delivering events.
enum SubscriptionEnd {
    /// End, failure, or silence: resubscribe while the connection is usable.
    Interrupted,
    /// Protocol violation: the connection has been closed.
    Incompatible,
}

async fn follow_events(mut follower: EventFollower, mut subscription: EventSubscription) {
    loop {
        if let SubscriptionEnd::Incompatible = follower.read(&mut subscription).await {
            return;
        }
        drop(subscription);
        match follower.resubscribe().await {
            Some(next) => subscription = next,
            None => return,
        }
    }
}

impl EventFollower {
    async fn read(&self, subscription: &mut EventSubscription) -> SubscriptionEnd {
        loop {
            match timeout(self.timing.silence_deadline, subscription.next()).await {
                Ok(Ok(EventItem::State(state))) => {
                    if !self.accept_state(state) {
                        return SubscriptionEnd::Incompatible;
                    }
                }
                Ok(Ok(EventItem::Keepalive)) => {}
                Ok(Err(TunnelH3Error::Incompatible(_))) => {
                    close_connection(&self.connection, Code::H3_GENERAL_PROTOCOL_ERROR);
                    return SubscriptionEnd::Incompatible;
                }
                Ok(Ok(EventItem::Ended)) | Ok(Err(_)) | Err(_) => {
                    subscription.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return SubscriptionEnd::Interrupted;
                }
            }
        }
    }

    /// Resubscribe until a valid subscription starts. `None` when the connection closed, GOAWAY
    /// forbids new requests, or the Server became incompatible.
    async fn resubscribe(&mut self) -> Option<EventSubscription> {
        loop {
            if self.connection.close_reason().is_some() {
                return None;
            }
            sleep(self.timing.resubscribe_delay).await;
            let subscribed = timeout(
                self.timing.initial_state_deadline,
                subscribe(&mut self.send_request, &self.events_uri),
            )
            .await;
            match subscribed {
                Ok(Ok((state, subscription))) => {
                    return self.accept_state(state).then_some(subscription);
                }
                Ok(Err(TunnelH3Error::Incompatible(_))) => {
                    close_connection(&self.connection, Code::H3_GENERAL_PROTOCOL_ERROR);
                    return None;
                }
                Ok(Err(TunnelH3Error::EventStream(error))) if forbids_new_requests(&error) => {
                    return None;
                }
                Ok(Err(_)) | Err(_) => {}
            }
        }
    }

    /// Publish a state. A different generation on the same connection is a protocol violation
    /// and closes it.
    fn accept_state(&self, state: TunnelEventState) -> bool {
        if state.server_generation != self.state.borrow().server_generation {
            close_connection(&self.connection, Code::H3_GENERAL_PROTOCOL_ERROR);
            return false;
        }
        self.state.send_if_modified(|current| {
            let changed = *current != state;
            *current = state;
            changed
        });
        true
    }
}

/// GOAWAY or connection loss: no new request can start on this connection.
fn forbids_new_requests(error: &StreamError) -> bool {
    matches!(
        error,
        StreamError::RemoteClosing | StreamError::ConnectionError { .. }
    )
}
