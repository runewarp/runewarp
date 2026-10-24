//! Client side of an HTTP/3 Tunnel connection.

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use h3::client::{RequestStream, SendRequest};
use h3::error::{Code, StreamError};
use http::{HeaderMap, Method, Request, StatusCode, header};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, sleep_until, timeout};

use crate::ServerHostname;
use crate::quic::{HANDSHAKE_TIMEOUT, with_handshake_timeout};
use crate::sse::{SseParseItem, SseParser};

use super::events::{ServerRuntimeGeneration, TUNNEL_EVENT_SSE_LIMITS, TunnelEventState};
use super::stream::{ClientTunnelStream, TunnelStream};
use super::{
    MAX_IDLE_RECEIVE_SLOTS, OwnedTask, TUNNEL_EVENTS_PATH, TunnelH3Error, TunnelH3Timing,
    close_connection,
};

type ClientSendRequest = SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientRequestStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Client-owned HTTP/3 Tunnel connection whose Server passed the event-stream gate.
///
/// Establishment returns only after the Server's first valid state, so a caller may offer
/// availability as soon as it holds this handle. The subscription is then followed for the
/// connection lifetime: it resubscribes after an end, failure, or silence while the connection
/// remains usable, and stops once GOAWAY forbids new requests. An incompatible event or a changed
/// generation closes the connection with `H3_GENERAL_PROTOCOL_ERROR`.
///
/// After the gate it keeps up to [`MAX_IDLE_RECEIVE_SLOTS`] receive slots open, each holding one
/// permit from the Client-instance stream budget, and replenishes a slot whenever one is assigned
/// or fails. Assigned slots are delivered by [`ClientTunnelH3::accept_tunnel_stream`].
///
/// Dropping the handle closes the connection immediately with `H3_NO_ERROR`.
pub struct ClientTunnelH3 {
    connection: quinn::Connection,
    state: watch::Receiver<TunnelEventState>,
    assigned: mpsc::UnboundedReceiver<ClientTunnelStream>,
    /// `h3` closes the connection when its last request sender drops, so the handle keeps one
    /// for its lifetime; background tasks that stop after GOAWAY must not end placed Visitors.
    _send_request: ClientSendRequest,
    _driver: OwnedTask,
    _events: OwnedTask,
    _slots: OwnedTask,
}

impl ClientTunnelH3 {
    /// Start HTTP/3 on an authenticated Tunnel connection to `server_hostname`, wait for the
    /// Server's first valid event-stream state, then start offering receive slots.
    ///
    /// `stream_budget` is the Client-instance stream-handler budget shared by every Tunnel
    /// connection; each idle or assigned slot holds one permit until its Tunnel stream drops.
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
        let (mut driver, mut send_request) = with_handshake_timeout(
            async {
                h3::client::builder()
                    .max_field_section_size(super::config::MAX_FIELD_SECTION_SIZE)
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .map_err(TunnelH3Error::Setup)
            },
            HANDSHAKE_TIMEOUT,
            || TunnelH3Error::SetupTimeout,
        )
        .await?;
        let driver = OwnedTask::spawn(async move {
            let _ = poll_fn(|context| driver.poll_close(context)).await;
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

        let (assigned_sender, assigned) = mpsc::unbounded_channel();
        let slots = OwnedTask::spawn(maintain_receive_slots(ReceiveSlotPool {
            send_request: send_request.clone(),
            slot_authority: format!("{server_hostname}:443"),
            stream_budget,
            budget_observer,
            connection: connection.clone(),
            assigned: assigned_sender,
            timing,
        }));
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

        Ok(Self {
            connection,
            state,
            assigned,
            _send_request: send_request,
            _driver: driver,
            _events: events,
            _slots: slots,
        })
    }

    /// Wait for the Server to place a Visitor on one of this connection's receive slots.
    ///
    /// `None` once the connection can deliver no more Visitors: it closed, or GOAWAY stopped new
    /// slots and every outstanding slot has resolved.
    pub async fn accept_tunnel_stream(&mut self) -> Option<ClientTunnelStream> {
        tokio::select! {
            stream = self.assigned.recv() => stream,
            _ = self.connection.closed() => None,
        }
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
}

impl Drop for ClientTunnelH3 {
    fn drop(&mut self) {
        close_connection(&self.connection, Code::H3_NO_ERROR);
    }
}

fn close_after_failure(connection: &quinn::Connection, error: &TunnelH3Error) {
    let code = match error {
        TunnelH3Error::Incompatible(_) => Code::H3_GENERAL_PROTOCOL_ERROR,
        _ => Code::H3_NO_ERROR,
    };
    close_connection(connection, code);
}

/// Open one subscription and read until its first valid state.
///
/// Comment keepalives before the first state do not satisfy the gate.
async fn subscribe(
    send_request: &mut ClientSendRequest,
    events_uri: &str,
) -> Result<(TunnelEventState, EventSubscription), TunnelH3Error> {
    let request = Request::get(events_uri)
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
        StreamError::RemoteClosing { .. } | StreamError::ConnectionError { .. }
    )
}

/// Receive-slot maintenance for one Tunnel connection.
struct ReceiveSlotPool {
    send_request: ClientSendRequest,
    /// Authority of every plain CONNECT slot: the Server hostname. The Server ignores the port.
    slot_authority: String,
    stream_budget: Arc<Semaphore>,
    budget_observer: Option<Arc<dyn Fn(bool) + Send + Sync>>,
    connection: quinn::Connection,
    assigned: mpsc::UnboundedSender<ClientTunnelStream>,
    timing: TunnelH3Timing,
}

/// Keep up to [`MAX_IDLE_RECEIVE_SLOTS`] slots open until GOAWAY or connection loss forbids new
/// requests, then let outstanding slots resolve.
///
/// A slot that ends without assignment, for example one the Server rejected, pauses opening for
/// the resubscribe delay so a refusing Server cannot drive a busy loop.
async fn maintain_receive_slots(mut pool: ReceiveSlotPool) {
    let mut waiting: JoinSet<Option<ClientTunnelStream>> = JoinSet::new();
    let mut opening = true;
    let mut next_open = Instant::now();

    while opening || !waiting.is_empty() {
        let may_open = opening && waiting.len() < MAX_IDLE_RECEIVE_SLOTS;
        if may_open
            && pool.stream_budget.available_permits() == 0
            && let Some(observer) = &pool.budget_observer
        {
            observer(false);
        }
        tokio::select! {
            _ = pool.connection.closed() => break,
            resolved = waiting.join_next(), if !waiting.is_empty() => {
                match resolved {
                    Some(Ok(Some(stream))) => {
                        // A dropped receiver resets the stream through its write half.
                        let _ = pool.assigned.send(stream);
                    }
                    Some(Ok(None) | Err(_)) | None => {
                        if opening {
                            next_open = Instant::now() + pool.timing.resubscribe_delay;
                        }
                    }
                }
            }
            permit = async {
                sleep_until(next_open).await;
                pool.stream_budget.clone().acquire_owned().await
            }, if may_open => {
                let Ok(permit) = permit else {
                    opening = false;
                    continue;
                };
                if let Some(observer) = &pool.budget_observer {
                    observer(true);
                }
                match pool.open_slot().await {
                    Ok(stream) => {
                        waiting.spawn(wait_for_assignment(stream, permit));
                    }
                    Err(error) if forbids_new_requests(&error) => opening = false,
                    Err(_) => next_open = Instant::now() + pool.timing.resubscribe_delay,
                }
            }
        }
    }
}

impl ReceiveSlotPool {
    /// Send one plain CONNECT request's HEADERS, leaving the stream open for Visitor bytes.
    async fn open_slot(&mut self) -> Result<ClientRequestStream, StreamError> {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(self.slot_authority.as_str())
            .body(())
            .expect("a Server hostname and port form a valid CONNECT authority");
        self.send_request.send_request(request).await
    }
}

/// Resolve one slot: a `200` response is the Server's assignment of one Visitor.
async fn wait_for_assignment(
    mut stream: ClientRequestStream,
    permit: OwnedSemaphorePermit,
) -> Option<ClientTunnelStream> {
    let response = stream.recv_response().await.ok()?;
    if response.status() != StatusCode::OK {
        return None;
    }
    let (send, recv) = stream.split();
    Some(TunnelStream::new(recv, send, Arc::new(permit)))
}
