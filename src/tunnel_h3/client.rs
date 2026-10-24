//! Client side of an HTTP/3 Tunnel connection.

use std::collections::VecDeque;

use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use h3::client::{RequestStream, SendRequest};
use h3::error::{Code, StreamError};
use http::{HeaderMap, Request, StatusCode, header};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

use crate::ServerHostname;
use crate::quic::{HANDSHAKE_TIMEOUT, with_handshake_timeout};
use crate::sse::{SseParseItem, SseParser};

use super::events::{ServerRuntimeGeneration, TUNNEL_EVENT_SSE_LIMITS, TunnelEventState};
use super::{OwnedTask, TUNNEL_EVENTS_PATH, TunnelH3Error, TunnelH3Timing, close_connection};

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
/// Dropping the handle closes the connection immediately with `H3_NO_ERROR`.
pub struct ClientTunnelH3 {
    connection: quinn::Connection,
    state: watch::Receiver<TunnelEventState>,
    _driver: OwnedTask,
    _events: OwnedTask,
}

impl ClientTunnelH3 {
    /// Start HTTP/3 on an authenticated Tunnel connection to `server_hostname` and wait for the
    /// Server's first valid event-stream state.
    pub async fn establish(
        connection: quinn::Connection,
        server_hostname: &ServerHostname,
    ) -> Result<Self, TunnelH3Error> {
        Self::establish_with_timing(connection, server_hostname, TunnelH3Timing::default()).await
    }

    pub(crate) async fn establish_with_timing(
        connection: quinn::Connection,
        server_hostname: &ServerHostname,
        timing: TunnelH3Timing,
    ) -> Result<Self, TunnelH3Error> {
        let (mut driver, mut send_request) = with_handshake_timeout(
            async {
                h3::client::new(h3_quinn::Connection::new(connection.clone()))
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
                close_after_failure(&connection, &error);
                return Err(error);
            }
            Err(_) => {
                close_connection(&connection, Code::H3_NO_ERROR);
                return Err(TunnelH3Error::InitialStateTimeout);
            }
        };

        let (state_sender, state) = watch::channel(initial);
        let events = OwnedTask::spawn(follow_events(
            EventFollower {
                connection: connection.clone(),
                send_request,
                events_uri,
                state: state_sender,
                timing,
            },
            subscription,
        ));

        Ok(Self {
            connection,
            state,
            _driver: driver,
            _events: events,
        })
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
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
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
