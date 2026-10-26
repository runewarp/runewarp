//! Ordinary-HTTP/3 Tunnel connections.
//!
//! This module owns HTTP/3 on one authenticated Tunnel connection, built on the git-pinned
//! `runewarp/h3` fork's HTTP/3 and WebTransport drivers over Quinn and rustls:
//!
//! - ALPN `h3` with a required, pinned Client identity certificate and no application 0-RTT;
//! - the Tunnel event stream, a Client-opened `GET /v1/tunnel/events` whose first valid `snapshot`
//!   event is the compatibility gate (there is no Runewarp-specific SETTINGS marker);
//! - one draft07 WebTransport session after that gate, carrying Server-opened Visitor streams;
//! - Client placement withdrawal, a bodyless `PUT /v1/tunnel/withdrawal` answered with a delayed
//!   bodyless `204` once the connection is quiescent;
//! - Server orderly shutdown through GOAWAY, with Runewarp enforcing the first-unprocessed
//!   request-stream boundary;
//! - bodyless status mapping for misdirected, unknown, or malformed signaling requests.
//!
//! Callers see Tunnel-level operations and never handle `h3` types. No Runewarp peer depends on a
//! received STOP_SENDING or RESET_STREAM error code: `h3-quinn` can deliver STOP_SENDING with code
//! 0 (hyperium/h3#361), so any stop or reset only ends that direction or stream.
//!
//! Static and Managed runtimes use this module for every Tunnel connection.

mod client;
mod config;
mod credit;
mod events;
mod server;
mod stream;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

use std::fmt;
use std::time::Duration;

use h3::error::{Code, ConnectionError, StreamError};
use tokio::task::JoinHandle;

pub use client::{ClientTunnelH3, ProtocolFailure, UnconfirmedDrain, WithdrawalOutcome};
pub use config::{
    make_client_tunnel_h3_config, make_server_tunnel_h3_config,
    make_server_tunnel_h3_config_with_resolver,
};
pub use events::{ServerRuntimeGeneration, ServerTunnelEvents, TunnelEventState};
pub use server::{OpenTunnelStreamError, ServerTunnelH3};
pub use stream::{
    ClientTunnelStream, ServerTunnelStream, TunnelReadHalf, TunnelStream, TunnelWriteHalf,
};

/// ALPN for HTTP/3 Tunnel connections. There is no fallback to `runewarp/1`.
pub const TUNNEL_H3_ALPN: &[u8] = b"h3";

/// Idle Visitor credits one Client connection reserves from its aggregate handler budget.
///
/// Each credit lets the Server start one Visitor without a Client acceptance exchange. Active
/// streams keep their permits separately, so concurrency can exceed this burst allowance.
pub const MAX_IDLE_VISITOR_CREDIT: usize = 256;

/// Tunnel event-stream resource on the Server hostname's HTTPS origin.
pub const TUNNEL_EVENTS_PATH: &str = "/v1/tunnel/events";

/// Placement-withdrawal resource on the Server hostname's HTTPS origin.
pub const TUNNEL_WITHDRAWAL_PATH: &str = "/v1/tunnel/withdrawal";

/// WebTransport session resource on the Server hostname's HTTPS origin.
pub const TUNNEL_SESSION_PATH: &str = "/v1/tunnel/session";

/// Fixed runtime-owned deadlines for Tunnel HTTP/3 signaling.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TunnelH3Timing {
    /// Server bound for receiving a complete signaling request: HEADERS through request FIN.
    pub request_deadline: Duration,
    /// Server interval between comment keepalives on a quiet event stream.
    pub keepalive_comment_interval: Duration,
    /// Server bound for one event-stream write blocked by flow control.
    pub blocked_write_deadline: Duration,
    /// Client bound for receiving the first valid snapshot of a subscription.
    pub initial_state_deadline: Duration,
    /// Client bound for silence on an established subscription.
    pub silence_deadline: Duration,
    /// Client pause before resubscribing after a subscription ends or fails.
    pub resubscribe_delay: Duration,
    /// Server wait for the Client to close a withdrawn, quiescent connection, measured from the
    /// first locally completed `204`.
    pub post_quiescence_close: Duration,
}

impl Default for TunnelH3Timing {
    fn default() -> Self {
        Self {
            request_deadline: Duration::from_secs(5),
            keepalive_comment_interval: Duration::from_secs(20),
            blocked_write_deadline: Duration::from_secs(60),
            initial_state_deadline: Duration::from_secs(60),
            silence_deadline: Duration::from_secs(60),
            resubscribe_delay: Duration::from_secs(1),
            post_quiescence_close: Duration::from_secs(5),
        }
    }
}

/// Why an HTTP/3 Tunnel connection could not be established.
#[derive(Debug)]
pub enum TunnelH3Error {
    /// The authenticated connection exposed no pinned Client identity.
    MissingClientIdentity,
    /// QUIC connection ended during HTTP/3 establishment.
    Transport(quinn::ConnectionError),
    /// HTTP/3 connection setup failed.
    Setup(ConnectionError),
    /// HTTP/3 connection setup did not finish within the handshake timeout.
    SetupTimeout,
    /// The event-stream request or response stream failed.
    EventStream(StreamError),
    /// WebTransport negotiation or CONNECT failed after the event-stream gate.
    SessionConnect(h3_webtransport::client::ConnectError),
    /// The WebTransport session CONNECT did not finish within the establishment deadline.
    SessionConnectTimeout,
    /// The event stream ended before delivering its first state.
    EventStreamEnded,
    /// No valid first state arrived within the initial-state deadline.
    InitialStateTimeout,
    /// The Server's event stream does not speak this Runewarp protocol.
    Incompatible(&'static str),
}

impl TunnelH3Error {
    pub(crate) fn is_unauthorized_client_identity(&self) -> bool {
        matches!(self, Self::Transport(error) if crate::quic::is_tls_access_denied(error))
    }
}

impl fmt::Display for TunnelH3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClientIdentity => {
                formatter.write_str("tunnel connection has no pinned client identity")
            }
            Self::Transport(_) => {
                formatter.write_str("tunnel connection closed during HTTP/3 establishment")
            }
            Self::Setup(_) => formatter.write_str("HTTP/3 tunnel connection setup failed"),
            Self::SetupTimeout => formatter.write_str("HTTP/3 tunnel connection setup timed out"),
            Self::EventStream(_) => formatter.write_str("tunnel event stream failed"),
            Self::SessionConnect(_) => formatter.write_str("tunnel WebTransport session failed"),
            Self::SessionConnectTimeout => {
                formatter.write_str("tunnel WebTransport session timed out")
            }
            Self::EventStreamEnded => {
                formatter.write_str("tunnel event stream ended before its first state")
            }
            Self::InitialStateTimeout => {
                formatter.write_str("tunnel event stream sent no state before its deadline")
            }
            Self::Incompatible(reason) => {
                write!(formatter, "incompatible tunnel event stream: {reason}")
            }
        }
    }
}

impl std::error::Error for TunnelH3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Setup(error) => Some(error),
            Self::EventStream(error) => Some(error),
            Self::SessionConnect(error) => Some(error),
            _ => None,
        }
    }
}

/// Background task aborted when its owner drops, so no connection task outlives its handle.
struct OwnedTask(JoinHandle<()>);

impl OwnedTask {
    fn spawn(future: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(tokio::spawn(future))
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Close the QUIC connection with an HTTP/3 application error code.
fn close_connection(connection: &quinn::Connection, code: Code) {
    let code = quinn::VarInt::from_u64(code.value())
        .expect("HTTP/3 error codes are QUIC variable-length integers");
    connection.close(code, b"");
}
