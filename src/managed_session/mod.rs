//! Role-neutral Managed-session downlink.
//!
//! Establishes one mutually authenticated HTTP/2 connection, opens the
//! role-specific SSE stream, validates snapshot envelopes, and replaces the
//! whole connection on any session failure.

mod connection;
mod role;
mod session;
mod snapshot;
mod sse;
mod status;
mod timing;
mod tls;

pub use connection::{ConnectionError, ManagedSessionConnection};
pub use role::{ManagedSessionRole, events_path};
pub use session::{ManagedSession, ManagedSessionError, ManagedSessionEvent};
pub use snapshot::{SnapshotEnvelope, SnapshotError, parse_snapshot_event};
pub use sse::{SseEvent, SseParseError, SseParseItem, SseParser};
pub use status::{SseResponseClass, classify_sse_response};
pub use timing::{FIRST_SNAPSHOT_DEADLINE, SILENCE_TIMEOUT, SessionClock, SystemSessionClock};
pub use tls::{
    CONTROL_ALPN_H2, ControlClientIdentityMaterial, ControlTlsMaterial, ControlTlsMaterialError,
    SessionMaterial, load_control_tls_material,
};
