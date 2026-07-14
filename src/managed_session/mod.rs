//! Role-neutral Managed-session engine.
//!
//! Establishes one mutually authenticated HTTP/2 connection, opens the
//! role-specific SSE stream, validates role inputs, sequences reconciliation
//! through a role adapter, and acknowledges successfully applied revisions
//! on the same connection.

mod adapter;
mod connection;
mod input;
mod reconcile;
mod role;
mod session;
mod snapshot;
mod sse;
mod status;
mod timing;
mod tls;

pub use adapter::{ApplyError, DeferredClientAdapter, DeferredServerAdapter, RoleAdapter};
pub use connection::{ConnectionError, ManagedSessionConnection};
pub use input::{
    ClientManagedInput, InputError, ServerManagedInput, parse_client_input, parse_server_input,
};
pub use role::{ManagedSessionRole, events_path, state_path};
pub use session::{ManagedSession, ManagedSessionError, ManagedSessionEvent};
pub use snapshot::{SnapshotEnvelope, SnapshotError, parse_snapshot_event};
pub use sse::{SseEvent, SseParseError, SseParseItem, SseParser};
pub use status::{
    SseResponseClass, StateResponseClass, classify_sse_response, classify_state_response,
};
pub use timing::{FIRST_SNAPSHOT_DEADLINE, SILENCE_TIMEOUT, SessionClock, SystemSessionClock};
pub use tls::{
    CONTROL_ALPN_H2, ControlClientIdentityMaterial, ControlTlsMaterial, ControlTlsMaterialError,
    SessionMaterial, load_control_tls_material,
};
