//! Role-neutral Managed-session engine.
//!
//! Establishes one mutually authenticated HTTP/2 connection, opens the
//! role-specific SSE stream, validates role inputs, sequences reconciliation
//! through a role adapter, and acknowledges successfully applied revisions
//! on the same connection.
//!
//! The public surface is the domain seam used by production runtimes and
//! integration tests: [`ManagedSession`], [`RoleAdapter`], role input types,
//! and session material. Transport, SSE framing, snapshot parsing, reporting
//! queues, timers, and TLS loading stay crate-internal.

mod adapter;
mod connection;
mod input;
mod limits;
mod reconcile;
mod role;
mod session;
mod snapshot;
mod sse;
mod status;
mod timing;
mod tls;

pub use adapter::{ApplyError, RoleAdapter};
pub use input::{
    ClientManagedInput, InputError, ServerManagedInput, parse_client_input, parse_server_input,
};
pub use limits::{ManagedSessionLimitKind, ManagedSessionLimits};
pub use role::ManagedSessionRole;
pub use session::{ManagedSession, ManagedSessionEvent};
pub use tls::{
    ControlClientIdentityMaterial, ControlTlsMaterialError, SessionMaterial, TrustLoadError,
};
