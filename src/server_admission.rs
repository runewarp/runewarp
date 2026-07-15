//! Server admission decided once during Config preparation.

/// How the Server admits authorization and readiness at bind time.
///
/// Config validation sets this once from Control address presence. Startup and
/// Authorization construction consume that prepared outcome instead of
/// re-deriving admission from `control` at every layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ServerAdmission {
    /// Static mode: requires at least one Tunnel and gains readiness immediately.
    #[default]
    Static,
    /// Managed mode: empty authorization is allowed; readiness stays deferred
    /// until the first successful Managed-session apply.
    Managed,
}
