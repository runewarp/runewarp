//! Role-specific Managed-session paths.

/// Runtime role that selects the Control event and state paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSessionRole {
    Server,
    Client,
}

/// Exact role-specific SSE downlink path. No role selector query is used.
pub fn events_path(role: ManagedSessionRole) -> &'static str {
    match role {
        ManagedSessionRole::Server => "/v1/server/events",
        ManagedSessionRole::Client => "/v1/client/events",
    }
}

/// Exact role-specific applied-state path on the same HTTP/2 connection.
pub fn state_path(role: ManagedSessionRole) -> &'static str {
    match role {
        ManagedSessionRole::Server => "/v1/server/state",
        ManagedSessionRole::Client => "/v1/client/state",
    }
}

#[cfg(test)]
mod tests {
    use super::{ManagedSessionRole, events_path, state_path};

    #[test]
    fn role_paths_are_exact_and_distinct() {
        assert_eq!(events_path(ManagedSessionRole::Server), "/v1/server/events");
        assert_eq!(events_path(ManagedSessionRole::Client), "/v1/client/events");
        assert_eq!(state_path(ManagedSessionRole::Server), "/v1/server/state");
        assert_eq!(state_path(ManagedSessionRole::Client), "/v1/client/state");
    }
}
