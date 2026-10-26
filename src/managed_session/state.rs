//! Role facts reported in Managed-session state documents.
//!
//! Every `PUT .../state` body is the role's full current state document: the session-owned
//! applied `revision`, then the role's facts in order. The session stays role-agnostic: a role
//! supplies a [`RoleState`] that renders its facts and signals when they may have changed.

use futures_util::future::BoxFuture;
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Role facts in wire order. A fact named `revision` is ignored: the session owns it.
pub type StateFields = Vec<(&'static str, Value)>;

/// Source of the facts one Managed role reports after `revision` in every state document.
pub trait RoleState: Send + Sync + 'static {
    /// Render the current facts. Called when a state request starts, so it sees the latest state.
    fn fields(&self) -> BoxFuture<'_, StateFields>;

    /// Resolve after a reported fact may have changed. Implementations must keep a change made
    /// while nobody waits, as `Notify::notify_one` does, so no change is lost between requests.
    fn changed(&self) -> BoxFuture<'_, ()>;
}

/// State document body: `revision` first, then role facts in order.
pub(super) struct StateDocument<'a> {
    pub(super) revision: &'a str,
    pub(super) fields: &'a [(&'static str, Value)],
}

impl Serialize for StateDocument<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields = self
            .fields
            .iter()
            .filter(|(name, _)| *name != "revision")
            .map(|(name, value)| (*name, value));
        serializer
            .collect_map(std::iter::once(("revision", &Value::from(self.revision))).chain(fields))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::StateDocument;

    #[test]
    fn documents_put_the_revision_first_and_ignore_a_role_revision() {
        let fields = vec![
            ("generation", json!("g")),
            ("revision", json!("spoofed")),
            ("tunnels", json!({"b": 1, "a": 2})),
        ];
        let body = serde_json::to_string(&StateDocument {
            revision: "srv-42",
            fields: &fields,
        })
        .unwrap();
        assert_eq!(
            body,
            r#"{"revision":"srv-42","generation":"g","tunnels":{"a":2,"b":1}}"#
        );
    }
}
