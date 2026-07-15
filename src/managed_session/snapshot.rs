//! v1 Managed-session snapshot envelope validation.
//!
//! Validates the shared envelope required to accept a downlink snapshot:
//! non-empty opaque revision plus a present `input` object. Role-specific
//! `input` schema checks live in [`super::input`]. Complete snapshot bytes and
//! cumulative decoded allocation are bounded before role parsing.

use std::fmt;

use crate::opaque_control_token::{OpaqueControlTokenError, validate_opaque_control_token};
use serde::Deserialize;
use serde_json::Value;

use super::limits::{ManagedSessionLimitKind, ManagedSessionLimits};

/// Validated v1 snapshot envelope from an SSE `snapshot` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEnvelope {
    pub revision: String,
    pub input: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    InvalidJson,
    MissingRevision,
    EmptyRevision,
    InvalidRevision(OpaqueControlTokenError),
    MissingInput,
    UnknownEventType(String),
    MissingEventType,
    LimitExceeded {
        limit: ManagedSessionLimitKind,
        value: usize,
        max: usize,
    },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => formatter.write_str("snapshot JSON was invalid"),
            Self::MissingRevision => formatter.write_str("snapshot omitted revision"),
            Self::EmptyRevision => formatter.write_str("snapshot revision was empty"),
            Self::InvalidRevision(error) => {
                write!(formatter, "snapshot revision was invalid: {error}")
            }
            Self::MissingInput => {
                formatter.write_str("snapshot input was missing or not an object")
            }
            Self::UnknownEventType(event_type) => {
                write!(formatter, "unknown SSE event type `{event_type}`")
            }
            Self::MissingEventType => formatter.write_str("SSE event omitted event type"),
            Self::LimitExceeded { limit, value, max } => write!(
                formatter,
                "snapshot {} limit exceeded: value={value} max={max}",
                limit.as_str()
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug, Deserialize)]
struct RawSnapshot {
    revision: Option<String>,
    input: Option<Value>,
}

/// Interpret a completed SSE event as a v1 snapshot envelope.
pub fn parse_snapshot_event(
    event_type: Option<&str>,
    data: &str,
    limits: &ManagedSessionLimits,
) -> Result<SnapshotEnvelope, SnapshotError> {
    match event_type {
        Some("snapshot") => {}
        Some(other) => return Err(SnapshotError::UnknownEventType(other.to_owned())),
        None => return Err(SnapshotError::MissingEventType),
    }

    if data.len() > limits.max_snapshot_bytes {
        return Err(SnapshotError::LimitExceeded {
            limit: ManagedSessionLimitKind::SnapshotBytes,
            value: data.len(),
            max: limits.max_snapshot_bytes,
        });
    }

    let raw: RawSnapshot = serde_json::from_str(data).map_err(|_| SnapshotError::InvalidJson)?;
    let revision = raw.revision.ok_or(SnapshotError::MissingRevision)?;
    let revision_chars = revision.chars().count();
    if revision_chars > limits.max_revision_chars {
        return Err(SnapshotError::LimitExceeded {
            limit: ManagedSessionLimitKind::RevisionChars,
            value: revision_chars,
            max: limits.max_revision_chars,
        });
    }
    validate_opaque_control_token(&revision).map_err(|error| match error {
        OpaqueControlTokenError::Empty => SnapshotError::EmptyRevision,
        other => SnapshotError::InvalidRevision(other),
    })?;
    let input = raw.input.ok_or(SnapshotError::MissingInput)?;
    if !input.is_object() {
        return Err(SnapshotError::MissingInput);
    }

    let decoded = data.len().saturating_add(estimate_json_allocation(&input));
    if decoded > limits.max_decoded_allocation_bytes {
        return Err(SnapshotError::LimitExceeded {
            limit: ManagedSessionLimitKind::DecodedAllocationBytes,
            value: decoded,
            max: limits.max_decoded_allocation_bytes,
        });
    }

    Ok(SnapshotEnvelope { revision, input })
}

/// Approximate retained allocation for a JSON value tree.
pub(crate) fn estimate_json_allocation(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(_) => 1,
        Value::Number(number) => number.to_string().len(),
        Value::String(string) => string.len(),
        Value::Array(items) => items
            .iter()
            .map(estimate_json_allocation)
            .fold(items.len(), |acc, item| acc.saturating_add(item)),
        Value::Object(map) => map.iter().fold(map.len(), |acc, (key, item)| {
            acc.saturating_add(key.len())
                .saturating_add(estimate_json_allocation(item))
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{SnapshotError, parse_snapshot_event};
    use crate::managed_session::limits::{ManagedSessionLimitKind, ManagedSessionLimits};

    fn limits() -> ManagedSessionLimits {
        ManagedSessionLimits::default()
    }

    #[test]
    fn accepts_snapshot_with_revision_and_input() {
        let envelope = parse_snapshot_event(
            Some("snapshot"),
            r#"{"revision":"rev-1","input":{"tunnels":[]},"extra":true}"#,
            &limits(),
        )
        .unwrap();
        assert_eq!(envelope.revision, "rev-1");
        assert_eq!(envelope.input, json!({"tunnels":[]}));
    }

    #[test]
    fn rejects_unknown_event_types_and_missing_type() {
        assert_eq!(
            parse_snapshot_event(Some("patch"), "{}", &limits()).unwrap_err(),
            SnapshotError::UnknownEventType("patch".to_owned())
        );
        assert_eq!(
            parse_snapshot_event(None, "{}", &limits()).unwrap_err(),
            SnapshotError::MissingEventType
        );
    }

    #[test]
    fn rejects_invalid_json_missing_fields_and_empty_revision() {
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), "{", &limits()).unwrap_err(),
            SnapshotError::InvalidJson
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), r#"{"input":{}}"#, &limits()).unwrap_err(),
            SnapshotError::MissingRevision
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), r#"{"revision":"","input":{}}"#, &limits())
                .unwrap_err(),
            SnapshotError::EmptyRevision
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), r#"{"revision":"rev-1"}"#, &limits())
                .unwrap_err(),
            SnapshotError::MissingInput
        );
        let invalid_input = parse_snapshot_event(
            Some("snapshot"),
            r#"{"revision":"rev-1","input":null}"#,
            &limits(),
        )
        .unwrap_err();
        assert_eq!(invalid_input, SnapshotError::MissingInput);
        assert_eq!(
            invalid_input.to_string(),
            "snapshot input was missing or not an object"
        );
    }

    #[test]
    fn rejects_revision_with_whitespace_or_oversize() {
        assert!(matches!(
            parse_snapshot_event(
                Some("snapshot"),
                r#"{"revision":"bad rev","input":{}}"#,
                &limits()
            )
            .unwrap_err(),
            SnapshotError::InvalidRevision(_)
        ));
        let oversize = "a".repeat(crate::opaque_control_token::OPAQUE_CONTROL_TOKEN_MAX_CHARS + 1);
        let payload = format!(r#"{{"revision":"{oversize}","input":{{}}}}"#);
        assert!(matches!(
            parse_snapshot_event(Some("snapshot"), &payload, &limits()).unwrap_err(),
            SnapshotError::LimitExceeded {
                limit: ManagedSessionLimitKind::RevisionChars,
                ..
            }
        ));
    }

    #[test]
    fn rejects_oversize_snapshot_bytes_before_json_work() {
        let limits = ManagedSessionLimits {
            max_snapshot_bytes: 32,
            ..ManagedSessionLimits::default()
        };
        let payload = format!(
            r#"{{"revision":"rev-1","input":{{"pad":"{}"}}}}"#,
            "x".repeat(64)
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), &payload, &limits).unwrap_err(),
            SnapshotError::LimitExceeded {
                limit: ManagedSessionLimitKind::SnapshotBytes,
                value: payload.len(),
                max: 32,
            }
        );
    }

    #[test]
    fn rejects_decoded_allocation_budget() {
        let limits = ManagedSessionLimits {
            max_snapshot_bytes: 1024,
            max_decoded_allocation_bytes: 40,
            ..ManagedSessionLimits::default()
        };
        let payload =
            r#"{"revision":"rev-1","input":{"tunnels":[],"pad":"abcdefghijklmnopqrstuvwxyz"}}"#;
        assert!(matches!(
            parse_snapshot_event(Some("snapshot"), payload, &limits).unwrap_err(),
            SnapshotError::LimitExceeded {
                limit: ManagedSessionLimitKind::DecodedAllocationBytes,
                ..
            }
        ));
    }
}
