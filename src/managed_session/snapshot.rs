//! v1 Managed-session snapshot envelope validation.
//!
//! Validates the shared envelope required to accept a downlink snapshot:
//! non-empty opaque revision plus a present `input` object. Role-specific
//! `input` schema checks live in [`super::input`].

use std::fmt;

use crate::opaque_control_token::{OpaqueControlTokenError, validate_opaque_control_token};
use serde::Deserialize;
use serde_json::Value;

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
) -> Result<SnapshotEnvelope, SnapshotError> {
    match event_type {
        Some("snapshot") => {}
        Some(other) => return Err(SnapshotError::UnknownEventType(other.to_owned())),
        None => return Err(SnapshotError::MissingEventType),
    }

    let raw: RawSnapshot = serde_json::from_str(data).map_err(|_| SnapshotError::InvalidJson)?;
    let revision = raw.revision.ok_or(SnapshotError::MissingRevision)?;
    validate_opaque_control_token(&revision).map_err(|error| match error {
        OpaqueControlTokenError::Empty => SnapshotError::EmptyRevision,
        other => SnapshotError::InvalidRevision(other),
    })?;
    let input = raw.input.ok_or(SnapshotError::MissingInput)?;
    if !input.is_object() {
        return Err(SnapshotError::MissingInput);
    }
    Ok(SnapshotEnvelope { revision, input })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{SnapshotError, parse_snapshot_event};

    #[test]
    fn accepts_snapshot_with_revision_and_input() {
        let envelope = parse_snapshot_event(
            Some("snapshot"),
            r#"{"revision":"rev-1","input":{"tunnels":[]},"extra":true}"#,
        )
        .unwrap();
        assert_eq!(envelope.revision, "rev-1");
        assert_eq!(envelope.input, json!({"tunnels":[]}));
    }

    #[test]
    fn rejects_unknown_event_types_and_missing_type() {
        assert_eq!(
            parse_snapshot_event(Some("patch"), "{}").unwrap_err(),
            SnapshotError::UnknownEventType("patch".to_owned())
        );
        assert_eq!(
            parse_snapshot_event(None, "{}").unwrap_err(),
            SnapshotError::MissingEventType
        );
    }

    #[test]
    fn rejects_invalid_json_missing_fields_and_empty_revision() {
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), "{").unwrap_err(),
            SnapshotError::InvalidJson
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), r#"{"input":{}}"#).unwrap_err(),
            SnapshotError::MissingRevision
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), r#"{"revision":"","input":{}}"#).unwrap_err(),
            SnapshotError::EmptyRevision
        );
        assert_eq!(
            parse_snapshot_event(Some("snapshot"), r#"{"revision":"rev-1"}"#).unwrap_err(),
            SnapshotError::MissingInput
        );
        let invalid_input =
            parse_snapshot_event(Some("snapshot"), r#"{"revision":"rev-1","input":null}"#)
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
            parse_snapshot_event(Some("snapshot"), r#"{"revision":"bad rev","input":{}}"#)
                .unwrap_err(),
            SnapshotError::InvalidRevision(_)
        ));
        let oversize = "a".repeat(crate::opaque_control_token::OPAQUE_CONTROL_TOKEN_MAX_CHARS + 1);
        let payload = format!(r#"{{"revision":"{oversize}","input":{{}}}}"#);
        assert!(matches!(
            parse_snapshot_event(Some("snapshot"), &payload).unwrap_err(),
            SnapshotError::InvalidRevision(_)
        ));
    }
}
