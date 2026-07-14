//! Opaque Control tokens: Managed-session revision and Tunnel ID strings.
//!
//! Core compares these by equality only. Control may use UUIDs or hashes as a
//! convention; Core does not parse those formats.

use std::fmt;

/// Maximum Unicode scalar count for revision and Tunnel ID strings.
pub(crate) const OPAQUE_CONTROL_TOKEN_MAX_CHARS: usize = 128;

/// Why an opaque Control token was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpaqueControlTokenError {
    Empty,
    TooLong { len: usize },
    ForbiddenCharacter,
}

impl fmt::Display for OpaqueControlTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("opaque Control token was empty"),
            Self::TooLong { len } => write!(
                formatter,
                "opaque Control token length {len} exceeds maximum of {OPAQUE_CONTROL_TOKEN_MAX_CHARS}"
            ),
            Self::ForbiddenCharacter => formatter
                .write_str("opaque Control token contains ASCII whitespace or control characters"),
        }
    }
}

impl std::error::Error for OpaqueControlTokenError {}

/// Validate a Managed-session revision or Tunnel ID string.
///
/// Rules: non-empty, at most [`OPAQUE_CONTROL_TOKEN_MAX_CHARS`] Unicode scalars,
/// and no ASCII whitespace or control characters. No trim.
pub(crate) fn validate_opaque_control_token(value: &str) -> Result<(), OpaqueControlTokenError> {
    if value.is_empty() {
        return Err(OpaqueControlTokenError::Empty);
    }
    let len = value.chars().count();
    if len > OPAQUE_CONTROL_TOKEN_MAX_CHARS {
        return Err(OpaqueControlTokenError::TooLong { len });
    }
    if value
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch.is_ascii_control())
    {
        return Err(OpaqueControlTokenError::ForbiddenCharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        OPAQUE_CONTROL_TOKEN_MAX_CHARS, OpaqueControlTokenError, validate_opaque_control_token,
    };

    #[test]
    fn accepts_uuid_and_sha256_hex_shapes() {
        validate_opaque_control_token("550e8400-e29b-41d4-a716-446655440000").unwrap();
        validate_opaque_control_token(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
    }

    #[test]
    fn rejects_empty_oversize_and_whitespace_or_controls() {
        assert_eq!(
            validate_opaque_control_token("").unwrap_err(),
            OpaqueControlTokenError::Empty
        );
        let oversize: String = "a".repeat(OPAQUE_CONTROL_TOKEN_MAX_CHARS + 1);
        assert_eq!(
            validate_opaque_control_token(&oversize).unwrap_err(),
            OpaqueControlTokenError::TooLong {
                len: OPAQUE_CONTROL_TOKEN_MAX_CHARS + 1
            }
        );
        assert_eq!(
            validate_opaque_control_token("has space").unwrap_err(),
            OpaqueControlTokenError::ForbiddenCharacter
        );
        assert_eq!(
            validate_opaque_control_token("has\ttab").unwrap_err(),
            OpaqueControlTokenError::ForbiddenCharacter
        );
        assert_eq!(
            validate_opaque_control_token("has\nnewline").unwrap_err(),
            OpaqueControlTokenError::ForbiddenCharacter
        );
        assert_eq!(
            validate_opaque_control_token("has\0null").unwrap_err(),
            OpaqueControlTokenError::ForbiddenCharacter
        );
    }

    #[test]
    fn accepts_exact_max_length_without_trimming() {
        let exact: String = "a".repeat(OPAQUE_CONTROL_TOKEN_MAX_CHARS);
        validate_opaque_control_token(&exact).unwrap();
    }
}
