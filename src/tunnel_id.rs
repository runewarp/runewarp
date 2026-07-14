//! Control-owned **Tunnel ID** for Managed-mode Server tunnels.

use std::fmt;

use crate::opaque_control_token::{OpaqueControlTokenError, validate_opaque_control_token};

/// Opaque identifier for one **Tunnel** in **Managed mode**.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TunnelId(String);

impl TunnelId {
    /// Parse a Control-published Tunnel ID string.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, OpaqueControlTokenError> {
        let value = value.as_ref();
        validate_opaque_control_token(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TunnelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::TunnelId;
    use crate::opaque_control_token::OpaqueControlTokenError;

    #[test]
    fn parses_valid_tunnel_id() {
        let id = TunnelId::parse("tunnel-a").unwrap();
        assert_eq!(id.as_str(), "tunnel-a");
        assert_eq!(id.to_string(), "tunnel-a");
    }

    #[test]
    fn rejects_invalid_tunnel_id() {
        assert_eq!(
            TunnelId::parse("").unwrap_err(),
            OpaqueControlTokenError::Empty
        );
        assert_eq!(
            TunnelId::parse("bad id").unwrap_err(),
            OpaqueControlTokenError::ForbiddenCharacter
        );
    }
}
