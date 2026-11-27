use std::fmt;
use std::path::Path;
use std::str::FromStr;

use crate::identity::{
    HexFingerprintError, IdentityKey, IdentityKeyFileError, parse_lowercase_hex_fingerprint,
    spki_fingerprint, write_lowercase_hex,
};

/// Default Server identity key filename inside the XDG data directory.
pub const SERVER_IDENTITY_KEY_FILENAME: &str = "server.key";

/// Stable pinned-public-key Server identity used to authenticate to Control.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServerIdentity([u8; 32]);

impl ServerIdentity {
    pub fn from_subject_public_key_info(subject_public_key_info: &[u8]) -> Self {
        Self(spki_fingerprint(subject_public_key_info))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lowercase_hex(formatter, &self.0)
    }
}

impl FromStr for ServerIdentity {
    type Err = ParseServerIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_lowercase_hex_fingerprint(value)
            .map(Self)
            .map_err(|error| match error {
                HexFingerprintError::WrongLength => ParseServerIdentityError::WrongLength,
                HexFingerprintError::InvalidHex => ParseServerIdentityError::InvalidHex,
            })
    }
}

#[derive(Debug)]
pub enum ParseServerIdentityError {
    WrongLength,
    InvalidHex,
}

impl fmt::Display for ParseServerIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => write!(
                formatter,
                "server identity must be 64 lowercase hex characters"
            ),
            Self::InvalidHex => write!(
                formatter,
                "server identity must use lowercase hex without separators"
            ),
        }
    }
}

impl std::error::Error for ParseServerIdentityError {}

/// Read the externally provisioned Server identity key and derive its fingerprint.
pub fn read_server_identity(path: &Path) -> Result<ServerIdentity, IdentityKeyFileError> {
    Ok(IdentityKey::read(path)?.server_identity())
}

#[cfg(test)]
mod tests {
    use super::ServerIdentity;

    #[test]
    fn parses_lowercase_hex_server_identities() {
        let identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .parse::<ServerIdentity>()
            .unwrap();

        assert_eq!(
            identity.to_string(),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn rejects_non_lowercase_hex_server_identities() {
        assert!(
            "00112233445566778899AAbbccddeeff00112233445566778899aabbccddeeff"
                .parse::<ServerIdentity>()
                .is_err()
        );
    }
}
