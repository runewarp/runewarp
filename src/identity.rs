use std::fmt;
use std::str::FromStr;

use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

pub const CLIENT_CERT_LIFETIME_DAYS: u64 = 90;
pub const CLIENT_CERT_RENEW_AFTER_DAYS: u64 = 60;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientIdentity([u8; 32]);

impl ClientIdentity {
    pub fn from_subject_public_key_info(subject_public_key_info: &[u8]) -> Self {
        let fingerprint = Sha256::digest(subject_public_key_info);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&fingerprint);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ClientIdentity {
    type Err = ParseClientIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(ParseClientIdentityError::WrongLength);
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let pair =
                std::str::from_utf8(chunk).map_err(|_| ParseClientIdentityError::InvalidHex)?;
            if pair
                .chars()
                .any(|character| !character.is_ascii_hexdigit() || character.is_ascii_uppercase())
            {
                return Err(ParseClientIdentityError::InvalidHex);
            }
            bytes[index] =
                u8::from_str_radix(pair, 16).map_err(|_| ParseClientIdentityError::InvalidHex)?;
        }

        Ok(Self(bytes))
    }
}

#[derive(Debug)]
pub enum ParseClientIdentityError {
    WrongLength,
    InvalidHex,
}

impl fmt::Display for ParseClientIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => write!(
                formatter,
                "client identity must be 64 lowercase hex characters"
            ),
            Self::InvalidHex => write!(
                formatter,
                "client identity must use lowercase hex without separators"
            ),
        }
    }
}

impl std::error::Error for ParseClientIdentityError {}

pub struct GeneratedClientIdentity {
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub client_identity: ClientIdentity,
}

pub fn generate_client_identity() -> Result<GeneratedClientIdentity, rcgen::Error> {
    let signing_key = KeyPair::generate()?;
    let mut certificate_params = CertificateParams::new(vec!["runewarp-client".to_owned()])?;
    let not_before = OffsetDateTime::now_utc() - Duration::minutes(1);
    certificate_params.not_before = not_before;
    certificate_params.not_after = not_before + Duration::days(CLIENT_CERT_LIFETIME_DAYS as i64);
    let certificate = certificate_params.self_signed(&signing_key)?;
    let client_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    Ok(GeneratedClientIdentity {
        private_key_pem: signing_key.serialize_pem(),
        certificate_pem: certificate.pem(),
        client_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::{CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS, ClientIdentity};

    #[test]
    fn parses_lowercase_hex_client_identities() {
        let identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            .parse::<ClientIdentity>()
            .unwrap();

        assert_eq!(
            identity.to_string(),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn rejects_non_lowercase_hex_client_identities() {
        assert!(
            "00112233445566778899AAbbccddeeff00112233445566778899aabbccddeeff"
                .parse::<ClientIdentity>()
                .is_err()
        );
        assert!(
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff0011223344556677"
                .parse::<ClientIdentity>()
                .is_err()
        );
    }

    #[test]
    fn phase_two_identity_defaults_stay_explicit() {
        assert_eq!(CLIENT_CERT_LIFETIME_DAYS, 90);
        assert_eq!(CLIENT_CERT_RENEW_AFTER_DAYS, 60);
    }
}
