use std::fmt;
use std::fs;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use x509_parser::parse_x509_certificate;

use crate::cert_file_ops;

pub const CLIENT_CERT_LIFETIME_DAYS: u64 = 90;
pub const CLIENT_CERT_RENEW_AFTER_DAYS: u64 = 60;
pub const CLIENT_CERT_FILENAME: &str = "client.crt";
pub const CLIENT_KEY_FILENAME: &str = "client.key";
pub const CLIENT_IDENTITY_FILENAME: &str = "client-identity.txt";

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

pub struct ClientCertificateState {
    pub client_identity: ClientIdentity,
    pub renew_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCertificateRenewalDecision {
    NotDue {
        renew_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    },
    Due {
        renew_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    },
    Expired {
        expired_at: OffsetDateTime,
    },
}

#[derive(Debug)]
pub enum ParseClientIdentityCertificateError {
    ParseCertificate,
}

impl fmt::Display for ParseClientIdentityCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseCertificate => {
                formatter.write_str("client certificate is not valid X.509 DER")
            }
        }
    }
}

impl std::error::Error for ParseClientIdentityCertificateError {}

pub fn generate_client_identity() -> Result<GeneratedClientIdentity, rcgen::Error> {
    let signing_key = KeyPair::generate()?;
    let certificate_pem = issue_client_certificate(&signing_key, OffsetDateTime::now_utc())?;
    let client_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    Ok(GeneratedClientIdentity {
        private_key_pem: signing_key.serialize_pem(),
        certificate_pem,
        client_identity,
    })
}

#[derive(Debug)]
pub enum ClientIdentityMaterialError {
    ReadFile {
        path: PathBuf,
        source: io::Error,
    },
    WriteFile {
        path: PathBuf,
        source: io::Error,
    },
    ParseCertificate {
        path: PathBuf,
    },
    ParseKey(rcgen::Error),
    Generate(rcgen::Error),
    IdentityMismatch {
        stored: ClientIdentity,
        derived: ClientIdentity,
    },
}

impl fmt::Display for ClientIdentityMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, .. } => {
                write!(formatter, "failed to read {}", path.display())
            }
            Self::WriteFile { path, .. } => {
                write!(formatter, "failed to write {}", path.display())
            }
            Self::ParseCertificate { path } => {
                write!(
                    formatter,
                    "failed to parse a client certificate from {}",
                    path.display()
                )
            }
            Self::ParseKey(_) => formatter.write_str("failed to parse the client private key"),
            Self::Generate(_) => formatter.write_str("failed to generate a client certificate"),
            Self::IdentityMismatch { stored, derived } => write!(
                formatter,
                "stored client identity {stored} does not match the current key or certificate identity {derived}"
            ),
        }
    }
}

impl std::error::Error for ClientIdentityMaterialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } | Self::WriteFile { source, .. } => Some(source),
            Self::ParseKey(source) | Self::Generate(source) => Some(source),
            Self::ParseCertificate { .. } | Self::IdentityMismatch { .. } => None,
        }
    }
}

pub fn renew_client_identity_certificate(
    directory: &Path,
) -> Result<ClientCertificateState, ClientIdentityMaterialError> {
    let material = load_client_identity_material(directory)?;
    let certificate_pem =
        issue_client_certificate(&material.signing_key, OffsetDateTime::now_utc())
            .map_err(ClientIdentityMaterialError::Generate)?;
    let certificate_path = directory.join(CLIENT_CERT_FILENAME);
    replace_file_atomically_with_mode(&certificate_path, certificate_pem.as_bytes(), 0o644)?;
    let updated_material = load_client_identity_material(directory)?;

    Ok(ClientCertificateState {
        client_identity: updated_material.client_identity,
        renew_at: updated_material.renew_at,
        expires_at: updated_material.expires_at,
    })
}

pub fn inspect_client_certificate_renewal(
    directory: &Path,
    now: OffsetDateTime,
) -> Result<ClientCertificateRenewalDecision, ClientIdentityMaterialError> {
    let material = load_client_identity_material(directory)?;
    Ok(decide_client_certificate_renewal(
        material.renew_at,
        material.expires_at,
        now,
    ))
}

pub fn read_client_identity(
    directory: &Path,
) -> Result<ClientIdentity, ClientIdentityMaterialError> {
    Ok(load_client_identity_material(directory)?.client_identity)
}

pub fn rotate_client_identity(
    directory: &Path,
) -> Result<ClientCertificateState, ClientIdentityMaterialError> {
    let _ = load_client_identity_material(directory)?;
    let generated = generate_client_identity().map_err(ClientIdentityMaterialError::Generate)?;

    replace_file_atomically_with_mode(
        &directory.join(CLIENT_KEY_FILENAME),
        generated.private_key_pem.as_bytes(),
        0o600,
    )?;
    replace_file_atomically_with_mode(
        &directory.join(CLIENT_CERT_FILENAME),
        generated.certificate_pem.as_bytes(),
        0o644,
    )?;
    replace_file_atomically_with_mode(
        &directory.join(CLIENT_IDENTITY_FILENAME),
        generated.client_identity.to_string().as_bytes(),
        0o644,
    )?;

    let updated_material = load_client_identity_material(directory)?;
    Ok(ClientCertificateState {
        client_identity: updated_material.client_identity,
        renew_at: updated_material.renew_at,
        expires_at: updated_material.expires_at,
    })
}

pub fn client_identity_from_certificate_der(
    certificate_der: &[u8],
) -> Result<ClientIdentity, ParseClientIdentityCertificateError> {
    let (remainder, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| ParseClientIdentityCertificateError::ParseCertificate)?;
    if !remainder.is_empty() {
        return Err(ParseClientIdentityCertificateError::ParseCertificate);
    }

    Ok(ClientIdentity::from_subject_public_key_info(
        certificate.tbs_certificate.subject_pki.raw,
    ))
}

fn issue_client_certificate(
    signing_key: &KeyPair,
    now: OffsetDateTime,
) -> Result<String, rcgen::Error> {
    let not_before = now - Duration::minutes(1);
    let mut certificate_params = CertificateParams::new(vec!["runewarp-client".to_owned()])?;
    certificate_params.not_before = not_before;
    certificate_params.not_after = not_before + Duration::days(CLIENT_CERT_LIFETIME_DAYS as i64);
    let certificate = certificate_params.self_signed(signing_key)?;
    Ok(certificate.pem())
}

struct LoadedClientIdentityMaterial {
    signing_key: KeyPair,
    client_identity: ClientIdentity,
    renew_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

fn load_client_identity_material(
    directory: &Path,
) -> Result<LoadedClientIdentityMaterial, ClientIdentityMaterialError> {
    let key_path = directory.join(CLIENT_KEY_FILENAME);
    let key_pem =
        fs::read_to_string(&key_path).map_err(|source| ClientIdentityMaterialError::ReadFile {
            path: key_path.clone(),
            source,
        })?;
    let signing_key = KeyPair::from_pem(&key_pem).map_err(ClientIdentityMaterialError::ParseKey)?;
    let key_identity =
        ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    let identity_path = directory.join(CLIENT_IDENTITY_FILENAME);
    let stored_identity = fs::read_to_string(&identity_path)
        .map_err(|source| ClientIdentityMaterialError::ReadFile {
            path: identity_path.clone(),
            source,
        })?
        .trim()
        .parse::<ClientIdentity>()
        .map_err(|_| ClientIdentityMaterialError::ParseCertificate {
            path: identity_path,
        })?;
    if stored_identity != key_identity {
        return Err(ClientIdentityMaterialError::IdentityMismatch {
            stored: stored_identity,
            derived: key_identity,
        });
    }

    let certificate_path = directory.join(CLIENT_CERT_FILENAME);
    let certificate_pem =
        fs::read(&certificate_path).map_err(|source| ClientIdentityMaterialError::ReadFile {
            path: certificate_path.clone(),
            source,
        })?;
    let certificate_der = certs(&mut Cursor::new(certificate_pem))
        .next()
        .transpose()
        .map_err(|source| ClientIdentityMaterialError::ReadFile {
            path: certificate_path.clone(),
            source,
        })?
        .ok_or_else(|| ClientIdentityMaterialError::ParseCertificate {
            path: certificate_path.clone(),
        })?;
    let certificate_identity = client_identity_from_certificate_der(certificate_der.as_ref())
        .map_err(|_| ClientIdentityMaterialError::ParseCertificate {
            path: certificate_path.clone(),
        })?;
    if stored_identity != certificate_identity {
        return Err(ClientIdentityMaterialError::IdentityMismatch {
            stored: stored_identity,
            derived: certificate_identity,
        });
    }

    let (_, certificate) = parse_x509_certificate(certificate_der.as_ref()).map_err(|_| {
        ClientIdentityMaterialError::ParseCertificate {
            path: certificate_path.clone(),
        }
    })?;
    let renew_at = certificate.validity().not_before.to_datetime()
        + Duration::days(CLIENT_CERT_RENEW_AFTER_DAYS as i64);
    let expires_at = certificate.validity().not_after.to_datetime();

    Ok(LoadedClientIdentityMaterial {
        signing_key,
        client_identity: stored_identity,
        renew_at,
        expires_at,
    })
}

fn replace_file_atomically_with_mode(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), ClientIdentityMaterialError> {
    cert_file_ops::replace_file_atomically_with_mode(path, contents, mode).map_err(|source| {
        ClientIdentityMaterialError::WriteFile {
            path: path.to_path_buf(),
            source,
        }
    })
}

pub fn decide_client_certificate_renewal(
    renew_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> ClientCertificateRenewalDecision {
    if now >= expires_at {
        ClientCertificateRenewalDecision::Expired {
            expired_at: expires_at,
        }
    } else if now >= renew_at {
        ClientCertificateRenewalDecision::Due {
            renew_at,
            expires_at,
        }
    } else {
        ClientCertificateRenewalDecision::NotDue {
            renew_at,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use time::{Duration, OffsetDateTime};

    use super::{
        CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS, ClientCertificateRenewalDecision,
        ClientIdentity, decide_client_certificate_renewal,
    };

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

    #[test]
    fn renewal_decision_is_not_due_before_the_renewal_window() {
        let renew_at = OffsetDateTime::UNIX_EPOCH + Duration::days(60);
        let expires_at = OffsetDateTime::UNIX_EPOCH + Duration::days(90);

        assert_eq!(
            decide_client_certificate_renewal(
                renew_at,
                expires_at,
                OffsetDateTime::UNIX_EPOCH + Duration::days(59),
            ),
            ClientCertificateRenewalDecision::NotDue {
                renew_at,
                expires_at,
            }
        );
    }

    #[test]
    fn renewal_decision_is_due_inside_the_renewal_window() {
        let renew_at = OffsetDateTime::UNIX_EPOCH + Duration::days(60);
        let expires_at = OffsetDateTime::UNIX_EPOCH + Duration::days(90);

        assert_eq!(
            decide_client_certificate_renewal(
                renew_at,
                expires_at,
                OffsetDateTime::UNIX_EPOCH + Duration::days(60),
            ),
            ClientCertificateRenewalDecision::Due {
                renew_at,
                expires_at,
            }
        );
    }

    #[test]
    fn renewal_decision_marks_expired_certificates() {
        let renew_at = OffsetDateTime::UNIX_EPOCH + Duration::days(60);
        let expires_at = OffsetDateTime::UNIX_EPOCH + Duration::days(90);

        assert_eq!(
            decide_client_certificate_renewal(
                renew_at,
                expires_at,
                OffsetDateTime::UNIX_EPOCH + Duration::days(90),
            ),
            ClientCertificateRenewalDecision::Expired {
                expired_at: expires_at
            }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn client_identities_round_trip_through_lowercase_hex(
            bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let encoded = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();

            let parsed = encoded.parse::<ClientIdentity>().unwrap();

            prop_assert_eq!(parsed.to_string(), encoded);
        }
    }
}
