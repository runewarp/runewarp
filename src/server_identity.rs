use std::fmt;
use std::fs;
use std::io::{self, Cursor};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rcgen::{KeyPair, PublicKeyData};
use rustls_pemfile::certs;
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

/// On-disk Server identity certificate presented to Control.
pub const SERVER_IDENTITY_CERT_FILENAME: &str = "server.crt";
/// On-disk Server identity private key.
pub const SERVER_IDENTITY_KEY_FILENAME: &str = "server.key";
/// On-disk pinned Server identity fingerprint.
pub const SERVER_IDENTITY_FILENAME: &str = "server-identity.txt";

/// Stable pinned-public-key Server identity used to authenticate to Control.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServerIdentity([u8; 32]);

impl ServerIdentity {
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

impl fmt::Display for ServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ServerIdentity {
    type Err = ParseServerIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(ParseServerIdentityError::WrongLength);
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let pair =
                std::str::from_utf8(chunk).map_err(|_| ParseServerIdentityError::InvalidHex)?;
            if pair
                .chars()
                .any(|character| !character.is_ascii_hexdigit() || character.is_ascii_uppercase())
            {
                return Err(ParseServerIdentityError::InvalidHex);
            }
            bytes[index] =
                u8::from_str_radix(pair, 16).map_err(|_| ParseServerIdentityError::InvalidHex)?;
        }

        Ok(Self(bytes))
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

#[derive(Debug)]
pub enum ServerIdentityMaterialError {
    ReadFile {
        path: PathBuf,
        source: io::Error,
    },
    ParseIdentity {
        path: PathBuf,
    },
    ParseCertificate {
        path: PathBuf,
    },
    ParseKey(rcgen::Error),
    IdentityMismatch {
        stored: ServerIdentity,
        derived: ServerIdentity,
    },
}

impl fmt::Display for ServerIdentityMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, .. } => {
                write!(formatter, "failed to read {}", path.display())
            }
            Self::ParseIdentity { path } => {
                write!(
                    formatter,
                    "failed to parse a server identity fingerprint from {}",
                    path.display()
                )
            }
            Self::ParseCertificate { path } => {
                write!(
                    formatter,
                    "failed to parse a server identity certificate from {}",
                    path.display()
                )
            }
            Self::ParseKey(_) => {
                formatter.write_str("failed to parse the server identity private key")
            }
            Self::IdentityMismatch { stored, derived } => write!(
                formatter,
                "stored server identity {stored} does not match the current key or certificate identity {derived}"
            ),
        }
    }
}

impl std::error::Error for ServerIdentityMaterialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::ParseKey(source) => Some(source),
            Self::ParseIdentity { .. }
            | Self::ParseCertificate { .. }
            | Self::IdentityMismatch { .. } => None,
        }
    }
}

/// Load and validate externally provisioned Server identity material.
pub fn read_server_identity(
    directory: &Path,
) -> Result<ServerIdentity, ServerIdentityMaterialError> {
    load_server_identity_material(directory)
}

fn load_server_identity_material(
    directory: &Path,
) -> Result<ServerIdentity, ServerIdentityMaterialError> {
    let key_path = directory.join(SERVER_IDENTITY_KEY_FILENAME);
    let key_pem =
        fs::read_to_string(&key_path).map_err(|source| ServerIdentityMaterialError::ReadFile {
            path: key_path.clone(),
            source,
        })?;
    let signing_key = KeyPair::from_pem(&key_pem).map_err(ServerIdentityMaterialError::ParseKey)?;
    let key_identity =
        ServerIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

    let identity_path = directory.join(SERVER_IDENTITY_FILENAME);
    let stored_identity = fs::read_to_string(&identity_path)
        .map_err(|source| ServerIdentityMaterialError::ReadFile {
            path: identity_path.clone(),
            source,
        })?
        .trim()
        .parse::<ServerIdentity>()
        .map_err(|_| ServerIdentityMaterialError::ParseIdentity {
            path: identity_path,
        })?;
    if stored_identity != key_identity {
        return Err(ServerIdentityMaterialError::IdentityMismatch {
            stored: stored_identity,
            derived: key_identity,
        });
    }

    let certificate_path = directory.join(SERVER_IDENTITY_CERT_FILENAME);
    let certificate_pem =
        fs::read(&certificate_path).map_err(|source| ServerIdentityMaterialError::ReadFile {
            path: certificate_path.clone(),
            source,
        })?;
    let certificate_der = certs(&mut Cursor::new(certificate_pem))
        .next()
        .transpose()
        .map_err(|source| ServerIdentityMaterialError::ReadFile {
            path: certificate_path.clone(),
            source,
        })?
        .ok_or_else(|| ServerIdentityMaterialError::ParseCertificate {
            path: certificate_path.clone(),
        })?;
    let certificate_identity = server_identity_from_certificate_der(certificate_der.as_ref())
        .map_err(|_| ServerIdentityMaterialError::ParseCertificate {
            path: certificate_path.clone(),
        })?;
    if stored_identity != certificate_identity {
        return Err(ServerIdentityMaterialError::IdentityMismatch {
            stored: stored_identity,
            derived: certificate_identity,
        });
    }

    Ok(stored_identity)
}

fn server_identity_from_certificate_der(
    certificate_der: &[u8],
) -> Result<ServerIdentity, ParseServerIdentityCertificateError> {
    let (remainder, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| ParseServerIdentityCertificateError::ParseCertificate)?;
    if !remainder.is_empty() {
        return Err(ParseServerIdentityCertificateError::ParseCertificate);
    }

    Ok(ServerIdentity::from_subject_public_key_info(
        certificate.tbs_certificate.subject_pki.raw,
    ))
}

#[derive(Debug)]
enum ParseServerIdentityCertificateError {
    ParseCertificate,
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
