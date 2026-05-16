use std::fmt;
use std::fs;
use std::io::{self, BufReader, Cursor};
use std::path::{Path, PathBuf};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::quic::{QuicConfigError, make_server_quic_config};

#[derive(Debug)]
pub(crate) enum TlsMaterialError {
    ReadFile { path: PathBuf, source: io::Error },
    MissingCertificate { path: PathBuf },
    MissingPrivateKey { path: PathBuf },
    ParsePem { path: PathBuf, source: io::Error },
    InvalidConfiguration(QuicConfigError),
}

impl fmt::Display for TlsMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFile { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::MissingCertificate { path } => {
                write!(formatter, "no certificates found in {}", path.display())
            }
            Self::MissingPrivateKey { path } => {
                write!(formatter, "no private key found in {}", path.display())
            }
            Self::ParsePem { path, source } => {
                write!(
                    formatter,
                    "failed to parse PEM in {}: {source}",
                    path.display()
                )
            }
            Self::InvalidConfiguration(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for TlsMaterialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::ParsePem { source, .. } => Some(source),
            Self::InvalidConfiguration(source) => Some(source),
            Self::MissingCertificate { .. } | Self::MissingPrivateKey { .. } => None,
        }
    }
}

pub(crate) fn load_certificate_chain(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, TlsMaterialError> {
    let bytes = fs::read(path).map_err(|source| TlsMaterialError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(Cursor::new(bytes));
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsMaterialError::ParsePem {
            path: path.to_path_buf(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsMaterialError::MissingCertificate {
            path: path.to_path_buf(),
        });
    }
    Ok(certs)
}

pub(crate) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsMaterialError> {
    let bytes = fs::read(path).map_err(|source| TlsMaterialError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(Cursor::new(bytes));
    let private_key =
        rustls_pemfile::private_key(&mut reader).map_err(|source| TlsMaterialError::ParsePem {
            path: path.to_path_buf(),
            source,
        })?;
    private_key.ok_or_else(|| TlsMaterialError::MissingPrivateKey {
        path: path.to_path_buf(),
    })
}

pub(crate) fn validate_server_tls_material(
    cert_file: &Path,
    key_file: &Path,
) -> Result<(), TlsMaterialError> {
    let cert_chain = load_certificate_chain(cert_file)?;
    let private_key = load_private_key(key_file)?;
    make_server_quic_config(cert_chain, private_key)
        .map_err(TlsMaterialError::InvalidConfiguration)?;
    Ok(())
}
