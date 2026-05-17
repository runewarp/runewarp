use std::fmt;
use std::fs;
use std::io::{self, BufReader, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier, danger::ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use x509_parser::parse_x509_certificate;

use crate::quic::{QuicConfigError, make_server_quic_config};

pub(crate) const SERVER_CERT_FILENAME: &str = "server.crt";
pub(crate) const SERVER_KEY_FILENAME: &str = "server.key";

#[derive(Debug)]
pub(crate) enum TlsMaterialError {
    ReadFile {
        path: PathBuf,
        source: io::Error,
    },
    MissingCertificate {
        path: PathBuf,
    },
    MissingPrivateKey {
        path: PathBuf,
    },
    ParsePem {
        path: PathBuf,
        source: io::Error,
    },
    ParseX509 {
        path: PathBuf,
    },
    AddRootCertificate {
        path: PathBuf,
        source: rustls::Error,
    },
    BuildServerVerifier(VerifierBuilderError),
    InvalidServerName {
        server_name: String,
    },
    InvalidCertificateAuthority {
        path: PathBuf,
    },
    InvalidServerCertificate {
        server_name: String,
        source: rustls::Error,
    },
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
            Self::ParseX509 { path } => {
                write!(formatter, "failed to parse X.509 DER in {}", path.display())
            }
            Self::AddRootCertificate { path, source } => {
                write!(
                    formatter,
                    "failed to load root certificate from {}: {source}",
                    path.display()
                )
            }
            Self::BuildServerVerifier(source) => {
                write!(
                    formatter,
                    "failed to build the server certificate verifier: {source}"
                )
            }
            Self::InvalidServerName { server_name } => {
                write!(
                    formatter,
                    "server hostname is not a valid DNS name: {server_name}"
                )
            }
            Self::InvalidCertificateAuthority { path } => write!(
                formatter,
                "{} must contain a CA certificate that issued the server certificate",
                path.display()
            ),
            Self::InvalidServerCertificate {
                server_name,
                source,
            } => write!(
                formatter,
                "server certificate is not valid for {server_name}: {source}"
            ),
            Self::InvalidConfiguration(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for TlsMaterialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::ParsePem { source, .. } => Some(source),
            Self::AddRootCertificate { source, .. } => Some(source),
            Self::BuildServerVerifier(source) => Some(source),
            Self::InvalidServerCertificate { source, .. } => Some(source),
            Self::InvalidConfiguration(source) => Some(source),
            Self::MissingCertificate { .. }
            | Self::MissingPrivateKey { .. }
            | Self::ParseX509 { .. }
            | Self::InvalidServerName { .. }
            | Self::InvalidCertificateAuthority { .. } => None,
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
    ca_file: &Path,
    server_hostname: &str,
) -> Result<(), TlsMaterialError> {
    let cert_chain = load_certificate_chain(cert_file)?;
    let private_key = load_private_key(key_file)?;
    make_server_quic_config(cert_chain.clone(), private_key)
        .map_err(TlsMaterialError::InvalidConfiguration)?;
    let ca_certificates = load_certificate_chain(ca_file)?;
    let mut roots = RootCertStore::empty();
    let mut has_certificate_authority = false;
    for ca_certificate in &ca_certificates {
        roots.add(ca_certificate.clone()).map_err(|source| {
            TlsMaterialError::AddRootCertificate {
                path: ca_file.to_path_buf(),
                source,
            }
        })?;
        let (_, parsed_ca) = parse_x509_certificate(ca_certificate.as_ref()).map_err(|_| {
            TlsMaterialError::ParseX509 {
                path: ca_file.to_path_buf(),
            }
        })?;
        let is_certificate_authority = parsed_ca
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.value.ca);
        if is_certificate_authority {
            has_certificate_authority = true;
        }
    }
    if !has_certificate_authority {
        return Err(TlsMaterialError::InvalidCertificateAuthority {
            path: ca_file.to_path_buf(),
        });
    }
    if server_hostname.is_empty() {
        return Ok(());
    }
    let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(TlsMaterialError::BuildServerVerifier)?;
    let server_name = ServerName::try_from(server_hostname.to_owned()).map_err(|_| {
        TlsMaterialError::InvalidServerName {
            server_name: server_hostname.to_owned(),
        }
    })?;
    verifier
        .verify_server_cert(
            &cert_chain[0],
            &cert_chain[1..],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .map_err(|source| TlsMaterialError::InvalidServerCertificate {
            server_name: server_hostname.to_owned(),
            source,
        })?;
    Ok(())
}
