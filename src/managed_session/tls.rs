//! Control TLS material loaded once per Managed-session connection.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::tls_material::{load_certificate_chain, load_private_key};
use crate::{CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, ControlTrust};

/// ALPN token for mandatory HTTP/2. HTTP/1.1 is never offered.
pub(crate) const CONTROL_ALPN_H2: &[u8] = b"h2";

/// Role identity presented to Control over mTLS.
#[derive(Clone, Debug)]
pub struct ControlClientIdentityMaterial {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Trust and identity inputs for one new Control connection.
#[derive(Clone, Debug)]
pub struct SessionMaterial {
    pub control_hostname: String,
    pub trust: ControlTrust,
    pub identity: ControlClientIdentityMaterial,
}

/// Loaded rustls client config for one Control connection attempt.
pub(crate) struct ControlTlsMaterial {
    pub client_config: Arc<ClientConfig>,
    pub server_name: String,
}

#[derive(Debug)]
pub enum ControlTlsMaterialError {
    Trust(TrustLoadError),
    Identity(String),
    ClientAuth(rustls::Error),
}

impl fmt::Display for ControlTlsMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trust(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::ClientAuth(error) => write!(formatter, "control client auth config: {error}"),
        }
    }
}

impl std::error::Error for ControlTlsMaterialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Trust(error) => Some(error),
            Self::ClientAuth(error) => Some(error),
            Self::Identity(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum TrustLoadError {
    NativeRoots { errors: usize },
    AddRoot(rustls::Error),
    CaFile(String),
}

impl fmt::Display for TrustLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeRoots { errors } => write!(
                formatter,
                "failed to load system trust store for Control ({errors} native cert errors)"
            ),
            Self::AddRoot(error) => write!(formatter, "invalid Control trust root: {error}"),
            Self::CaFile(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for TrustLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddRoot(error) => Some(error),
            Self::CaFile(_) | Self::NativeRoots { .. } => None,
        }
    }
}

/// Load Control trust roots and role identity for a new connection.
///
/// Material is read from disk on every call so post-start replacements are
/// picked up on reconnect. Failures are returned to the caller for in-process
/// retry rather than process exit.
pub(crate) fn load_control_tls_material(
    material: &SessionMaterial,
) -> Result<ControlTlsMaterial, ControlTlsMaterialError> {
    let roots = load_control_root_store(&material.trust).map_err(ControlTlsMaterialError::Trust)?;
    let (cert_chain, private_key) = load_identity_files(&material.identity)
        .map_err(|error| ControlTlsMaterialError::Identity(error.to_string()))?;

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, private_key)
        .map_err(ControlTlsMaterialError::ClientAuth)?;
    client_config.alpn_protocols = vec![CONTROL_ALPN_H2.to_vec()];
    // Never offer or fall back to HTTP/1.1.
    client_config.enable_sni = true;

    Ok(ControlTlsMaterial {
        client_config: Arc::new(client_config),
        server_name: material.control_hostname.clone(),
    })
}

fn load_identity_files(
    identity: &ControlClientIdentityMaterial,
) -> Result<
    (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    crate::tls_material::TlsMaterialError,
> {
    Ok((
        load_certificate_chain(&identity.cert_path)?,
        load_private_key(&identity.key_path)?,
    ))
}

fn load_control_root_store(trust: &ControlTrust) -> Result<RootCertStore, TrustLoadError> {
    let mut roots = RootCertStore::empty();
    match trust {
        ControlTrust::System => {
            let native = rustls_native_certs::load_native_certs();
            let error_count = native.errors.len();
            let mut loaded = 0;
            for cert in native.certs {
                roots.add(cert).map_err(TrustLoadError::AddRoot)?;
                loaded += 1;
            }
            if loaded == 0 {
                return Err(TrustLoadError::NativeRoots {
                    errors: error_count,
                });
            }
        }
        ControlTrust::CaFile(path) => {
            let certs = load_certificate_chain(path)
                .map_err(|error| TrustLoadError::CaFile(error.to_string()))?;
            if certs.is_empty() {
                return Err(TrustLoadError::CaFile(format!(
                    "control CA file {} contained no certificates",
                    path.display()
                )));
            }
            for cert in certs {
                roots.add(cert).map_err(TrustLoadError::AddRoot)?;
            }
        }
    }
    Ok(roots)
}

impl ControlClientIdentityMaterial {
    pub fn from_client_identity_dir(directory: &Path) -> Self {
        Self {
            cert_path: directory.join(CLIENT_CERT_FILENAME),
            key_path: directory.join(CLIENT_KEY_FILENAME),
        }
    }

    pub fn from_server_identity_dir(directory: &Path) -> Self {
        Self {
            cert_path: directory.join(crate::SERVER_IDENTITY_CERT_FILENAME),
            key_path: directory.join(crate::SERVER_IDENTITY_KEY_FILENAME),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CONTROL_ALPN_H2;

    #[test]
    fn control_alpn_is_http2_only() {
        assert_eq!(CONTROL_ALPN_H2, b"h2");
    }
}
