//! Control TLS material loaded once per Managed-session connection.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;

use crate::tls_material::load_certificate_chain;
use crate::{ControlTrust, IdentityKey, IdentityRole};

/// ALPN token for mandatory HTTP/2. HTTP/1.1 is never offered.
pub(crate) const CONTROL_ALPN_H2: &[u8] = b"h2";

/// Role identity key presented to Control over mTLS.
///
/// The certificate is built in memory from the key on every connection attempt.
#[derive(Clone, Debug)]
pub struct ControlRoleIdentityMaterial {
    pub role: IdentityRole,
    pub key_path: PathBuf,
}

/// Trust and identity inputs for one new Control connection.
#[derive(Clone, Debug)]
pub struct SessionMaterial {
    pub control_hostname: String,
    pub trust: ControlTrust,
    pub identity: ControlRoleIdentityMaterial,
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
    let credentials = IdentityKey::read(&material.identity.key_path)
        .map_err(|error| ControlTlsMaterialError::Identity(error.to_string()))?
        .tls_credentials(material.identity.role)
        .map_err(|error| ControlTlsMaterialError::Identity(error.to_string()))?;

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(credentials.cert_chain, credentials.private_key)
        .map_err(ControlTlsMaterialError::ClientAuth)?;
    client_config.alpn_protocols = vec![CONTROL_ALPN_H2.to_vec()];
    // Never offer or fall back to HTTP/1.1.
    client_config.enable_sni = true;

    Ok(ControlTlsMaterial {
        client_config: Arc::new(client_config),
        server_name: material.control_hostname.clone(),
    })
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

impl ControlRoleIdentityMaterial {
    pub fn client(key_path: PathBuf) -> Self {
        Self {
            role: IdentityRole::Client,
            key_path,
        }
    }

    pub fn server(key_path: PathBuf) -> Self {
        Self {
            role: IdentityRole::Server,
            key_path,
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
