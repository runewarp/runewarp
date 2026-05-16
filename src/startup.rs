use std::fmt;
use std::io;
use std::net::SocketAddr;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use tokio::net::lookup_host;

use crate::tls_material::{TlsMaterialError, load_certificate_chain, load_private_key};
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, Client, ClientConfig, ClientConnectError,
    ClientIdentity, ClientSettings, QuicConfigError, Server, ServerConfig, ServerSettings,
    make_client_quic_config_with_client_auth, make_server_quic_config,
};

pub struct PreparedServer {
    server: Server,
    trusted_client_identities: Vec<ClientIdentity>,
}

impl PreparedServer {
    pub async fn bind(
        settings: &ServerSettings,
        public_bind_addr: SocketAddr,
        tunnel_bind_addr: SocketAddr,
    ) -> Result<Self, ServerStartupError> {
        let cert_chain = load_certificate_chain(&settings.cert_file)?;
        let private_key = load_private_key(&settings.key_file)?;
        let quic_server_config = make_server_quic_config(cert_chain, private_key)
            .map_err(ServerStartupError::QuicConfig)?;
        let server = Server::bind(ServerConfig {
            public_bind_addr,
            tunnel_bind_addr,
            server_hostname: settings.hostname.clone(),
            quic_server_config,
        })
        .await
        .map_err(ServerStartupError::Bind)?;

        Ok(Self {
            server,
            trusted_client_identities: settings
                .tunnels
                .iter()
                .map(|tunnel| tunnel.client_identity.clone())
                .collect(),
        })
    }

    pub fn public_addr(&self) -> io::Result<SocketAddr> {
        self.server.public_addr()
    }

    pub fn tunnel_addr(&self) -> io::Result<SocketAddr> {
        self.server.tunnel_addr()
    }

    pub fn trusted_client_identities(&self) -> &[ClientIdentity] {
        &self.trusted_client_identities
    }

    pub async fn run(self) -> io::Result<()> {
        self.server.run().await
    }
}

pub struct PreparedClient {
    client: Client,
    native_root_error_count: usize,
}

impl PreparedClient {
    pub async fn connect(
        settings: &ClientSettings,
        local_bind_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        let mut server_addrs = lookup_host((settings.server_hostname.as_str(), 443))
            .await
            .map_err(ClientStartupError::Resolve)?;
        let Some(server_addr) = server_addrs.next() else {
            return Err(ClientStartupError::MissingServerAddress {
                server_hostname: settings.server_hostname.clone(),
            });
        };
        Self::connect_to(settings, local_bind_addr, server_addr).await
    }

    pub async fn connect_to(
        settings: &ClientSettings,
        local_bind_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        let [service] = settings.services.as_slice() else {
            return Err(ClientStartupError::InvalidSettings(
                "client settings must include exactly one Catch-all Service",
            ));
        };
        let loaded_roots = load_root_store(settings.server_ca_file.as_deref())?;
        let cert_chain = load_certificate_chain(&settings.identity_directory.join(CLIENT_CERT_FILENAME))
            .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?;
        let private_key = load_private_key(&settings.identity_directory.join(CLIENT_KEY_FILENAME))
            .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?;
        let quic_client_config =
            make_client_quic_config_with_client_auth(loaded_roots.roots, cert_chain, private_key)
                .map_err(ClientStartupError::QuicConfig)?;
        let client = Client::connect(ClientConfig {
            local_bind_addr,
            server_addr,
            server_name: settings.server_hostname.clone(),
            backend_addr: service.backend_addr.clone(),
            quic_client_config,
        })
        .await
        .map_err(ClientStartupError::Connect)?;

        Ok(Self {
            client,
            native_root_error_count: loaded_roots.native_root_error_count,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.client.local_addr()
    }

    pub fn native_root_error_count(&self) -> usize {
        self.native_root_error_count
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        self.client.run().await
    }
}

#[derive(Debug)]
pub enum ServerStartupError {
    ReadFile {
        path: std::path::PathBuf,
        source: io::Error,
    },
    MissingCertificate {
        path: std::path::PathBuf,
    },
    MissingPrivateKey {
        path: std::path::PathBuf,
    },
    ParsePem {
        path: std::path::PathBuf,
        source: io::Error,
    },
    QuicConfig(QuicConfigError),
    Bind(io::Error),
}

impl fmt::Display for ServerStartupError {
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
            Self::QuicConfig(source) => write!(formatter, "{source}"),
            Self::Bind(source) => write!(formatter, "failed to bind server listeners: {source}"),
        }
    }
}

impl std::error::Error for ServerStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFile { source, .. } => Some(source),
            Self::ParsePem { source, .. } => Some(source),
            Self::QuicConfig(source) => Some(source),
            Self::Bind(source) => Some(source),
            Self::MissingCertificate { .. } | Self::MissingPrivateKey { .. } => None,
        }
    }
}

impl From<TlsMaterialError> for ServerStartupError {
    fn from(error: TlsMaterialError) -> Self {
        match error {
            TlsMaterialError::ReadFile { path, source } => Self::ReadFile { path, source },
            TlsMaterialError::MissingCertificate { path } => Self::MissingCertificate { path },
            TlsMaterialError::MissingPrivateKey { path } => Self::MissingPrivateKey { path },
            TlsMaterialError::ParsePem { path, source } => Self::ParsePem { path, source },
            TlsMaterialError::InvalidConfiguration(source) => Self::QuicConfig(source),
        }
    }
}

#[derive(Debug)]
pub enum ClientStartupError {
    TlsMaterial(ServerStartupError),
    InvalidSettings(&'static str),
    NativeRoots { errors: usize },
    AddRootCertificate(rustls::Error),
    QuicConfig(QuicConfigError),
    Resolve(io::Error),
    MissingServerAddress { server_hostname: String },
    Connect(ClientConnectError),
}

impl fmt::Display for ClientStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsMaterial(source) => write!(formatter, "{source}"),
            Self::InvalidSettings(message) => formatter.write_str(message),
            Self::NativeRoots { errors } => write!(
                formatter,
                "failed to load the system trust store: {errors} certificate(s) could not be loaded"
            ),
            Self::AddRootCertificate(source) => write!(
                formatter,
                "failed to add a trusted CA certificate: {source}"
            ),
            Self::QuicConfig(source) => write!(formatter, "{source}"),
            Self::Resolve(source) => {
                write!(formatter, "failed to resolve the Server hostname: {source}")
            }
            Self::MissingServerAddress { server_hostname } => {
                write!(
                    formatter,
                    "the Server hostname did not resolve to any addresses: {server_hostname}"
                )
            }
            Self::Connect(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for ClientStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TlsMaterial(source) => Some(source),
            Self::AddRootCertificate(source) => Some(source),
            Self::QuicConfig(source) => Some(source),
            Self::Resolve(source) => Some(source),
            Self::Connect(source) => Some(source),
            Self::InvalidSettings(_)
            | Self::NativeRoots { .. }
            | Self::MissingServerAddress { .. } => None,
        }
    }
}

#[derive(Debug)]
struct NativeRootsLoad {
    certs: Vec<CertificateDer<'static>>,
    error_count: usize,
}

#[derive(Debug)]
struct LoadedRootStore {
    roots: RootCertStore,
    native_root_error_count: usize,
    #[cfg(test)]
    loaded_root_count: usize,
}

fn load_root_store(
    server_ca_file: Option<&std::path::Path>,
) -> Result<LoadedRootStore, ClientStartupError> {
    let native_certs = rustls_native_certs::load_native_certs();
    build_root_store(
        NativeRootsLoad {
            certs: native_certs.certs,
            error_count: native_certs.errors.len(),
        },
        server_ca_file,
    )
}

fn build_root_store(
    native_roots: NativeRootsLoad,
    server_ca_file: Option<&std::path::Path>,
) -> Result<LoadedRootStore, ClientStartupError> {
    let mut roots = RootCertStore::empty();
    let mut loaded_root_count = 0;

    for cert in native_roots.certs {
        roots
            .add(cert)
            .map_err(ClientStartupError::AddRootCertificate)?;
        loaded_root_count += 1;
    }
    if let Some(server_ca_file) = server_ca_file {
        for cert in load_certificate_chain(server_ca_file)
            .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?
        {
            roots
                .add(cert)
                .map_err(ClientStartupError::AddRootCertificate)?;
            loaded_root_count += 1;
        }
    }
    if loaded_root_count == 0 {
        return Err(ClientStartupError::NativeRoots {
            errors: native_roots.error_count,
        });
    }

    Ok(LoadedRootStore {
        roots,
        native_root_error_count: native_roots.error_count,
        #[cfg(test)]
        loaded_root_count,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rcgen::generate_simple_self_signed;

    use super::{ClientStartupError, NativeRootsLoad, build_root_store};

    #[test]
    fn extra_ca_material_still_loads_when_native_trust_loading_is_partially_degraded() {
        let tempdir = tempfile::tempdir().unwrap();
        let extra_ca = generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
        fs::write(tempdir.path().join("server-ca.pem"), extra_ca.cert.pem()).unwrap();

        let loaded = build_root_store(
            NativeRootsLoad {
                certs: Vec::new(),
                error_count: 2,
            },
            Some(tempdir.path().join("server-ca.pem").as_path()),
        )
        .unwrap();

        assert_eq!(loaded.native_root_error_count, 2);
        assert_eq!(loaded.loaded_root_count, 1);
    }

    #[test]
    fn missing_all_trust_anchors_still_fails() {
        let error = build_root_store(
            NativeRootsLoad {
                certs: Vec::new(),
                error_count: 2,
            },
            None,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ClientStartupError::NativeRoots { errors: 2 }
        ));
    }
}
