use std::fmt;
use std::io;
use std::net::SocketAddr;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use tokio::net::lookup_host;

use crate::acme::{ManagedAcmeState, build_acme_state, run_acme_state};
use crate::tls_material::{
    SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, TlsMaterialError, load_certificate_chain,
    load_private_key,
};
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, Client, ClientConnectError, ClientIdentity,
    ClientSettings, QuicConfigError, Server, ServerCertificateSettings, ServerConfig,
    ServerSettings, client::validate_services, make_client_quic_config_with_client_auth,
    make_server_quic_config_with_client_auth, make_server_quic_config_with_client_auth_resolver,
};

pub struct PreparedServer {
    server: Server,
    logs: bool,
    trusted_client_identities: Vec<ClientIdentity>,
    acme_state: Option<ManagedAcmeState>,
}

impl PreparedServer {
    pub async fn bind(
        settings: &ServerSettings,
        public_bind_addr: SocketAddr,
        tunnel_bind_addr: SocketAddr,
    ) -> Result<Self, ServerStartupError> {
        let trusted_client_identities = settings
            .tunnels
            .iter()
            .map(|tunnel| tunnel.client_identity.clone())
            .collect::<Vec<_>>();
        let (quic_server_config, acme_state) = match &settings.certificate {
            ServerCertificateSettings::Manual { directory } => {
                let cert_chain = load_certificate_chain(&directory.join(SERVER_CERT_FILENAME))?;
                let private_key = load_private_key(&directory.join(SERVER_KEY_FILENAME))?;
                let quic_server_config = make_server_quic_config_with_client_auth(
                    cert_chain,
                    private_key,
                    &trusted_client_identities,
                )
                .map_err(ServerStartupError::QuicConfig)?;
                (quic_server_config, None)
            }
            ServerCertificateSettings::Acme {
                email,
                state_directory,
            } => {
                let acme_state = build_acme_state(&settings.hostname, email, state_directory);
                let quic_server_config = make_server_quic_config_with_client_auth_resolver(
                    acme_state.resolver(),
                    &trusted_client_identities,
                )
                .map_err(ServerStartupError::QuicConfig)?;
                (quic_server_config, Some(acme_state))
            }
        };
        let server = Server::bind(ServerConfig {
            public_bind_addr,
            tunnel_bind_addr,
            server_hostname: settings.hostname.clone(),
            configured_tunnels: settings.tunnels.clone(),
            logs: settings.logs,
            public_tls_config: acme_state
                .as_ref()
                .map(ManagedAcmeState::challenge_rustls_config),
            quic_server_config,
        })
        .await
        .map_err(ServerStartupError::Bind)?;

        Ok(Self {
            server,
            logs: settings.logs,
            trusted_client_identities,
            acme_state,
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
        let Self {
            server,
            logs,
            acme_state,
            ..
        } = self;
        if let Some(acme_state) = acme_state {
            tokio::select! {
                server_result = server.run() => server_result,
                acme_result = run_acme_state(acme_state, logs) => match acme_result {
                    Ok(never) => match never {},
                    Err(error) => Err(error),
                },
            }
        } else {
            server.run().await
        }
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
        let mut server_addrs =
            lookup_host((settings.server_hostname.as_str(), settings.server_port))
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
        if settings.services.is_empty() {
            return Err(ClientStartupError::InvalidSettings(
                "client settings must include at least one Service".to_owned(),
            ));
        }
        let services = validate_services(&settings.services)
            .map_err(|error| ClientStartupError::InvalidSettings(error.to_string()))?;
        let loaded_roots = load_root_store(settings.server_ca_file.as_deref())?;
        let cert_chain =
            load_certificate_chain(&settings.identity_directory.join(CLIENT_CERT_FILENAME))
                .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?;
        let private_key = load_private_key(&settings.identity_directory.join(CLIENT_KEY_FILENAME))
            .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?;
        let quic_client_config =
            make_client_quic_config_with_client_auth(loaded_roots.roots, cert_chain, private_key)
                .map_err(ClientStartupError::QuicConfig)?;
        let client = Client::connect_with_services(crate::client::RoutedClientConfig {
            local_bind_addr,
            server_addr,
            server_name: settings.server_hostname.clone(),
            services,
            logs: settings.logs,
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
    InvalidTlsMaterial(String),
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
            Self::InvalidTlsMaterial(message) => write!(formatter, "{message}"),
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
            Self::MissingCertificate { .. }
            | Self::MissingPrivateKey { .. }
            | Self::InvalidTlsMaterial(_) => None,
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
            TlsMaterialError::ParseX509 { .. }
            | TlsMaterialError::AddRootCertificate { .. }
            | TlsMaterialError::BuildServerVerifier(_)
            | TlsMaterialError::InvalidServerName { .. }
            | TlsMaterialError::InvalidCertificateAuthority { .. }
            | TlsMaterialError::InvalidServerCertificate { .. } => {
                Self::InvalidTlsMaterial(error.to_string())
            }
            TlsMaterialError::InvalidConfiguration(source) => Self::QuicConfig(source),
        }
    }
}

#[derive(Debug)]
pub enum ClientStartupError {
    TlsMaterial(ServerStartupError),
    InvalidSettings(String),
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
    let native_root_error_count = if let Some(server_ca_file) = server_ca_file {
        for cert in load_certificate_chain(server_ca_file)
            .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?
        {
            roots
                .add(cert)
                .map_err(ClientStartupError::AddRootCertificate)?;
            loaded_root_count += 1;
        }
        0
    } else {
        for cert in native_roots.certs {
            roots
                .add(cert)
                .map_err(ClientStartupError::AddRootCertificate)?;
            loaded_root_count += 1;
        }
        native_roots.error_count
    };
    if loaded_root_count == 0 {
        return Err(ClientStartupError::NativeRoots {
            errors: native_root_error_count,
        });
    }

    Ok(LoadedRootStore {
        roots,
        native_root_error_count,
        #[cfg(test)]
        loaded_root_count,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::CertificateDer;

    use super::{ClientStartupError, NativeRootsLoad, build_root_store};

    #[test]
    fn configured_server_ca_file_still_loads_without_native_roots() {
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

        assert_eq!(loaded.native_root_error_count, 0);
        assert_eq!(loaded.loaded_root_count, 1);
    }

    #[test]
    fn configured_server_ca_file_replaces_native_roots() {
        let tempdir = tempfile::tempdir().unwrap();
        let native_ca =
            generate_simple_self_signed(vec!["native.example.test".to_owned()]).unwrap();
        let extra_ca = generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
        fs::write(tempdir.path().join("server-ca.pem"), extra_ca.cert.pem()).unwrap();

        let loaded = build_root_store(
            NativeRootsLoad {
                certs: vec![CertificateDer::from(native_ca.cert)],
                error_count: 1,
            },
            Some(tempdir.path().join("server-ca.pem").as_path()),
        )
        .unwrap();

        assert_eq!(loaded.native_root_error_count, 0);
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
