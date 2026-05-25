use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use tokio::net::lookup_host;

use crate::acme::{ManagedAcmeState, build_acme_state, build_client_acme_state, run_acme_state};
use crate::client_public_cert::{
    CLIENT_PUBLIC_CERT_FILENAME, CLIENT_PUBLIC_KEY_FILENAME, client_public_cert_leaf_dir,
};
use crate::tls_material::{
    SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, TlsMaterialError, load_certificate_chain,
    load_private_key,
};
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, Client, ClientConnectError, ClientIdentity,
    ClientPublicCertConfig, ClientServiceSettings, ClientSettings, ClientTlsMode, QuicConfigError,
    Server, ServerCertificateSettings, ServerConfig, ServerSettings, client::validate_services,
    make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    make_server_quic_config_with_client_auth_resolver,
};

pub struct PreparedServer {
    server: Server,
    trusted_client_identities: Vec<ClientIdentity>,
    acme_state: Option<ManagedAcmeState>,
}

impl PreparedServer {
    pub async fn bind(
        settings: &ServerSettings,
        public_bind_addr: SocketAddr,
        tunnel_connection_bind_addr: SocketAddr,
    ) -> Result<Self, ServerStartupError> {
        prepare_default_server_acme_state_dir(settings)?;
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
                ..
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
            tunnel_connection_bind_addr,
            server_hostname: settings.hostname.clone(),
            configured_tunnels: settings.tunnels.clone(),
            public_tls_config: acme_state
                .as_ref()
                .map(ManagedAcmeState::challenge_rustls_config),
            quic_server_config,
        })
        .await
        .map_err(ServerStartupError::Bind)?;

        Ok(Self {
            server,
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
            server, acme_state, ..
        } = self;
        if let Some(acme_state) = acme_state {
            tokio::select! {
                server_result = server.run() => server_result,
                acme_result = run_acme_state(acme_state, "server") => match acme_result {
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
    acme_state: Option<ManagedAcmeState>,
}

type TerminationTlsConfigs = HashMap<String, Arc<rustls::ServerConfig>>;
type LoadedTerminationTls = (TerminationTlsConfigs, Option<ManagedAcmeState>);

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
        prepare_default_client_acme_state_dir(settings)?;

        let (hostname_tls_configs, acme_state) =
            load_termination_tls_configs(settings).map_err(ClientStartupError::InvalidSettings)?;

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
            quic_client_config,
            hostname_tls_configs,
        })
        .await
        .map_err(ClientStartupError::Connect)?;

        Ok(Self {
            client,
            native_root_error_count: loaded_roots.native_root_error_count,
            acme_state,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.client.local_addr()
    }

    pub fn native_root_error_count(&self) -> usize {
        self.native_root_error_count
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        let Self {
            client, acme_state, ..
        } = self;
        if let Some(acme_state) = acme_state {
            tokio::spawn(run_acme_state(acme_state, "client"));
        }
        client.run().await
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
    CreateDirectory {
        field_name: &'static str,
        path: PathBuf,
        source: io::Error,
    },
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
            Self::CreateDirectory {
                field_name,
                path,
                source,
            } => write!(
                formatter,
                "failed to create {field_name} directory {}: {source}",
                path.display()
            ),
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
            Self::CreateDirectory { source, .. } => Some(source),
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
    NativeRoots {
        errors: usize,
    },
    AddRootCertificate(rustls::Error),
    QuicConfig(QuicConfigError),
    Resolve(io::Error),
    MissingServerAddress {
        server_hostname: String,
    },
    Connect(ClientConnectError),
    CreateDirectory {
        field_name: &'static str,
        path: PathBuf,
        source: io::Error,
    },
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
            Self::CreateDirectory {
                field_name,
                path,
                source,
            } => write!(
                formatter,
                "failed to create {field_name} directory {}: {source}",
                path.display()
            ),
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
            Self::CreateDirectory { source, .. } => Some(source),
            Self::InvalidSettings(_)
            | Self::NativeRoots { .. }
            | Self::MissingServerAddress { .. } => None,
        }
    }
}

fn prepare_default_server_acme_state_dir(
    settings: &ServerSettings,
) -> Result<(), ServerStartupError> {
    let ServerCertificateSettings::Acme {
        state_directory,
        state_directory_was_defaulted: true,
        ..
    } = &settings.certificate
    else {
        return Ok(());
    };

    std::fs::create_dir_all(state_directory).map_err(|source| ServerStartupError::CreateDirectory {
        field_name: "server.acme.state-dir",
        path: state_directory.clone(),
        source,
    })
}

fn prepare_default_client_acme_state_dir(
    settings: &ClientSettings,
) -> Result<(), ClientStartupError> {
    let Some(ClientPublicCertConfig::Acme {
        state_directory,
        state_directory_was_defaulted: true,
        ..
    }) = &settings.public_cert_config
    else {
        return Ok(());
    };

    std::fs::create_dir_all(state_directory).map_err(|source| ClientStartupError::CreateDirectory {
        field_name: "client.acme.state-dir",
        path: state_directory.clone(),
        source,
    })
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
    if native_root_error_count > 0 {
        crate::runtime_log::client_trust_store_warning(native_root_error_count);
    }

    Ok(LoadedRootStore {
        roots,
        native_root_error_count,
        #[cfg(test)]
        loaded_root_count,
    })
}

/// Returns the set of explicit public hostnames for all terminating services.
/// Used to determine which hostnames should be managed by ACME.
pub(crate) fn acme_terminating_hostnames(services: &[ClientServiceSettings]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut hostnames = Vec::new();
    for service in services {
        if service.tls_mode != ClientTlsMode::Terminate {
            continue;
        }
        let Some(hs) = &service.public_hostnames else {
            continue;
        };
        for hostname in hs {
            if seen.insert(hostname.clone()) {
                hostnames.push(hostname.clone());
            }
        }
    }
    hostnames
}

/// Loads and validates TLS server configs for every terminating hostname across all services.
/// Returns a map from normalized hostname to the rustls::ServerConfig for that hostname,
/// plus an optional ACME state that must be driven to keep certificates current.
fn load_termination_tls_configs(settings: &ClientSettings) -> Result<LoadedTerminationTls, String> {
    match &settings.public_cert_config {
        None => Ok((HashMap::new(), None)),
        Some(ClientPublicCertConfig::Manual { directory }) => {
            let configs = load_manual_termination_tls_configs(settings, directory)?;
            Ok((configs, None))
        }
        Some(ClientPublicCertConfig::Acme {
            email,
            state_directory,
            ..
        }) => {
            let (configs, acme_state) =
                build_acme_termination_configs(settings, email, state_directory)?;
            Ok((configs, Some(acme_state)))
        }
    }
}

fn load_manual_termination_tls_configs(
    settings: &ClientSettings,
    directory: &std::path::Path,
) -> Result<TerminationTlsConfigs, String> {
    let mut configs = HashMap::new();
    for service in &settings.services {
        if service.tls_mode != ClientTlsMode::Terminate {
            continue;
        }
        let Some(hostnames) = &service.public_hostnames else {
            continue;
        };
        for hostname in hostnames {
            if configs.contains_key(hostname) {
                continue;
            }
            let leaf_dir = client_public_cert_leaf_dir(directory, hostname);
            let cert_chain = load_certificate_chain(&leaf_dir.join(CLIENT_PUBLIC_CERT_FILENAME))
                .map_err(|_| {
                    format!(
                        "missing certificate for terminating hostname {hostname}: \
                         run `runewarp client public-cert init --hostname {hostname}`"
                    )
                })?;
            let private_key = load_private_key(&leaf_dir.join(CLIENT_PUBLIC_KEY_FILENAME))
                .map_err(|_| {
                    format!(
                        "missing private key for terminating hostname {hostname}: \
                         run `runewarp client public-cert init --hostname {hostname}`"
                    )
                })?;
            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| {
                    format!("invalid TLS material for terminating hostname {hostname}: {e}")
                })?;
            configs.insert(hostname.clone(), Arc::new(tls_config));
        }
    }
    Ok(configs)
}

/// Builds per-hostname TLS configs backed by a shared ACME state.
/// All terminating hostnames share one ACME account and one resolver; the resolver
/// handles both regular TLS connections (once a cert is acquired) and TLS-ALPN-01
/// challenge connections (while acquisition is in progress). Hostnames without a ready
/// certificate fail closed at the TLS handshake layer.
fn build_acme_termination_configs(
    settings: &ClientSettings,
    email: &str,
    state_directory: &std::path::Path,
) -> Result<(TerminationTlsConfigs, ManagedAcmeState), String> {
    let hostnames = acme_terminating_hostnames(&settings.services);
    if hostnames.is_empty() {
        // Settings validation should prevent this, but guard defensively.
        return Err(
            "[client.acme] requires at least one service with tls-mode = \"terminate\" \
             and explicit public-hostnames"
                .to_owned(),
        );
    }

    let acme_state = build_client_acme_state(&hostnames, email, state_directory);
    // The resolver handles all managed hostnames: it presents the challenge cert when
    // the ACME validator connects with acme-tls/1, and the domain cert for normal traffic.
    // Connections that arrive before the cert is ready fail at TLS handshake (fail closed).
    let tls_config: Arc<rustls::ServerConfig> = acme_state.challenge_rustls_config();

    let mut configs = HashMap::new();
    for hostname in hostnames {
        configs.insert(hostname, tls_config.clone());
    }
    Ok((configs, acme_state))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::CertificateDer;

    use super::{
        ClientStartupError, NativeRootsLoad, ServerStartupError, acme_terminating_hostnames,
        build_root_store,
    };
    use crate::{
        ClientPublicCertConfig, ClientServiceSettings, ClientSettings, ClientTlsMode, LogLevel,
        ServerCertificateSettings, ServerSettings,
    };

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

    #[test]
    fn acme_terminating_hostnames_only_includes_terminate_mode_services() {
        let services = vec![
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["api.example.test".to_owned()]),
                backend_address: "localhost:8080".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
        ];

        let hostnames = acme_terminating_hostnames(&services);

        assert_eq!(hostnames, vec!["app.example.test"]);
    }

    #[test]
    fn acme_terminating_hostnames_skips_catch_all_service() {
        let services = vec![ClientServiceSettings {
            public_hostnames: None, // catch-all has no explicit hostnames
            backend_address: "localhost:80".to_owned(),
            tls_mode: ClientTlsMode::Terminate,
        }];

        let hostnames = acme_terminating_hostnames(&services);

        assert!(
            hostnames.is_empty(),
            "Catch-all Services must not contribute Client ACME hostnames"
        );
    }

    #[test]
    fn acme_terminating_hostnames_deduplicates_across_services() {
        let services = vec![
            ClientServiceSettings {
                public_hostnames: Some(vec![
                    "app.example.test".to_owned(),
                    "api.example.test".to_owned(),
                ]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "localhost:8080".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            },
        ];

        let hostnames = acme_terminating_hostnames(&services);

        let mut sorted = hostnames.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["api.example.test", "app.example.test"]);
        assert_eq!(hostnames.len(), 2, "each hostname must appear only once");
    }

    #[test]
    fn acme_terminating_hostnames_empty_when_no_terminate_services() {
        let services = vec![
            ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
            ClientServiceSettings {
                public_hostnames: Some(vec!["api.example.test".to_owned()]),
                backend_address: "localhost:8080".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
        ];

        let hostnames = acme_terminating_hostnames(&services);

        assert!(hostnames.is_empty());
    }

    #[test]
    fn defaulted_server_acme_state_dir_is_created_during_startup()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let state_directory = tempdir.path().join("server/acme");
        let settings = ServerSettings {
            hostname: "tunnel.example.test".to_owned(),
            log_level: LogLevel::Info,
            certificate: ServerCertificateSettings::Acme {
                email: "admin@example.test".to_owned(),
                state_directory: state_directory.clone(),
                state_directory_was_defaulted: true,
            },
            public_bind_address: "127.0.0.1:443".parse()?,
            tunnel_connection_bind_address: "127.0.0.1:443".parse()?,
            tunnels: Vec::new(),
        };

        super::prepare_default_server_acme_state_dir(&settings)?;

        assert!(state_directory.is_dir());
        Ok(())
    }

    #[test]
    fn defaulted_client_acme_state_dir_is_created_during_startup()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let state_directory = tempdir.path().join("client/acme");
        let settings = ClientSettings {
            server_hostname: "tunnel.example.test".to_owned(),
            server_port: 443,
            log_level: LogLevel::Info,
            server_ca_file: None,
            identity_directory: tempdir.path().join("client-identity"),
            reconnect_interval: Duration::from_secs(5),
            services: vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:443".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            }],
            public_cert_config: Some(ClientPublicCertConfig::Acme {
                email: "admin@example.test".to_owned(),
                state_directory: state_directory.clone(),
                state_directory_was_defaulted: true,
            }),
        };

        super::prepare_default_client_acme_state_dir(&settings)?;

        assert!(state_directory.is_dir());
        Ok(())
    }

    #[test]
    fn startup_surfaces_defaulted_server_acme_state_dir_creation_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let blocked_parent = tempdir.path().join("blocked");
        fs::write(&blocked_parent, "not a directory")?;
        let state_directory = blocked_parent.join("acme");
        let settings = ServerSettings {
            hostname: "tunnel.example.test".to_owned(),
            log_level: LogLevel::Info,
            certificate: ServerCertificateSettings::Acme {
                email: "admin@example.test".to_owned(),
                state_directory: state_directory.clone(),
                state_directory_was_defaulted: true,
            },
            public_bind_address: "127.0.0.1:443".parse()?,
            tunnel_connection_bind_address: "127.0.0.1:443".parse()?,
            tunnels: Vec::new(),
        };

        let error = match super::prepare_default_server_acme_state_dir(&settings) {
            Ok(()) => panic!("expected startup preparation to fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ServerStartupError::CreateDirectory {
                field_name: "server.acme.state-dir",
                path,
                ..
            } if path == state_directory
        ));
        Ok(())
    }

    #[test]
    fn startup_surfaces_defaulted_client_acme_state_dir_creation_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let blocked_parent = tempdir.path().join("blocked");
        fs::write(&blocked_parent, "not a directory")?;
        let state_directory = blocked_parent.join("acme");
        let settings = ClientSettings {
            server_hostname: "tunnel.example.test".to_owned(),
            server_port: 443,
            log_level: LogLevel::Info,
            server_ca_file: None,
            identity_directory: tempdir.path().join("client-identity"),
            reconnect_interval: Duration::from_secs(5),
            services: vec![ClientServiceSettings {
                public_hostnames: Some(vec!["app.example.test".to_owned()]),
                backend_address: "127.0.0.1:443".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            }],
            public_cert_config: Some(ClientPublicCertConfig::Acme {
                email: "admin@example.test".to_owned(),
                state_directory: state_directory.clone(),
                state_directory_was_defaulted: true,
            }),
        };

        let error = match super::prepare_default_client_acme_state_dir(&settings) {
            Ok(()) => panic!("expected startup preparation to fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ClientStartupError::CreateDirectory {
                field_name: "client.acme.state-dir",
                path,
                ..
            } if path == state_directory
        ));
        Ok(())
    }
}
