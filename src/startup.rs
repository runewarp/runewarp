use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use tokio::net::lookup_host;

use crate::acme::{
    AcmeLifecycle, ManagedAcmeRuntime, build_acme_state, build_client_acme_state, run_acme_state,
};
use crate::client_public_cert::{
    CLIENT_PUBLIC_CERT_FILENAME, CLIENT_PUBLIC_KEY_FILENAME, client_public_cert_leaf_dir,
};
use crate::runtime_log::{self, AcmeEvent, AcmeRole};
use crate::tls_material::{
    SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, TlsMaterialError, load_certificate_chain,
    load_private_key,
};
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_KEY_FILENAME, Client, ClientConfig, ClientConnectError,
    ClientIdentity, ClientPublicCertConfig, ClientTlsMode, QuicConfigError, Server, ServerAddress,
    ServerBindConfig, ServerCertificateConfig, ServerConfig, ServiceConfig,
    client::TerminationTlsConfigs, client::validate_services,
    make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    make_server_quic_config_with_client_auth_resolver, shutdown::GracefulShutdown,
};

pub struct PreparedServer {
    server: Server,
    trusted_client_identities: Vec<ClientIdentity>,
    acme_runtime: Option<ManagedAcmeRuntime>,
}

impl PreparedServer {
    pub async fn bind(
        config: &ServerConfig,
        public_bind_addr: SocketAddr,
        tunnel_connection_bind_addr: SocketAddr,
    ) -> Result<Self, ServerStartupError> {
        prepare_default_server_acme_state_dir(config)?;
        let trusted_client_identities = config
            .tunnels
            .iter()
            .flat_map(|tunnel| tunnel.authorized_client_identities.iter().cloned())
            .collect::<Vec<_>>();
        let (quic_server_config, acme_runtime) = match &config.certificate {
            ServerCertificateConfig::Manual { directory } => {
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
            ServerCertificateConfig::Acme {
                email,
                state_directory,
                ..
            } => {
                if should_warn_server_acme_non_standard_public_port(config, public_bind_addr) {
                    runtime_log::acme(
                        AcmeRole::Server {
                            server_hostname: config.hostname.as_str(),
                        },
                        AcmeEvent::NonStandardPublicBind {
                            bind_address: public_bind_addr,
                        },
                    );
                }
                let acme_state = build_acme_state(config.hostname.as_str(), email, state_directory);
                let acme_lifecycle =
                    AcmeLifecycle::server(config.hostname.as_str(), state_directory).await;
                let quic_server_config = make_server_quic_config_with_client_auth_resolver(
                    acme_state.resolver(),
                    &trusted_client_identities,
                )
                .map_err(ServerStartupError::QuicConfig)?;
                (
                    quic_server_config,
                    Some(ManagedAcmeRuntime {
                        state: acme_state,
                        lifecycle: acme_lifecycle,
                    }),
                )
            }
        };
        let server = Server::bind(ServerBindConfig {
            public_bind_addr,
            tunnel_connection_bind_addr,
            server_hostname: config.hostname.clone(),
            configured_tunnels: config.tunnels.clone(),
            public_tls_config: acme_runtime
                .as_ref()
                .map(|acme| acme.state.challenge_rustls_config()),
            quic_server_config,
        })
        .await
        .map_err(ServerStartupError::Bind)?;

        Ok(Self {
            server,
            trusted_client_identities,
            acme_runtime,
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
            acme_runtime,
            ..
        } = self;
        if let Some(acme_runtime) = acme_runtime {
            tokio::select! {
                server_result = server.run() => server_result,
                acme_result = run_acme_state(acme_runtime.state, acme_runtime.lifecycle) => match acme_result {
                    Ok(never) => match never {},
                    Err(error) => Err(error),
                },
            }
        } else {
            server.run().await
        }
    }

    pub async fn run_until_shutdown<Shutdown>(self, shutdown_signal: Shutdown) -> io::Result<()>
    where
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let shutdown = GracefulShutdown::new(std::time::Duration::from_millis(100));
        let shutdown_trigger = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal.await;
            shutdown_trigger.begin();
        });
        self.run_with_shutdown(&shutdown).await
    }

    async fn run_with_shutdown(self, shutdown: &GracefulShutdown) -> io::Result<()> {
        let Self {
            server,
            acme_runtime,
            ..
        } = self;
        if let Some(acme_runtime) = acme_runtime {
            tokio::select! {
                server_result = server.run_with_shutdown(shutdown) => server_result,
                acme_result = run_acme_state(acme_runtime.state, acme_runtime.lifecycle) => match acme_result {
                    Ok(never) => match never {},
                    Err(error) => Err(error),
                },
            }
        } else {
            server.run_with_shutdown(shutdown).await
        }
    }
}

pub struct PreparedClient {
    client: Client,
    native_root_error_count: usize,
    acme_runtimes: Vec<ManagedAcmeRuntime>,
}

type LoadedTerminationTls = (TerminationTlsConfigs, Vec<ManagedAcmeRuntime>);

impl PreparedClient {
    pub async fn connect(
        config: &ClientConfig,
        local_bind_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        let server_address = config
            .server_addresses
            .first()
            .expect("validated client config includes at least one Server address");
        let mut server_addrs =
            lookup_host((server_address.hostname().as_str(), server_address.port()))
                .await
                .map_err(ClientStartupError::Resolve)?;
        let Some(server_addr) = server_addrs.next() else {
            return Err(ClientStartupError::MissingServerAddress {
                server_hostname: server_address.hostname().to_string(),
            });
        };
        Self::connect_to_server_address(config, local_bind_addr, server_address, server_addr).await
    }

    pub async fn connect_to(
        config: &ClientConfig,
        local_bind_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        let server_address = config
            .server_addresses
            .first()
            .expect("validated client config includes at least one Server address");
        Self::connect_to_server_address(config, local_bind_addr, server_address, server_addr).await
    }

    pub async fn connect_to_server_address(
        config: &ClientConfig,
        local_bind_addr: SocketAddr,
        server_address: &ServerAddress,
        server_addr: SocketAddr,
    ) -> Result<Self, ClientStartupError> {
        if config.services.is_empty() {
            return Err(ClientStartupError::InvalidSettings(
                "client config must include at least one Service".to_owned(),
            ));
        }
        let services = validate_services(&config.services)
            .map_err(|error| ClientStartupError::InvalidSettings(error.to_string()))?;
        prepare_default_client_acme_state_dir(config)?;

        let (termination_tls_configs, acme_runtimes) =
            load_termination_tls_configs(config)
                .await
                .map_err(ClientStartupError::InvalidSettings)?;

        let loaded_roots = load_root_store(config.server_ca_file.as_deref())?;
        let cert_chain =
            load_certificate_chain(&config.identity_directory.join(CLIENT_CERT_FILENAME))
                .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?;
        let private_key = load_private_key(&config.identity_directory.join(CLIENT_KEY_FILENAME))
            .map_err(|error| ClientStartupError::TlsMaterial(error.into()))?;
        let quic_client_config =
            make_client_quic_config_with_client_auth(loaded_roots.roots, cert_chain, private_key)
                .map_err(ClientStartupError::QuicConfig)?;
        let client = Client::connect_with_services(crate::client::RoutedClientConnectConfig {
            local_bind_addr,
            server_addr,
            server_name: server_address.hostname().to_string(),
            services,
            quic_client_config,
            termination_tls_configs,
        })
        .await
        .map_err(ClientStartupError::Connect)?;

        Ok(Self {
            client,
            native_root_error_count: loaded_roots.native_root_error_count,
            acme_runtimes,
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
            client,
            acme_runtimes,
            ..
        } = self;
        for acme_runtime in acme_runtimes {
            tokio::spawn(async move {
                let _ = run_acme_state(acme_runtime.state, acme_runtime.lifecycle).await;
            });
        }
        client.run().await
    }

    pub async fn run_until_shutdown<Shutdown>(
        self,
        shutdown_signal: Shutdown,
    ) -> Result<(), quinn::ConnectionError>
    where
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let shutdown = GracefulShutdown::new(std::time::Duration::from_millis(100));
        let shutdown_trigger = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal.await;
            shutdown_trigger.begin();
        });
        self.run_with_shutdown(&shutdown).await
    }

    async fn run_with_shutdown(
        self,
        shutdown: &GracefulShutdown,
    ) -> Result<(), quinn::ConnectionError> {
        let Self {
            client,
            acme_runtimes,
            ..
        } = self;
        for acme_runtime in acme_runtimes {
            tokio::spawn(async move {
                let _ = run_acme_state(acme_runtime.state, acme_runtime.lifecycle).await;
            });
        }
        client.run_with_shutdown(shutdown).await
    }
}

fn should_warn_server_acme_non_standard_public_port(
    settings: &ServerConfig,
    public_bind_addr: SocketAddr,
) -> bool {
    matches!(settings.certificate, ServerCertificateConfig::Acme { .. })
        && public_bind_addr.port() != 443
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
            Self::ReadFile { path, .. } => {
                write!(formatter, "failed to read {}", path.display())
            }
            Self::MissingCertificate { path } => {
                write!(formatter, "no certificates found in {}", path.display())
            }
            Self::MissingPrivateKey { path } => {
                write!(formatter, "no private key found in {}", path.display())
            }
            Self::ParsePem { path, .. } => {
                write!(formatter, "failed to parse PEM in {}", path.display())
            }
            Self::InvalidTlsMaterial(message) => write!(formatter, "{message}"),
            Self::QuicConfig(source) => write!(formatter, "{source}"),
            Self::Bind(source) => write!(formatter, "{source}"),
            Self::CreateDirectory {
                field_name, path, ..
            } => write!(
                formatter,
                "failed to create {field_name} directory {}",
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
            Self::AddRootCertificate(_) => {
                formatter.write_str("failed to add a trusted CA certificate")
            }
            Self::QuicConfig(source) => write!(formatter, "{source}"),
            Self::Resolve(_) => formatter.write_str("failed to resolve the Server hostname"),
            Self::MissingServerAddress { server_hostname } => {
                write!(
                    formatter,
                    "the Server hostname did not resolve to any addresses: {server_hostname}"
                )
            }
            Self::Connect(source) => write!(formatter, "{source}"),
            Self::CreateDirectory {
                field_name, path, ..
            } => write!(
                formatter,
                "failed to create {field_name} directory {}",
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
    settings: &ServerConfig,
) -> Result<(), ServerStartupError> {
    let ServerCertificateConfig::Acme {
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
    settings: &ClientConfig,
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
    if maybe_emit_client_trust_store_warning(native_root_error_count) {
        crate::runtime_log::client_trust_store_warning(native_root_error_count);
    }

    Ok(LoadedRootStore {
        roots,
        native_root_error_count,
        #[cfg(test)]
        loaded_root_count,
    })
}

fn maybe_emit_client_trust_store_warning(errors: usize) -> bool {
    static CLIENT_TRUST_STORE_WARNING_EMITTED: AtomicBool = AtomicBool::new(false);
    should_emit_client_trust_store_warning(errors, &CLIENT_TRUST_STORE_WARNING_EMITTED)
}

fn should_emit_client_trust_store_warning(errors: usize, emitted: &AtomicBool) -> bool {
    errors > 0 && !emitted.swap(true, Ordering::AcqRel)
}

/// Returns the set of explicit public hostnames for all terminating services.
/// Used to determine which hostnames should be managed by ACME.
pub(crate) fn acme_terminating_hostnames(services: &[ServiceConfig]) -> Vec<String> {
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
                hostnames.push(hostname.to_string());
            }
        }
    }
    hostnames
}

/// Loads and validates TLS server configs for every terminating hostname across all services.
/// Returns a map from normalized hostname to the rustls::ServerConfig for that hostname,
/// plus an optional ACME state that must be driven to keep certificates current.
async fn load_termination_tls_configs(
    settings: &ClientConfig,
) -> Result<LoadedTerminationTls, String> {
    match &settings.public_cert_config {
        None => Ok((TerminationTlsConfigs::empty(), Vec::new())),
        Some(ClientPublicCertConfig::Manual { directory }) => {
            let configs = load_manual_termination_tls_configs(settings, directory)?;
            Ok((
                TerminationTlsConfigs::new(configs, HashMap::new()),
                Vec::new(),
            ))
        }
        Some(ClientPublicCertConfig::Acme {
            email,
            state_directory,
            ..
        }) => build_acme_termination_configs(settings, email, state_directory).await,
    }
}

fn load_manual_termination_tls_configs(
    settings: &ClientConfig,
    directory: &std::path::Path,
) -> Result<HashMap<String, Arc<rustls::ServerConfig>>, String> {
    let mut configs = HashMap::new();
    for service in &settings.services {
        if service.tls_mode != ClientTlsMode::Terminate {
            continue;
        }
        let Some(hostnames) = &service.public_hostnames else {
            continue;
        };
        for hostname in hostnames {
            if configs.contains_key(hostname.as_str()) {
                continue;
            }
            let leaf_dir = client_public_cert_leaf_dir(directory, hostname.as_str());
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
            configs.insert(hostname.to_string(), Arc::new(tls_config));
        }
    }
    Ok(configs)
}

/// Builds per-hostname TLS configs backed by independently managed ACME states.
/// The shared state directory still allows the Let's Encrypt account cache to be reused,
/// while each terminating hostname keeps its own certificate cache entry and lifecycle logs.
async fn build_acme_termination_configs(
    settings: &ClientConfig,
    email: &str,
    state_directory: &std::path::Path,
) -> Result<LoadedTerminationTls, String> {
    let hostnames = acme_terminating_hostnames(&settings.services);
    if hostnames.is_empty() {
        // Settings validation should prevent this, but guard defensively.
        return Err(
            "[client.acme] requires at least one service with tls-mode = \"terminate\" \
             and explicit public-hostnames"
                .to_owned(),
        );
    }

    let mut configs = HashMap::new();
    let mut challenge_configs = HashMap::new();
    let mut acme_runtimes = Vec::new();
    for hostname in hostnames {
        let hostname_set = vec![hostname.clone()];
        let acme_state = build_client_acme_state(&hostname_set, email, state_directory);
        let tls_config: Arc<rustls::ServerConfig> = acme_state.default_rustls_config();
        let challenge_tls_config: Arc<rustls::ServerConfig> = acme_state.challenge_rustls_config();
        let acme_lifecycle = AcmeLifecycle::client(&hostname, state_directory).await;
        configs.insert(hostname.clone(), tls_config);
        challenge_configs.insert(hostname.clone(), challenge_tls_config);
        acme_runtimes.push(ManagedAcmeRuntime {
            state: acme_state,
            lifecycle: acme_lifecycle,
        });
    }
    Ok((
        TerminationTlsConfigs::new(configs, challenge_configs),
        acme_runtimes,
    ))
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, generate_simple_self_signed};
    use rustls::pki_types::CertificateDer;
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;

    use super::{
        ClientStartupError, NativeRootsLoad, PreparedServer, ServerStartupError,
        acme_terminating_hostnames, build_root_store,
    };
    use crate::tls_material::{SERVER_CERT_FILENAME, SERVER_KEY_FILENAME};
    use crate::{
        ClientConfig, ClientIdentity, ClientPublicCertConfig, ClientTlsMode, LogLevel,
        PublicHostname, ServerAddress, ServerCertificateConfig, ServerConfig, ServerHostname,
        ServerTunnelConfig, ServiceConfig,
    };

    fn public_hostname(hostname: &str) -> PublicHostname {
        PublicHostname::try_from(hostname).unwrap()
    }

    fn server_hostname(hostname: &str) -> ServerHostname {
        ServerHostname::try_from(hostname).unwrap()
    }

    fn server_address(value: &str) -> ServerAddress {
        ServerAddress::parse(value).unwrap()
    }

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
    fn client_trust_store_warning_only_emits_once_per_process_session() {
        let warning_emitted = AtomicBool::new(false);

        assert!(super::should_emit_client_trust_store_warning(
            2,
            &warning_emitted
        ));
        assert!(!super::should_emit_client_trust_store_warning(
            2,
            &warning_emitted
        ));
        assert!(!super::should_emit_client_trust_store_warning(
            0,
            &warning_emitted
        ));
    }

    #[test]
    fn startup_error_display_includes_bind_address_and_os_detail() {
        assert_eq!(
            ClientStartupError::Resolve(io::Error::other("lookup failed")).to_string(),
            "failed to resolve the Server hostname"
        );
        assert_eq!(
            ServerStartupError::Bind(io::Error::other(
                "failed to bind server.public-bind-address 127.0.0.1:443: address already in use",
            ))
            .to_string(),
            "failed to bind server.public-bind-address 127.0.0.1:443: address already in use"
        );
        assert_eq!(
            ClientStartupError::CreateDirectory {
                field_name: "client.acme.state-dir",
                path: PathBuf::from("/tmp/runewarp/client-acme"),
                source: io::Error::other("permission denied"),
            }
            .to_string(),
            "failed to create client.acme.state-dir directory /tmp/runewarp/client-acme"
        );
    }

    #[test]
    fn acme_terminating_hostnames_only_includes_terminate_mode_services() {
        let services = vec![
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("api.example.test")]),
                backend_address: "localhost:8080".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
        ];

        let hostnames = acme_terminating_hostnames(&services);

        assert_eq!(hostnames, vec!["app.example.test"]);
    }

    #[test]
    fn acme_terminating_hostnames_skips_catch_all_service() {
        let services = vec![ServiceConfig {
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
            ServiceConfig {
                public_hostnames: Some(vec![
                    public_hostname("app.example.test"),
                    public_hostname("api.example.test"),
                ]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
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
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
                backend_address: "localhost:80".to_owned(),
                tls_mode: ClientTlsMode::Passthrough,
            },
            ServiceConfig {
                public_hostnames: Some(vec![public_hostname("api.example.test")]),
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
        let settings = ServerConfig {
            hostname: server_hostname("tunnel.example.test"),
            log_level: LogLevel::Info,
            certificate: ServerCertificateConfig::Acme {
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
    fn non_standard_server_acme_public_port_warning_only_applies_to_server_acme() {
        let acme_settings = ServerConfig {
            hostname: server_hostname("tunnel.example.test"),
            log_level: LogLevel::Info,
            certificate: ServerCertificateConfig::Acme {
                email: "admin@example.test".to_owned(),
                state_directory: PathBuf::from("/tmp/server-acme"),
                state_directory_was_defaulted: false,
            },
            public_bind_address: "127.0.0.1:443".parse().unwrap(),
            tunnel_connection_bind_address: "127.0.0.1:443".parse().unwrap(),
            tunnels: Vec::new(),
        };
        let manual_settings = ServerConfig {
            certificate: ServerCertificateConfig::Manual {
                directory: PathBuf::from("/tmp/server-cert"),
            },
            ..acme_settings.clone()
        };

        assert!(super::should_warn_server_acme_non_standard_public_port(
            &acme_settings,
            "127.0.0.1:8443".parse().unwrap()
        ));
        assert!(!super::should_warn_server_acme_non_standard_public_port(
            &acme_settings,
            "127.0.0.1:443".parse().unwrap()
        ));
        assert!(!super::should_warn_server_acme_non_standard_public_port(
            &manual_settings,
            "127.0.0.1:8443".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn client_acme_builds_one_runtime_per_terminating_hostname() {
        let tempdir = tempfile::tempdir().unwrap();
        let settings = ClientConfig {
            server_addresses: vec![server_address("tunnel.example.test")],
            server_hostname: server_hostname("tunnel.example.test"),
            server_port: 443,
            log_level: LogLevel::Info,
            server_ca_file: None,
            identity_directory: tempdir.path().join("client-identity"),
            services: vec![ServiceConfig {
                public_hostnames: Some(vec![
                    public_hostname("app.example.test"),
                    public_hostname("api.example.test"),
                ]),
                backend_address: "127.0.0.1:8080".to_owned(),
                tls_mode: ClientTlsMode::Terminate,
            }],
            public_cert_config: Some(ClientPublicCertConfig::Acme {
                email: "admin@example.test".to_owned(),
                state_directory: tempdir.path().join("acme-state"),
                state_directory_was_defaulted: false,
            }),
        };

        let (configs, acme_runtimes) = super::load_termination_tls_configs(&settings)
            .await
            .expect("ACME termination configs should build");

        assert!(configs.default_server_config("app.example.test").is_some());
        assert!(configs.default_server_config("api.example.test").is_some());
        assert!(
            configs
                .acme_challenge_server_config("app.example.test")
                .is_some()
        );
        assert!(
            configs
                .acme_challenge_server_config("api.example.test")
                .is_some()
        );
        assert_eq!(acme_runtimes.len(), 2);
    }

    #[test]
    fn defaulted_client_acme_state_dir_is_created_during_startup()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let state_directory = tempdir.path().join("client/acme");
        let settings = ClientConfig {
            server_addresses: vec![server_address("tunnel.example.test")],
            server_hostname: server_hostname("tunnel.example.test"),
            server_port: 443,
            log_level: LogLevel::Info,
            server_ca_file: None,
            identity_directory: tempdir.path().join("client-identity"),
            services: vec![ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
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
        let settings = ServerConfig {
            hostname: server_hostname("tunnel.example.test"),
            log_level: LogLevel::Info,
            certificate: ServerCertificateConfig::Acme {
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
        let settings = ClientConfig {
            server_addresses: vec![server_address("tunnel.example.test")],
            server_hostname: server_hostname("tunnel.example.test"),
            server_port: 443,
            log_level: LogLevel::Info,
            server_ca_file: None,
            identity_directory: tempdir.path().join("client-identity"),
            services: vec![ServiceConfig {
                public_hostnames: Some(vec![public_hostname("app.example.test")]),
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

    #[tokio::test]
    async fn server_startup_reports_public_bind_address_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        write_manual_server_certificate(tempdir.path())?;
        let occupied_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let public_bind_address = occupied_listener.local_addr()?;

        let error = match PreparedServer::bind(
            &server_settings(tempdir.path()),
            public_bind_address,
            "127.0.0.1:0".parse()?,
        )
        .await
        {
            Ok(_) => panic!("expected public listener bind failure"),
            Err(error) => error,
        };

        assert!(matches!(
            &error,
            ServerStartupError::Bind(source)
                if source.to_string().starts_with(&format!(
                    "failed to bind server.public-bind-address {public_bind_address}:"
                ))
        ));
        let message = error.to_string();
        assert!(
            message.starts_with(&format!(
                "failed to bind server.public-bind-address {public_bind_address}:"
            )),
            "{message}"
        );
        assert!(
            message.contains("Address already in use")
                || message.contains("address already in use"),
            "{message}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn server_startup_reports_tunnel_bind_address_failures()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        write_manual_server_certificate(tempdir.path())?;
        let occupied_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let tunnel_bind_address = occupied_socket.local_addr()?;

        let error = match PreparedServer::bind(
            &server_settings(tempdir.path()),
            "127.0.0.1:0".parse()?,
            tunnel_bind_address,
        )
        .await
        {
            Ok(_) => panic!("expected tunnel listener bind failure"),
            Err(error) => error,
        };

        assert!(matches!(
            &error,
            ServerStartupError::Bind(source)
                if source.to_string().starts_with(&format!(
                    "failed to bind server.tunnel-bind-address {tunnel_bind_address}:"
                ))
        ));
        let message = error.to_string();
        assert!(
            message.starts_with(&format!(
                "failed to bind server.tunnel-bind-address {tunnel_bind_address}:"
            )),
            "{message}"
        );
        assert!(
            message.contains("Address already in use")
                || message.contains("address already in use"),
            "{message}"
        );
        Ok(())
    }

    fn server_settings(certificate_directory: &Path) -> ServerConfig {
        ServerConfig {
            hostname: server_hostname("tunnel.example.test"),
            log_level: LogLevel::Info,
            certificate: ServerCertificateConfig::Manual {
                directory: certificate_directory.to_path_buf(),
            },
            public_bind_address: "127.0.0.1:0".parse().unwrap(),
            tunnel_connection_bind_address: "127.0.0.1:0".parse().unwrap(),
            tunnels: vec![ServerTunnelConfig {
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![
                    ClientIdentity::from_str(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    )
                    .unwrap(),
                ],
            }],
        }
    }

    fn write_manual_server_certificate(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let signing_key = KeyPair::generate()?;
        let certificate = CertificateParams::new(vec!["tunnel.example.test".to_owned()])?
            .self_signed(&signing_key)?;
        fs::write(directory.join(SERVER_CERT_FILENAME), certificate.pem())?;
        fs::write(
            directory.join(SERVER_KEY_FILENAME),
            signing_key.serialize_pem(),
        )?;
        Ok(())
    }
}
