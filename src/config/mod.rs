use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::DeserializeOwned;

pub mod client;
mod preparation;
pub mod server;

use self::preparation::PreparedDirectory;
use self::preparation::client::{
    PreparedClientAcmeConfig, PreparedClientConfig, PreparedClientServiceConfig,
    PreparedClientTlsMode, PreparedClientTrust,
};
use self::preparation::control::PreparedControlTrust;
use self::preparation::server::{
    PreparedServerAcmeConfig, PreparedServerConfig, PreparedServerTunnelConfig,
};
use crate::control_address::ControlAddress;
use crate::server_address::ServerAddress;
use crate::server_identity::{ServerIdentity, read_server_identity};
use crate::tls_material::{
    SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, validate_server_tls_material,
};
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientIdentity,
    PublicHostname, SERVER_CA_FILENAME, SERVER_IDENTITY_CERT_FILENAME, SERVER_IDENTITY_FILENAME,
    SERVER_IDENTITY_KEY_FILENAME, ServerHostname, XdgPathError,
};

pub use self::preparation::material::MaterialDirectoryError;
pub use self::preparation::server::{ServerCertHostnameError, ServerRuntimeArgs};

pub const SERVER_HOSTNAME_ENV_VAR: &str = "RUNEWARP_SERVER_HOSTNAME";

pub use crate::trust::ControlTrust;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlConfig {
    pub address: ControlAddress,
    pub trust: ControlTrust,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerIdentityConfig {
    pub directory: PathBuf,
    pub identity: ServerIdentity,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub hostname: ServerHostname,
    pub log_level: LogLevel,
    pub certificate: ServerCertificateConfig,
    pub public_bind_address: SocketAddr,
    pub tunnel_connection_bind_address: SocketAddr,
    pub readiness_bind_address: Option<SocketAddr>,
    pub graceful_shutdown_duration: std::time::Duration,
    pub tunnels: Vec<ServerTunnelConfig>,
    pub control: Option<ControlConfig>,
    pub identity: Option<ServerIdentityConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTunnelConfig {
    /// Control-owned continuity key in Managed mode; always `None` in static mode.
    pub id: Option<crate::TunnelId>,
    pub public_hostnames: Vec<PublicHostname>,
    pub authorized_client_identities: Vec<ClientIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerCertificateConfig {
    Manual {
        directory: PathBuf,
    },
    Acme {
        email: String,
        state_directory: PathBuf,
        state_directory_was_defaulted: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    pub server_addresses: Vec<ServerAddress>,
    pub server_hostname: ServerHostname,
    pub server_port: u16,
    pub log_level: LogLevel,
    pub server_ca_file: Option<PathBuf>,
    pub identity_directory: PathBuf,
    pub services: Vec<ServiceConfig>,
    pub public_cert_config: Option<ClientPublicCertConfig>,
    pub control: Option<ControlConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientPublicCertConfig {
    Manual {
        directory: PathBuf,
    },
    Acme {
        email: String,
        state_directory: PathBuf,
        state_directory_was_defaulted: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    pub public_hostnames: Option<Vec<PublicHostname>>,
    pub backend_address: String,
    pub tls_mode: ClientTlsMode,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ClientTlsMode {
    #[default]
    Passthrough,
    Terminate,
}

struct ValidatedRequiredPublicHostnames {
    values: Vec<PublicHostname>,
    is_valid: bool,
}

struct ValidatedOptionalPublicHostnames {
    values: Option<Vec<PublicHostname>>,
    valid_hostnames: Vec<PublicHostname>,
    is_valid: bool,
}

struct ValidatedServerTunnel {
    settings: Option<ServerTunnelConfig>,
    public_hostnames: Vec<PublicHostname>,
    authorized_client_identities: Vec<ClientIdentity>,
}

struct ValidatedClientService {
    settings: Option<ServiceConfig>,
    public_hostnames: Vec<PublicHostname>,
    parsed_tls_mode: Option<ClientTlsMode>,
}

struct ValidatedAcmeStateDirectory {
    path: PathBuf,
    was_defaulted: bool,
}

#[derive(Debug)]
pub enum ConfigFileError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        section: &'static str,
        source: Box<toml::de::Error>,
    },
    Validation {
        path: PathBuf,
        section: &'static str,
        messages: Vec<String>,
    },
}

impl fmt::Display for ConfigFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, .. } => {
                write!(formatter, "failed to read {}", path.display())
            }
            Self::Parse { path, section, .. } => write!(
                formatter,
                "failed to parse [{section}] in {}",
                path.display()
            ),
            Self::Validation {
                path,
                section,
                messages,
            } => {
                write!(formatter, "invalid {section} config in {}:", path.display())?;
                for message in messages {
                    write!(formatter, "\n- {message}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source.as_ref()),
            Self::Validation { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum ServerConfigResolutionError {
    XdgPath(XdgPathError),
    ConfigFile(ConfigFileError),
}

impl ServerConfigResolutionError {
    pub fn selected_config_path(&self) -> Option<&Path> {
        match self {
            Self::ConfigFile(ConfigFileError::Read { path, .. })
            | Self::ConfigFile(ConfigFileError::Parse { path, .. })
            | Self::ConfigFile(ConfigFileError::Validation { path, .. }) => Some(path.as_path()),
            Self::XdgPath(_) => None,
        }
    }

    pub fn config_file_error(&self) -> Option<&ConfigFileError> {
        match self {
            Self::ConfigFile(error) => Some(error),
            Self::XdgPath(_) => None,
        }
    }
}

impl fmt::Display for ServerConfigResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XdgPath(error) => write!(formatter, "{error}"),
            Self::ConfigFile(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ServerConfigResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::XdgPath(error) => Some(error),
            Self::ConfigFile(error) => Some(error),
        }
    }
}

pub fn load_server_config(path: &Path) -> Result<ServerConfig, ConfigFileError> {
    let prepared = preparation::server::prepare_server_config_from_path(path)?;
    validate_prepared_server_config(path, prepared)
}

pub fn resolve_server_config_from_cli(
    config: Option<PathBuf>,
    runtime: ServerRuntimeArgs,
) -> Result<ServerConfig, ServerConfigResolutionError> {
    let config_path = preparation::server::select_server_config_path(config)
        .map_err(ServerConfigResolutionError::XdgPath)?;
    let prepared = preparation::server::prepare_server_config_from_cli(&config_path, runtime)
        .map_err(ServerConfigResolutionError::ConfigFile)?;
    validate_prepared_server_config(&config_path, prepared)
        .map_err(ServerConfigResolutionError::ConfigFile)
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig, ConfigFileError> {
    let prepared = preparation::client::prepare_client_config_from_path(path)?;
    validate_prepared_client_config(path, prepared)
}

pub fn resolve_server_cert_material_dir_from_config(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    preparation::server::project_server_cert_material_dir(path)
}

pub fn resolve_server_hostname_from_config(
    path: &Path,
) -> Result<Option<ServerHostname>, ConfigFileError> {
    preparation::server::project_server_hostname(path)
}

pub fn resolve_server_hostname_runtime_override(hostname: Option<String>) -> Option<String> {
    preparation::server::resolve_server_hostname_runtime_override(hostname)
}

pub fn resolve_server_cert_material_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, MaterialDirectoryError> {
    preparation::server::resolve_server_cert_material_dir(config, directory)
}

pub fn resolve_server_cert_hostname(
    config: Option<PathBuf>,
    hostname: Option<String>,
) -> Result<String, ServerCertHostnameError> {
    preparation::server::resolve_server_cert_hostname(config, hostname)
}

pub fn resolve_client_public_cert_material_dir_from_config(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    preparation::client::project_client_public_cert_material_dir(path)
}

/// Returns the deduplicated, normalized list of `public-hostnames` from every
/// `[[client.services]]` entry whose `tls-mode` is `"terminate"`. Returns
/// `None` when no `[client]` section exists in the config file.
pub fn resolve_terminating_hostnames_from_config(
    path: &Path,
) -> Result<Option<Vec<PublicHostname>>, ConfigFileError> {
    preparation::client::project_terminating_hostnames(path)
}

pub fn resolve_client_identity_material_dir_from_config(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    preparation::client::project_client_identity_material_dir(path)
}

pub fn resolve_client_identity_material_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, MaterialDirectoryError> {
    preparation::client::resolve_client_identity_material_dir(config, directory)
}

pub fn resolve_client_public_cert_material_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, MaterialDirectoryError> {
    preparation::client::resolve_client_public_cert_material_dir(config, directory)
}

pub(crate) fn load_optional_selected_section_value(
    path: &Path,
    section: &'static str,
) -> Result<Option<toml::Value>, ConfigFileError> {
    let document = load_config_document(path, section)?;
    Ok(document.get(section).cloned())
}

pub(crate) fn load_log_level_from_path(path: &Path) -> Result<LogLevel, ConfigFileError> {
    let document = load_config_document(path, "config")?;
    document
        .try_into::<RawGlobalConfig>()
        .map(|raw| raw.log_level.unwrap_or_default())
        .map_err(|source| ConfigFileError::Parse {
            path: path.to_path_buf(),
            section: "config",
            source: Box::new(source),
        })
}

fn load_config_document(
    path: &Path,
    section: &'static str,
) -> Result<toml::Value, ConfigFileError> {
    let contents = fs::read_to_string(path).map_err(|source| ConfigFileError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let document =
        toml::from_str::<toml::Value>(&contents).map_err(|source| ConfigFileError::Parse {
            path: path.to_path_buf(),
            section,
            source: Box::new(source),
        })?;
    Ok(document)
}

pub(crate) fn deserialize_selected_section<T>(
    path: &Path,
    section: &'static str,
    section_value: &toml::Value,
) -> Result<T, ConfigFileError>
where
    T: DeserializeOwned,
{
    section_value
        .clone()
        .try_into::<T>()
        .map_err(|source| ConfigFileError::Parse {
            path: path.to_path_buf(),
            section,
            source: Box::new(source),
        })
}

fn validate_prepared_server_config(
    path: &Path,
    prepared: PreparedServerConfig,
) -> Result<ServerConfig, ConfigFileError> {
    let PreparedServerConfig {
        hostname,
        log_level,
        public_bind_address,
        tunnel_bind_address,
        readiness_bind_address,
        graceful_shutdown_duration,
        manual_cert_present,
        acme_present,
        manual_certificate_directory,
        acme,
        tunnels,
        unknown_field_messages,
        control,
        identity_directory,
    } = prepared;
    let mut messages = unknown_field_messages;
    messages.extend(control.unknown_field_messages);

    let managed = control.address.is_some();
    if control.section_present && control.address.is_none() {
        messages.push("control.address is required".to_owned());
    }

    let hostname = match hostname {
        Some(hostname) => {
            validate_server_hostname_field("server.hostname", hostname, &mut messages)
        }
        None => {
            messages.push("server.hostname is required".to_owned());
            None
        }
    };

    if manual_cert_present && acme_present {
        messages.push("[server.acme] and server.cert-dir are mutually exclusive".to_owned());
    }
    let manual = if !acme_present {
        manual_certificate_directory
            .and_then(|directory| directory.into_option(&mut messages))
            .and_then(|directory| {
                validate_prepared_server_manual_cert_settings(
                    directory,
                    hostname.as_ref(),
                    &mut messages,
                )
            })
    } else {
        None
    };
    let acme = if acme_present && !manual_cert_present {
        acme.and_then(|acme| validate_prepared_server_acme_settings(acme, &mut messages))
    } else {
        None
    };
    let certificate = match acme_present {
        false => manual.map(|directory| ServerCertificateConfig::Manual { directory }),
        true => acme.map(|(email, state_directory)| ServerCertificateConfig::Acme {
            email,
            state_directory: state_directory.path,
            state_directory_was_defaulted: state_directory.was_defaulted,
        }),
    };

    let public_bind_address = validate_socket_address_field(
        "server.public-bind-address",
        public_bind_address,
        &mut messages,
    );
    let tunnel_connection_bind_address = validate_socket_address_field(
        "server.tunnel-bind-address",
        tunnel_bind_address,
        &mut messages,
    );
    let readiness_bind_address = readiness_bind_address.and_then(|address| {
        validate_socket_address_field("server.readiness-bind-address", address, &mut messages)
    });
    let graceful_shutdown_duration = validate_duration_field(
        "server.graceful-shutdown-duration",
        graceful_shutdown_duration.as_str(),
        &mut messages,
    );

    let validated_tunnels = if managed {
        if !tunnels.is_empty() {
            messages.push("[[server.tunnels]] may not be configured in managed mode".to_owned());
        }
        Vec::new()
    } else {
        if tunnels.is_empty() {
            messages.push("at least one [[server.tunnels]] entry is required".to_owned());
        }
        let validated = tunnels
            .into_iter()
            .map(|tunnel| validate_prepared_server_tunnel(tunnel, &mut messages))
            .collect::<Vec<_>>();
        validate_unique_client_identities(&validated, &mut messages);
        if let Some(hostname) = hostname.as_ref() {
            validate_unique_server_hostnames(hostname, &validated, &mut messages);
        }
        validated
            .into_iter()
            .filter_map(|tunnel| tunnel.settings)
            .collect::<Vec<_>>()
    };

    let identity = if managed {
        let identity_directory = identity_directory
            .and_then(|directory| directory.into_option(&mut messages))
            .and_then(|directory| {
                validate_existing_directory_path("server.identity-dir", directory, &mut messages)
            });
        if let (Some(identity_directory), Some(cert_directory)) = (
            identity_directory.as_ref(),
            certificate_directory(&certificate),
        ) && paths_refer_to_same_location(identity_directory, &cert_directory)
        {
            messages.push(
                "server.identity-dir must resolve to a different directory than server.cert-dir"
                    .to_owned(),
            );
        }
        identity_directory.and_then(|directory| {
            validate_prepared_server_identity_material(directory, &mut messages)
        })
    } else {
        if identity_directory.is_some() {
            messages.push("server.identity-dir may be set only in managed mode".to_owned());
        }
        None
    };

    let control = if managed {
        let address = control.address.and_then(|address| {
            validate_control_address_field("control.address", address, &mut messages)
        });
        let trust = validate_prepared_control_trust(control.trust, &mut messages);
        match (address, trust) {
            (Some(address), Some(trust)) => Some(ControlConfig { address, trust }),
            _ => None,
        }
    } else {
        None
    };

    if messages.is_empty() {
        Ok(ServerConfig {
            hostname: hostname.expect("validated server.hostname"),
            log_level,
            certificate: certificate.expect("validated server certificate settings"),
            public_bind_address: public_bind_address.expect("validated server.public-bind-address"),
            tunnel_connection_bind_address: tunnel_connection_bind_address
                .expect("validated server.tunnel-bind-address"),
            readiness_bind_address,
            graceful_shutdown_duration: graceful_shutdown_duration
                .expect("validated server.graceful-shutdown-duration"),
            tunnels: validated_tunnels,
            control,
            identity,
        })
    } else {
        Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages,
        })
    }
}

pub(crate) fn validate_prepared_client_config(
    path: &Path,
    prepared: PreparedClientConfig,
) -> Result<ClientConfig, ConfigFileError> {
    let PreparedClientConfig {
        server_address,
        server_addresses,
        log_level,
        trust,
        identity_directory,
        services,
        manual_public_cert_present,
        manual_public_cert_directory,
        acme_present,
        acme,
        unknown_field_messages,
        control,
        ..
    } = prepared;
    let mut messages = unknown_field_messages;
    messages.extend(control.unknown_field_messages);

    let managed = control.address.is_some();
    if control.section_present && control.address.is_none() {
        messages.push("control.address is required".to_owned());
    }

    let mut validated_server_addresses = Vec::new();
    if managed {
        if server_address.is_some() || server_addresses.is_some() {
            messages.push(
                "client.server-address and client.server-addresses may not be configured in managed mode"
                    .to_owned(),
            );
        }
        if let Some(server_address) = server_address {
            let _ = validate_server_address_field(
                "client.server-address",
                server_address,
                &mut messages,
            );
        }
        if let Some(server_addresses) = server_addresses {
            for (index, server_address) in server_addresses.into_iter().enumerate() {
                let field = format!("client.server-addresses[{index}]");
                let _ = validate_server_address_field(&field, server_address, &mut messages);
            }
        }
    } else if server_address.is_some() && server_addresses.is_some() {
        messages.push(
            "client.server-address and client.server-addresses are mutually exclusive".to_owned(),
        );
        if let (Some(server_address), Some(server_addresses)) = (server_address, server_addresses) {
            if let Some(server_address) = validate_server_address_field(
                "client.server-address",
                server_address,
                &mut messages,
            ) {
                validated_server_addresses.push(server_address);
            }
            for (index, server_address) in server_addresses.into_iter().enumerate() {
                let field = format!("client.server-addresses[{index}]");
                if let Some(server_address) =
                    validate_server_address_field(&field, server_address, &mut messages)
                {
                    validated_server_addresses.push(server_address);
                }
            }
        }
    } else {
        match (server_address, server_addresses) {
            (Some(server_address), None) => {
                if let Some(server_address) = validate_server_address_field(
                    "client.server-address",
                    server_address,
                    &mut messages,
                ) {
                    validated_server_addresses.push(server_address);
                }
            }
            (None, Some(server_addresses)) => {
                if server_addresses.is_empty() {
                    messages
                        .push("client.server-addresses must contain at least one entry".to_owned());
                }
                for (index, server_address) in server_addresses.into_iter().enumerate() {
                    let field = format!("client.server-addresses[{index}]");
                    if let Some(server_address) =
                        validate_server_address_field(&field, server_address, &mut messages)
                    {
                        validated_server_addresses.push(server_address);
                    }
                }
            }
            (None, None) => {
                messages.push(
                    "client.server-address or client.server-addresses is required".to_owned(),
                );
            }
            (Some(server_address), Some(server_addresses)) => {
                if let Some(server_address) = validate_server_address_field(
                    "client.server-address",
                    server_address,
                    &mut messages,
                ) {
                    validated_server_addresses.push(server_address);
                }
                for (index, server_address) in server_addresses.into_iter().enumerate() {
                    let field = format!("client.server-addresses[{index}]");
                    if let Some(server_address) =
                        validate_server_address_field(&field, server_address, &mut messages)
                    {
                        validated_server_addresses.push(server_address);
                    }
                }
            }
        }
        validate_unique_server_addresses(&validated_server_addresses, &mut messages);
    }

    let server_ca_file = match trust {
        PreparedClientTrust::System => None,
        PreparedClientTrust::CaFile(server_ca_file) => server_ca_file
            .into_option(&mut messages)
            .and_then(|server_ca_file| {
                validate_existing_file("client.server-ca-file", server_ca_file, &mut messages)
            }),
        PreparedClientTrust::InvalidMode(value) => {
            messages.push(format!(
                "client.server-trust must be one of `system` or `ca-file`, got `{value}`"
            ));
            None
        }
        PreparedClientTrust::UnexpectedServerCaFile => {
            messages.push(
                "client.server-ca-file may be set only when client.server-trust = \"ca-file\""
                    .to_owned(),
            );
            None
        }
    };
    let identity_directory = identity_directory
        .into_option(&mut messages)
        .and_then(|directory| {
            validate_existing_directory_path("client.identity-dir", directory, &mut messages)
        });
    if let Some(identity_directory) = identity_directory.as_deref() {
        let _ = validate_directory_file(
            "client.identity-dir",
            identity_directory,
            CLIENT_CERT_FILENAME,
            &mut messages,
        );
        let _ = validate_directory_file(
            "client.identity-dir",
            identity_directory,
            CLIENT_KEY_FILENAME,
            &mut messages,
        );
        let _ = validate_directory_file(
            "client.identity-dir",
            identity_directory,
            CLIENT_IDENTITY_FILENAME,
            &mut messages,
        );
    }

    if manual_public_cert_present && acme_present {
        messages.push("[client.acme] and client.public-cert-dir are mutually exclusive".to_owned());
    }
    let manual_cert_selected = manual_public_cert_directory.is_some() && !acme_present;
    let manual_cert = if !acme_present {
        manual_public_cert_directory.and_then(|directory| {
            directory.into_option(&mut messages).and_then(|directory| {
                validate_existing_directory_path("client.public-cert-dir", directory, &mut messages)
            })
        })
    } else {
        None
    };
    let acme = if acme_present && !manual_public_cert_present {
        acme.and_then(|acme| validate_prepared_client_acme_settings(acme, &mut messages))
    } else {
        None
    };
    let public_cert_config = match acme_present {
        false => manual_cert.map(|directory| ClientPublicCertConfig::Manual { directory }),
        true => acme.map(|(email, state_directory)| ClientPublicCertConfig::Acme {
            email,
            state_directory: state_directory.path,
            state_directory_was_defaulted: state_directory.was_defaulted,
        }),
    };

    let service_count = services.len();
    let omitted_service_public_hostnames = services
        .iter()
        .filter(|service| service.public_hostnames.is_none())
        .count();
    if service_count == 0 {
        messages.push("at least one [[client.services]] entry is required".to_owned());
    }
    let validated_services = services
        .into_iter()
        .map(|service| validate_prepared_client_service(service, &mut messages))
        .collect::<Vec<_>>();
    validate_client_service_shapes(
        service_count,
        omitted_service_public_hostnames,
        &mut messages,
    );
    validate_unique_client_service_hostnames(&validated_services, &mut messages);

    let has_terminating_service = validated_services
        .iter()
        .any(|s| s.parsed_tls_mode == Some(ClientTlsMode::Terminate));
    if has_terminating_service && public_cert_config.is_none() && !manual_cert_selected {
        messages.push(
            "client.public-cert-dir or [client.acme] is required when any service uses tls-mode = \"terminate\""
                .to_owned(),
        );
    }
    if (manual_public_cert_present || acme_present) && !has_terminating_service {
        messages.push(
            "client.public-cert-dir and [client.acme] require at least one service with tls-mode = \"terminate\""
                .to_owned(),
        );
    }

    let services = validated_services
        .into_iter()
        .filter_map(|service| service.settings)
        .collect::<Vec<_>>();

    let control_config = if managed {
        let address = control.address.and_then(|address| {
            validate_control_address_field("control.address", address, &mut messages)
        });
        let trust = validate_prepared_control_trust(control.trust, &mut messages);
        match (address, trust) {
            (Some(address), Some(trust)) => Some(ControlConfig { address, trust }),
            _ => None,
        }
    } else {
        None
    };

    if messages.is_empty() {
        let (server_hostname, server_port) = match validated_server_addresses.first() {
            Some(first) => (first.hostname().clone(), first.port()),
            None => {
                // Managed mode starts with an empty Server-address assignment. These
                // legacy single-target fields stay unused until addresses are applied.
                (
                    ServerHostname::try_from("unassigned.invalid")
                        .expect("literal hostname is valid by construction"),
                    crate::server_address::DEFAULT_SERVER_PORT,
                )
            }
        };
        Ok(ClientConfig {
            server_addresses: validated_server_addresses,
            server_hostname,
            server_port,
            log_level,
            server_ca_file,
            identity_directory: identity_directory.expect("validated client.identity-dir"),
            services,
            public_cert_config,
            control: control_config,
        })
    } else {
        Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages,
        })
    }
}

fn validate_prepared_client_acme_settings(
    raw: PreparedClientAcmeConfig,
    messages: &mut Vec<String>,
) -> Option<(String, ValidatedAcmeStateDirectory)> {
    let email = raw.email.unwrap_or_else(|| {
        messages.push("client.acme.email is required".to_owned());
        String::new()
    });
    let state_directory = validate_prepared_acme_state_directory(
        "client.acme.state-dir",
        raw.state_directory,
        messages,
    );

    if email.is_empty() || state_directory.is_none() {
        return None;
    }

    Some((email, state_directory.expect("validated state directory")))
}

fn validate_prepared_server_manual_cert_settings(
    directory: PathBuf,
    server_hostname: Option<&ServerHostname>,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    let directory = validate_existing_directory_path("server.cert-dir", directory, messages)?;
    let cert_path = validate_directory_file(
        "server.cert-dir",
        &directory,
        SERVER_CERT_FILENAME,
        messages,
    );
    let key_path =
        validate_directory_file("server.cert-dir", &directory, SERVER_KEY_FILENAME, messages);
    let ca_path =
        validate_directory_file("server.cert-dir", &directory, SERVER_CA_FILENAME, messages);
    if let (Some(cert_path), Some(key_path), Some(ca_path)) = (
        cert_path.as_deref(),
        key_path.as_deref(),
        ca_path.as_deref(),
    ) && let Some(server_hostname) = server_hostname
        && let Err(error) =
            validate_server_tls_material(cert_path, key_path, ca_path, server_hostname.as_str())
    {
        messages.push(format!("server TLS material is invalid: {error}"));
        return None;
    }

    Some(directory)
}

fn validate_prepared_server_acme_settings(
    raw: PreparedServerAcmeConfig,
    messages: &mut Vec<String>,
) -> Option<(String, ValidatedAcmeStateDirectory)> {
    let email = raw.email.unwrap_or_else(|| {
        messages.push("server.acme.email is required".to_owned());
        String::new()
    });
    let state_directory = validate_prepared_acme_state_directory(
        "server.acme.state-dir",
        raw.state_directory,
        messages,
    );

    if email.is_empty() || state_directory.is_none() {
        return None;
    }

    Some((email, state_directory.expect("validated state directory")))
}

fn validate_prepared_acme_state_directory(
    field_name: &str,
    directory: PreparedDirectory,
    messages: &mut Vec<String>,
) -> Option<ValidatedAcmeStateDirectory> {
    match directory {
        PreparedDirectory::Explicit(path) => {
            validate_existing_directory_path(field_name, path, messages).map(|path| {
                ValidatedAcmeStateDirectory {
                    path,
                    was_defaulted: false,
                }
            })
        }
        PreparedDirectory::Defaulted(path) => {
            path.into_option(messages)
                .map(|path| ValidatedAcmeStateDirectory {
                    path,
                    was_defaulted: true,
                })
        }
    }
}

fn validate_existing_file(
    field_name: &str,
    path: PathBuf,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    if !path.is_file() {
        messages.push(format!("{field_name} file not found: {}", path.display()));
        return None;
    }
    Some(path)
}

fn validate_existing_directory_path(
    field_name: &str,
    path: PathBuf,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    if !path.is_dir() {
        messages.push(format!(
            "{field_name} directory not found: {}",
            path.display()
        ));
        return None;
    }
    Some(path)
}

fn validate_directory_file(
    field_name: &str,
    directory: &Path,
    filename: &str,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    let path = directory.join(filename);
    if !path.is_file() {
        messages.push(format!("{field_name} file not found: {}", path.display()));
        return None;
    }
    Some(path)
}

fn validate_prepared_server_tunnel(
    raw: PreparedServerTunnelConfig,
    messages: &mut Vec<String>,
) -> ValidatedServerTunnel {
    let PreparedServerTunnelConfig {
        public_hostnames,
        client_identity,
        client_identities,
    } = raw;
    let public_hostnames = validate_required_public_hostnames(
        "server.tunnels[].public-hostnames",
        public_hostnames,
        messages,
    );

    let authorized_client_identities = validate_server_tunnel_authorized_client_identities(
        client_identity,
        client_identities,
        messages,
    );

    let settings = if public_hostnames.is_valid {
        (!authorized_client_identities.is_empty()).then(|| ServerTunnelConfig {
            id: None,
            public_hostnames: public_hostnames.values.clone(),
            authorized_client_identities: authorized_client_identities.clone(),
        })
    } else {
        None
    };

    ValidatedServerTunnel {
        settings,
        public_hostnames: public_hostnames.values,
        authorized_client_identities,
    }
}

fn validate_server_tunnel_authorized_client_identities(
    client_identity: Option<String>,
    client_identities: Option<Vec<String>>,
    messages: &mut Vec<String>,
) -> Vec<ClientIdentity> {
    if client_identity.is_some() && client_identities.is_some() {
        messages.push(
            "server.tunnels[].client-identity and server.tunnels[].client-identities are mutually exclusive"
                .to_owned(),
        );
        return Vec::new();
    }

    if let Some(client_identities) = client_identities {
        return validate_client_identity_list(
            "server.tunnels[].client-identities",
            client_identities,
            messages,
        );
    }

    match client_identity {
        Some(client_identity) => match client_identity.parse::<ClientIdentity>() {
            Ok(client_identity) => vec![client_identity],
            Err(error) => {
                messages.push(format!(
                    "server.tunnels[].client-identity is invalid: {error}"
                ));
                Vec::new()
            }
        },
        None => {
            messages.push(
                "one of server.tunnels[].client-identity or server.tunnels[].client-identities is required"
                    .to_owned(),
            );
            Vec::new()
        }
    }
}

fn validate_client_identity_list(
    field_name: &str,
    client_identities: Vec<String>,
    messages: &mut Vec<String>,
) -> Vec<ClientIdentity> {
    if client_identities.is_empty() {
        messages.push(format!("{field_name} must not be empty"));
        return Vec::new();
    }

    client_identities
        .into_iter()
        .filter_map(
            |client_identity| match client_identity.parse::<ClientIdentity>() {
                Ok(client_identity) => Some(client_identity),
                Err(error) => {
                    messages.push(format!(
                        "{field_name} contains invalid identity `{client_identity}`: {error}"
                    ));
                    None
                }
            },
        )
        .collect()
}

fn validate_prepared_client_service(
    raw: PreparedClientServiceConfig,
    messages: &mut Vec<String>,
) -> ValidatedClientService {
    let public_hostnames = validate_optional_public_hostnames(
        "client.services[].public-hostnames",
        raw.public_hostnames,
        messages,
    );

    let backend_address = match raw.backend_address {
        Some(backend_address) => {
            if !is_valid_backend_address(&backend_address) {
                messages.push(
                    "client.services[].backend-address must be a TCP address or host:port pair"
                        .to_owned(),
                );
                None
            } else {
                Some(backend_address)
            }
        }
        None => {
            messages.push("client.services[].backend-address is required".to_owned());
            None
        }
    };

    let parsed_tls_mode = match raw.tls_mode {
        PreparedClientTlsMode::Passthrough => Some(ClientTlsMode::Passthrough),
        PreparedClientTlsMode::Terminate => Some(ClientTlsMode::Terminate),
        PreparedClientTlsMode::Invalid(_) => {
            messages.push(
                "client.services[].tls-mode must be \"passthrough\" or \"terminate\"".to_owned(),
            );
            None
        }
    };

    if parsed_tls_mode == Some(ClientTlsMode::Terminate) && public_hostnames.values.is_none() {
        messages.push(
            "client.services[].tls-mode = \"terminate\" requires explicit public-hostnames"
                .to_owned(),
        );
    }

    let settings = if public_hostnames.is_valid && parsed_tls_mode.is_some() {
        backend_address.map(|backend_address| ServiceConfig {
            public_hostnames: public_hostnames.values.clone(),
            backend_address,
            tls_mode: parsed_tls_mode.clone().expect("validated tls mode"),
        })
    } else {
        None
    };

    ValidatedClientService {
        settings,
        public_hostnames: public_hostnames.valid_hostnames,
        parsed_tls_mode,
    }
}

fn validate_control_address_field(
    field_name: &str,
    address: String,
    messages: &mut Vec<String>,
) -> Option<ControlAddress> {
    match ControlAddress::parse(&address) {
        Ok(address) => Some(address),
        Err(error) => {
            messages.push(format!("{field_name} is invalid: {error}"));
            None
        }
    }
}

fn validate_prepared_control_trust(
    trust: PreparedControlTrust,
    messages: &mut Vec<String>,
) -> Option<ControlTrust> {
    match trust {
        PreparedControlTrust::System => Some(ControlTrust::System),
        PreparedControlTrust::CaFile(ca_file) => ca_file
            .into_option(messages)
            .and_then(|ca_file| validate_existing_file("control.ca-file", ca_file, messages))
            .map(ControlTrust::CaFile),
        PreparedControlTrust::InvalidMode(value) => {
            messages.push(format!(
                "control.trust must be one of `system` or `ca-file`, got `{value}`"
            ));
            None
        }
        PreparedControlTrust::UnexpectedCaFile => {
            messages.push(
                "control.ca-file may be set only when control.trust = \"ca-file\"".to_owned(),
            );
            None
        }
    }
}

fn validate_prepared_server_identity_material(
    directory: PathBuf,
    messages: &mut Vec<String>,
) -> Option<ServerIdentityConfig> {
    let _ = validate_directory_file(
        "server.identity-dir",
        &directory,
        SERVER_IDENTITY_CERT_FILENAME,
        messages,
    );
    let _ = validate_directory_file(
        "server.identity-dir",
        &directory,
        SERVER_IDENTITY_KEY_FILENAME,
        messages,
    );
    let _ = validate_directory_file(
        "server.identity-dir",
        &directory,
        SERVER_IDENTITY_FILENAME,
        messages,
    );
    match read_server_identity(&directory) {
        Ok(identity) => Some(ServerIdentityConfig {
            directory,
            identity,
        }),
        Err(error) => {
            messages.push(format!("server identity material is invalid: {error}"));
            None
        }
    }
}

fn certificate_directory(certificate: &Option<ServerCertificateConfig>) -> Option<PathBuf> {
    match certificate {
        Some(ServerCertificateConfig::Manual { directory }) => Some(directory.clone()),
        Some(ServerCertificateConfig::Acme { .. }) | None => None,
    }
}

fn paths_refer_to_same_location(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn validate_server_hostname_field(
    field_name: &str,
    hostname: String,
    messages: &mut Vec<String>,
) -> Option<ServerHostname> {
    match ServerHostname::try_from(hostname.as_str()) {
        Ok(hostname) => Some(hostname),
        Err(error) => {
            messages.push(format!("{field_name} is invalid: {error}"));
            None
        }
    }
}

fn validate_server_address_field(
    field_name: &str,
    server_address: String,
    messages: &mut Vec<String>,
) -> Option<ServerAddress> {
    match ServerAddress::parse(&server_address) {
        Ok(server_address) => Some(server_address),
        Err(error) => {
            messages.push(format!("{field_name} is invalid: {error}"));
            None
        }
    }
}

fn validate_unique_server_addresses(
    server_addresses: &[ServerAddress],
    messages: &mut Vec<String>,
) {
    let mut seen = HashSet::new();
    for server_address in server_addresses {
        let rendered = format!(
            "{}:{}",
            server_address.hostname().as_str(),
            server_address.port()
        );
        if !seen.insert(rendered.clone()) {
            messages.push(format!(
                "client.server-addresses contains duplicate Server address `{rendered}`"
            ));
        }
    }
}

fn validate_socket_address_field(
    field_name: &str,
    socket_address: String,
    messages: &mut Vec<String>,
) -> Option<SocketAddr> {
    match socket_address.parse::<SocketAddr>() {
        Ok(socket_address) => Some(socket_address),
        Err(_) => {
            messages.push(format!(
                "{field_name} is invalid: must be a literal socket address"
            ));
            None
        }
    }
}

fn validate_required_public_hostnames(
    field_name: &str,
    raw_hostnames: Option<Vec<String>>,
    messages: &mut Vec<String>,
) -> ValidatedRequiredPublicHostnames {
    match raw_hostnames {
        Some(hostnames) => validate_public_hostnames(field_name, hostnames, messages),
        None => {
            messages.push(format!("{field_name} is required"));
            ValidatedRequiredPublicHostnames {
                values: Vec::new(),
                is_valid: false,
            }
        }
    }
}

fn validate_optional_public_hostnames(
    field_name: &str,
    raw_hostnames: Option<Vec<String>>,
    messages: &mut Vec<String>,
) -> ValidatedOptionalPublicHostnames {
    match raw_hostnames {
        Some(hostnames) => {
            let validated = validate_public_hostnames(field_name, hostnames, messages);
            ValidatedOptionalPublicHostnames {
                values: validated.is_valid.then(|| validated.values.clone()),
                valid_hostnames: validated.values,
                is_valid: validated.is_valid,
            }
        }
        None => ValidatedOptionalPublicHostnames {
            values: None,
            valid_hostnames: Vec::new(),
            is_valid: true,
        },
    }
}

fn validate_public_hostnames(
    field_name: &str,
    hostnames: Vec<String>,
    messages: &mut Vec<String>,
) -> ValidatedRequiredPublicHostnames {
    if hostnames.is_empty() {
        messages.push(format!("{field_name} must not be empty"));
        return ValidatedRequiredPublicHostnames {
            values: Vec::new(),
            is_valid: false,
        };
    }

    let mut validated = Vec::with_capacity(hostnames.len());
    let hostnames_len = hostnames.len();
    for hostname in hostnames {
        match PublicHostname::try_from(hostname.as_str()) {
            Ok(hostname) => validated.push(hostname),
            Err(error) => messages.push(format!(
                "{field_name} contains invalid hostname `{hostname}`: {error}"
            )),
        }
    }

    ValidatedRequiredPublicHostnames {
        is_valid: validated.len() == hostnames_len,
        values: validated,
    }
}

fn validate_unique_client_identities(
    tunnels: &[ValidatedServerTunnel],
    messages: &mut Vec<String>,
) {
    let mut seen = HashSet::new();
    for tunnel in tunnels {
        for identity in &tunnel.authorized_client_identities {
            let identity = identity.to_string();
            if !seen.insert(identity.clone()) {
                messages.push(format!(
                    "authorized Client identities must be unique across all Server Tunnels: {identity}"
                ));
            }
        }
    }
}

fn validate_unique_server_hostnames(
    server_hostname: &ServerHostname,
    tunnels: &[ValidatedServerTunnel],
    messages: &mut Vec<String>,
) {
    let mut seen = HashSet::new();
    for tunnel in tunnels {
        for hostname in &tunnel.public_hostnames {
            if hostname.as_str() == server_hostname.as_str() {
                messages.push(format!(
                    "server.tunnels[].public-hostnames must not include server.hostname `{server_hostname}`"
                ));
            }
            if !seen.insert(hostname.clone()) {
                messages.push(format!(
                    "server.tunnels[].public-hostnames must be unique after normalization: {hostname}"
                ));
            }
        }
    }
}

fn validate_client_service_shapes(
    service_count: usize,
    omitted_service_public_hostnames: usize,
    messages: &mut Vec<String>,
) {
    if service_count > 1 && omitted_service_public_hostnames > 0 {
        messages.push(
            "client.services[].public-hostnames may be omitted only when there is exactly one service"
                .to_owned(),
        );
    }
}

fn validate_unique_client_service_hostnames(
    services: &[ValidatedClientService],
    messages: &mut Vec<String>,
) {
    let mut seen = HashSet::new();
    for service in services {
        for hostname in &service.public_hostnames {
            if !seen.insert(hostname.clone()) {
                messages.push(format!(
                    "client.services[].public-hostnames must be unique after normalization: {hostname}"
                ));
            }
        }
    }
}

pub(crate) fn is_valid_backend_address(backend_address: &str) -> bool {
    backend_address.parse::<std::net::SocketAddr>().is_ok()
        || backend_address
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
}

fn validate_duration_field(
    field_name: &str,
    value: &str,
    messages: &mut Vec<String>,
) -> Option<std::time::Duration> {
    match parse_duration(value) {
        Ok(duration) => Some(duration),
        Err(error) => {
            messages.push(format!("{field_name} is invalid: {error}"));
            None
        }
    }
}

fn parse_duration(value: &str) -> Result<std::time::Duration, String> {
    let (numeric, unit) = if let Some(stripped) = value.strip_suffix("ms") {
        (stripped, "ms")
    } else if let Some(stripped) = value.strip_suffix('s') {
        (stripped, "s")
    } else if let Some(stripped) = value.strip_suffix('m') {
        (stripped, "m")
    } else if let Some(stripped) = value.strip_suffix('h') {
        (stripped, "h")
    } else {
        return Err(
            "expected a non-negative duration like \"60s\", \"5m\", \"1h\", or \"250ms\""
                .to_string(),
        );
    };

    let quantity = numeric
        .parse::<u64>()
        .map_err(|_| format!("expected a non-negative integer before `{unit}`"))?;
    match unit {
        "ms" => Ok(std::time::Duration::from_millis(quantity)),
        "s" => Ok(std::time::Duration::from_secs(quantity)),
        "m" => Ok(std::time::Duration::from_secs(quantity.saturating_mul(60))),
        "h" => Ok(std::time::Duration::from_secs(
            quantity.saturating_mul(60 * 60),
        )),
        _ => unreachable!("validated duration suffix"),
    }
}

pub(crate) fn collect_server_unknown_field_messages(section_value: &toml::Value) -> Vec<String> {
    let mut messages = Vec::new();
    let Some(server) = section_value.as_table() else {
        return messages;
    };

    push_unknown_table_fields(
        server,
        &[
            "hostname",
            "cert-dir",
            "acme",
            "public-bind-address",
            "tunnel-bind-address",
            "readiness-bind-address",
            "graceful-shutdown-duration",
            "identity-dir",
            "tunnels",
        ],
        &mut messages,
    );

    if let Some(acme) = server.get("acme").and_then(toml::Value::as_table) {
        push_unknown_table_fields(acme, &["email", "state-dir"], &mut messages);
    }

    if let Some(tunnels) = server.get("tunnels").and_then(toml::Value::as_array) {
        for tunnel in tunnels {
            if let Some(tunnel) = tunnel.as_table() {
                push_unknown_table_fields(
                    tunnel,
                    &["public-hostnames", "client-identity", "client-identities"],
                    &mut messages,
                );
            }
        }
    }

    messages
}

pub(crate) fn collect_control_unknown_field_messages(section_value: &toml::Value) -> Vec<String> {
    let mut messages = Vec::new();
    let Some(control) = section_value.as_table() else {
        return messages;
    };

    push_unknown_table_fields(control, &["address", "trust", "ca-file"], &mut messages);

    messages
}

pub fn is_managed_client_config(path: &Path) -> Result<bool, ConfigFileError> {
    preparation::client::is_managed_client_config(path)
}

pub fn is_managed_selected_client_config(
    config: Option<PathBuf>,
) -> Result<bool, crate::config::client::ClientConfigResolutionError> {
    preparation::client::is_managed_selected_client_config(config)
}

pub use preparation::client::SelectedTerminatingHostnames;

pub fn resolve_selected_terminating_hostnames(
    config: Option<PathBuf>,
) -> Result<Option<SelectedTerminatingHostnames>, crate::config::client::ClientConfigResolutionError>
{
    preparation::client::resolve_selected_terminating_hostnames(config)
}

pub(crate) fn collect_client_unknown_field_messages(section_value: &toml::Value) -> Vec<String> {
    let mut messages = Vec::new();
    let Some(client) = section_value.as_table() else {
        return messages;
    };

    push_unknown_table_fields(
        client,
        &[
            "server-address",
            "server-addresses",
            "server-trust",
            "server-ca-file",
            "identity-dir",
            "public-cert-dir",
            "acme",
            "services",
        ],
        &mut messages,
    );

    if let Some(acme) = client.get("acme").and_then(toml::Value::as_table) {
        push_unknown_table_fields(acme, &["email", "state-dir"], &mut messages);
    }

    if let Some(services) = client.get("services").and_then(toml::Value::as_array) {
        for service in services {
            if let Some(service) = service.as_table() {
                push_unknown_table_fields(
                    service,
                    &["public-hostnames", "backend-address", "tls-mode"],
                    &mut messages,
                );
            }
        }
    }

    messages
}

fn push_unknown_table_fields(
    table: &toml::Table,
    known_fields: &[&str],
    messages: &mut Vec<String>,
) {
    for field in table.keys() {
        if !known_fields.contains(&field.as_str()) {
            messages.push(format!("unknown field `{field}`"));
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawControlConfig {
    pub(crate) address: Option<String>,
    pub(crate) trust: Option<String>,
    pub(crate) ca_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawServerConfig {
    pub(crate) hostname: Option<String>,
    pub(crate) cert_dir: Option<PathBuf>,
    pub(crate) identity_dir: Option<PathBuf>,
    pub(crate) acme: Option<RawServerAcmeConfig>,
    pub(crate) public_bind_address: Option<String>,
    pub(crate) tunnel_bind_address: Option<String>,
    pub(crate) readiness_bind_address: Option<String>,
    pub(crate) graceful_shutdown_duration: Option<String>,
    #[serde(default)]
    pub(crate) tunnels: Vec<RawServerTunnelConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawServerAcmeConfig {
    pub(crate) email: Option<String>,
    pub(crate) state_dir: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawServerTunnelConfig {
    pub(crate) public_hostnames: Option<Vec<String>>,
    pub(crate) client_identity: Option<String>,
    pub(crate) client_identities: Option<Vec<String>>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawClientConfig {
    pub(crate) server_address: Option<String>,
    pub(crate) server_addresses: Option<Vec<String>>,
    pub(crate) server_trust: Option<String>,
    pub(crate) server_ca_file: Option<PathBuf>,
    pub(crate) identity_dir: Option<PathBuf>,
    pub(crate) public_cert_dir: Option<PathBuf>,
    pub(crate) acme: Option<RawClientAcmeConfig>,
    #[serde(default)]
    pub(crate) services: Vec<RawClientServiceConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawClientAcmeConfig {
    pub(crate) email: Option<String>,
    pub(crate) state_dir: Option<PathBuf>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawClientServiceConfig {
    pub(crate) public_hostnames: Option<Vec<String>>,
    pub(crate) backend_address: Option<String>,
    pub(crate) tls_mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawGlobalConfig {
    log_level: Option<LogLevel>,
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{ConfigFileError, is_valid_backend_address, parse_duration};

    #[test]
    fn parses_human_duration_strings() {
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn rejects_invalid_duration_strings() {
        assert!(parse_duration("60").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn accepts_host_port_local_backend_pairs() {
        assert!(is_valid_backend_address("localhost:8443"));
        assert!(is_valid_backend_address("127.0.0.1:443"));
        assert!(!is_valid_backend_address("caddy.local"));
    }

    #[test]
    fn config_file_error_display_omits_nested_io_detail() {
        assert_eq!(
            ConfigFileError::Read {
                path: PathBuf::from("/tmp/runewarp/config.toml"),
                source: io::Error::other("no such file or directory"),
            }
            .to_string(),
            "failed to read /tmp/runewarp/config.toml"
        );
    }
}
