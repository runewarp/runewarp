use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::config_preparation::PreparedDirectory;
use crate::config_preparation::client::{
    PreparedClientAcmeConfig, PreparedClientConfig, PreparedClientServiceConfig,
    PreparedClientTlsMode, PreparedClientTrust,
};
use crate::config_preparation::server::{
    PreparedServerAcmeConfig, PreparedServerConfig, PreparedServerTunnelConfig,
};
use crate::server_address::ServerAddress;
use crate::tls_material::{
    SERVER_CERT_FILENAME, SERVER_KEY_FILENAME, validate_server_tls_material,
};
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientIdentity,
    PublicHostname, SERVER_CA_FILENAME, ServerHostname, XdgPathError,
};

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
    pub tunnels: Vec<ServerTunnelConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTunnelConfig {
    pub public_hostnames: Vec<PublicHostname>,
    pub client_identity: ClientIdentity,
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
    pub server_hostname: ServerHostname,
    pub server_port: u16,
    pub log_level: LogLevel,
    pub server_ca_file: Option<PathBuf>,
    pub identity_directory: PathBuf,
    pub services: Vec<ServiceConfig>,
    pub public_cert_config: Option<ClientPublicCertConfig>,
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
    client_identity: Option<ClientIdentity>,
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
    let prepared = crate::config_preparation::server::prepare_server_config_from_path(path)?;
    validate_prepared_server_config(path, prepared)
}

pub fn resolve_server_config_from_cli(
    config: Option<PathBuf>,
) -> Result<ServerConfig, ServerConfigResolutionError> {
    let config_path = crate::config_preparation::server::select_server_config_path(config)
        .map_err(ServerConfigResolutionError::XdgPath)?;
    load_server_config(&config_path).map_err(ServerConfigResolutionError::ConfigFile)
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig, ConfigFileError> {
    let prepared = crate::config_preparation::client::prepare_client_config_from_path(path)?;
    validate_prepared_client_config(path, prepared)
}

pub fn resolve_server_cert_material_dir_from_config(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    let base_dir = config_dir(path);
    let Some(section_value) = load_optional_selected_section_value(path, "server")? else {
        return Ok(None);
    };
    let unknown_field_messages = collect_server_unknown_field_messages(&section_value);
    if !unknown_field_messages.is_empty() {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages: unknown_field_messages,
        });
    }
    let raw = deserialize_selected_section::<RawServerConfig>(path, "server", &section_value)?;
    Ok(raw.cert_dir.map(|path| resolve_path(base_dir, &path)))
}

pub fn resolve_server_hostname_from_config(
    path: &Path,
) -> Result<Option<ServerHostname>, ConfigFileError> {
    let Some(section_value) = load_optional_selected_section_value(path, "server")? else {
        return Ok(None);
    };
    let unknown_field_messages = collect_server_unknown_field_messages(&section_value);
    if !unknown_field_messages.is_empty() {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages: unknown_field_messages,
        });
    }
    let raw = deserialize_selected_section::<RawServerConfig>(path, "server", &section_value)?;
    let mut messages = Vec::new();
    let hostname = raw.hostname.and_then(|hostname| {
        validate_server_hostname_field("server.hostname", hostname, &mut messages)
    });
    if messages.is_empty() {
        Ok(hostname)
    } else {
        Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages,
        })
    }
}

pub fn resolve_client_public_cert_material_dir_from_config(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    let base_dir = config_dir(path);
    let Some(section_value) = load_optional_selected_section_value(path, "client")? else {
        return Ok(None);
    };
    let unknown_field_messages = collect_client_unknown_field_messages(&section_value);
    if !unknown_field_messages.is_empty() {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages: unknown_field_messages,
        });
    }
    let raw = deserialize_selected_section::<RawClientConfig>(path, "client", &section_value)?;
    Ok(raw.public_cert_dir.map(|p| resolve_path(base_dir, &p)))
}

/// Returns the deduplicated, normalized list of `public-hostnames` from every
/// `[[client.services]]` entry whose `tls-mode` is `"terminate"`. Returns
/// `None` when no `[client]` section exists in the config file.
pub fn resolve_terminating_hostnames_from_config(
    path: &Path,
) -> Result<Option<Vec<PublicHostname>>, ConfigFileError> {
    let Some(section_value) = load_optional_selected_section_value(path, "client")? else {
        return Ok(None);
    };
    let unknown_field_messages = collect_client_unknown_field_messages(&section_value);
    if !unknown_field_messages.is_empty() {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages: unknown_field_messages,
        });
    }
    let raw = deserialize_selected_section::<RawClientConfig>(path, "client", &section_value)?;
    let mut messages = Vec::new();
    let mut hostnames = Vec::new();
    for hostname in raw
        .services
        .into_iter()
        .filter(|service| service.tls_mode.as_deref() == Some("terminate"))
        .flat_map(|service| service.public_hostnames.unwrap_or_default())
    {
        match PublicHostname::try_from(hostname.as_str()) {
            Ok(hostname) => hostnames.push(hostname),
            Err(error) => messages.push(format!(
                "client.services[].public-hostnames contains invalid hostname `{hostname}`: {error}"
            )),
        }
    }
    hostnames.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    hostnames.dedup();
    if messages.is_empty() {
        Ok(Some(hostnames))
    } else {
        Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages,
        })
    }
}

pub fn resolve_client_identity_material_dir_from_config(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    let base_dir = config_dir(path);
    let Some(section_value) = load_optional_selected_section_value(path, "client")? else {
        return Ok(None);
    };
    let unknown_field_messages = collect_client_unknown_field_messages(&section_value);
    if !unknown_field_messages.is_empty() {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages: unknown_field_messages,
        });
    }
    let raw = deserialize_selected_section::<RawClientConfig>(path, "client", &section_value)?;
    Ok(raw.identity_dir.map(|path| resolve_path(base_dir, &path)))
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

fn config_dir(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("."))
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
        manual_cert_present,
        acme_present,
        manual_certificate_directory,
        acme,
        tunnels,
        unknown_field_messages,
    } = prepared;
    let mut messages = unknown_field_messages;

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
    if tunnels.is_empty() {
        messages.push("at least one [[server.tunnels]] entry is required".to_owned());
    }
    let validated_tunnels = tunnels
        .into_iter()
        .map(|tunnel| validate_prepared_server_tunnel(tunnel, &mut messages))
        .collect::<Vec<_>>();
    validate_unique_client_identities(&validated_tunnels, &mut messages);
    if let Some(hostname) = hostname.as_ref() {
        validate_unique_server_hostnames(hostname, &validated_tunnels, &mut messages);
    }
    let tunnels = validated_tunnels
        .into_iter()
        .filter_map(|tunnel| tunnel.settings)
        .collect::<Vec<_>>();

    if messages.is_empty() {
        Ok(ServerConfig {
            hostname: hostname.expect("validated server.hostname"),
            log_level,
            certificate: certificate.expect("validated server certificate settings"),
            public_bind_address: public_bind_address.expect("validated server.public-bind-address"),
            tunnel_connection_bind_address: tunnel_connection_bind_address
                .expect("validated server.tunnel-bind-address"),
            tunnels,
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
        log_level,
        trust,
        identity_directory,
        services,
        manual_public_cert_present,
        manual_public_cert_directory,
        acme_present,
        acme,
        unknown_field_messages,
        ..
    } = prepared;
    let mut messages = unknown_field_messages;

    let server_address = match server_address {
        Some(server_address) => {
            validate_server_address_field("client.server-address", server_address, &mut messages)
        }
        None => {
            messages.push("client.server-address is required".to_owned());
            None
        }
    };

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

    if messages.is_empty() {
        Ok(ClientConfig {
            server_hostname: server_address
                .as_ref()
                .expect("validated client.server-address")
                .hostname()
                .clone(),
            server_port: server_address
                .as_ref()
                .expect("validated client.server-address")
                .port(),
            log_level,
            server_ca_file,
            identity_directory: identity_directory.expect("validated client.identity-dir"),
            services,
            public_cert_config,
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
    let public_hostnames = validate_required_public_hostnames(
        "server.tunnels[].public-hostnames",
        raw.public_hostnames,
        messages,
    );

    let client_identity = match raw.client_identity {
        Some(client_identity) => match client_identity.parse::<ClientIdentity>() {
            Ok(client_identity) => Some(client_identity),
            Err(error) => {
                messages.push(format!(
                    "server.tunnels[].client-identity is invalid: {error}"
                ));
                None
            }
        },
        None => {
            messages.push("server.tunnels[].client-identity is required".to_owned());
            None
        }
    };

    let settings = if public_hostnames.is_valid {
        client_identity
            .clone()
            .map(|client_identity| ServerTunnelConfig {
                public_hostnames: public_hostnames.values.clone(),
                client_identity,
            })
    } else {
        None
    };

    ValidatedServerTunnel {
        settings,
        public_hostnames: public_hostnames.values,
        client_identity,
    }
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
        if let Some(identity) = &tunnel.client_identity {
            let identity = identity.to_string();
            if !seen.insert(identity.clone()) {
                messages.push(format!(
                    "server.tunnels[].client-identity must be unique: {identity}"
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

fn resolve_path(config_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
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
                    &["public-hostnames", "client-identity"],
                    &mut messages,
                );
            }
        }
    }

    messages
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
pub(crate) struct RawServerConfig {
    pub(crate) hostname: Option<String>,
    pub(crate) cert_dir: Option<PathBuf>,
    pub(crate) acme: Option<RawServerAcmeConfig>,
    pub(crate) public_bind_address: Option<String>,
    pub(crate) tunnel_bind_address: Option<String>,
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
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawClientConfig {
    pub(crate) server_address: Option<String>,
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

    use super::{ConfigFileError, is_valid_backend_address, resolve_path};

    #[test]
    fn resolves_relative_paths_against_the_config_directory() {
        assert_eq!(
            resolve_path(
                PathBuf::from("/tmp/runewarp").as_path(),
                PathBuf::from("server.crt").as_path()
            ),
            PathBuf::from("/tmp/runewarp/server.crt")
        );
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
