use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::tls_material::validate_server_tls_material;
use crate::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientIdentity,
    hostname::normalize_public_hostname,
};

pub const DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerSettings {
    pub hostname: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub tunnels: Vec<ServerTunnelSettings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTunnelSettings {
    pub client_identity: ClientIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSettings {
    pub server_hostname: String,
    pub server_ca_file: Option<PathBuf>,
    pub identity_directory: PathBuf,
    pub reconnect_interval: Duration,
    pub services: Vec<ClientServiceSettings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientServiceSettings {
    pub backend_addr: String,
}

#[derive(Debug)]
pub enum SettingsError {
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

impl fmt::Display for SettingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(formatter, "failed to read {}: {source}", path.display())
            }
            Self::Parse {
                path,
                section,
                source,
            } => write!(
                formatter,
                "failed to parse [{section}] in {}: {source}",
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

impl std::error::Error for SettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source.as_ref()),
            Self::Validation { .. } => None,
        }
    }
}

pub fn load_server_settings(path: &Path) -> Result<ServerSettings, SettingsError> {
    let raw = load_selected_section::<RawServerConfig>(path, "server")?;
    validate_server_settings(path, raw)
}

pub fn load_client_settings(path: &Path) -> Result<ClientSettings, SettingsError> {
    let raw = load_selected_section::<RawClientConfig>(path, "client")?;
    validate_client_settings(path, raw)
}

fn load_selected_section<T>(path: &Path, section: &'static str) -> Result<T, SettingsError>
where
    T: DeserializeOwned,
{
    let contents = fs::read_to_string(path).map_err(|source| SettingsError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let document =
        toml::from_str::<toml::Value>(&contents).map_err(|source| SettingsError::Parse {
            path: path.to_path_buf(),
            section,
            source: Box::new(source),
        })?;
    let Some(section_value) = document.get(section).cloned() else {
        return Err(SettingsError::Validation {
            path: path.to_path_buf(),
            section,
            messages: vec![format!("missing [{section}] section")],
        });
    };
    section_value
        .try_into::<T>()
        .map_err(|source| SettingsError::Parse {
            path: path.to_path_buf(),
            section,
            source: Box::new(source),
        })
}

fn validate_server_settings(
    path: &Path,
    raw: RawServerConfig,
) -> Result<ServerSettings, SettingsError> {
    let mut messages = Vec::new();
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));

    let hostname = raw
        .hostname
        .map(|hostname| normalize_public_hostname(&hostname))
        .unwrap_or_else(|| {
            messages.push("server.hostname is required".to_owned());
            String::new()
        });

    if raw.acme.is_some() {
        messages.push("server.acme is not supported in Catch-all mode yet".to_owned());
    }

    let cert_file =
        validate_required_path("server.cert-file", raw.cert_file, config_dir, &mut messages);
    let key_file =
        validate_required_path("server.key-file", raw.key_file, config_dir, &mut messages);
    if let (Some(cert_file), Some(key_file)) = (cert_file.as_deref(), key_file.as_deref())
        && let Err(error) = validate_server_tls_material(cert_file, key_file)
    {
        messages.push(format!("server TLS material is invalid: {error}"));
    }

    let tunnel_count = raw.tunnels.len();
    let tunnels = raw
        .tunnels
        .into_iter()
        .filter_map(|tunnel| validate_server_tunnel(tunnel, &mut messages))
        .collect();
    if tunnel_count != 1 {
        messages.push("phase-2 server mode requires exactly one Catch-all Tunnel".to_owned());
    }

    if messages.is_empty() {
        Ok(ServerSettings {
            hostname,
            cert_file: cert_file.expect("validated server.cert-file"),
            key_file: key_file.expect("validated server.key-file"),
            tunnels,
        })
    } else {
        Err(SettingsError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages,
        })
    }
}

fn validate_client_settings(
    path: &Path,
    raw: RawClientConfig,
) -> Result<ClientSettings, SettingsError> {
    let mut messages = Vec::new();
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));

    let server_hostname = raw
        .server_hostname
        .map(|hostname| normalize_public_hostname(&hostname))
        .unwrap_or_else(|| {
            messages.push("client.server-hostname is required".to_owned());
            String::new()
        });

    let server_ca_file = match raw.server_ca_file {
        Some(server_ca_file) => validate_optional_path(
            "client.server-ca-file",
            server_ca_file,
            config_dir,
            &mut messages,
        ),
        None => None,
    };
    let identity_directory = validate_required_directory(
        "client.identity-directory",
        raw.identity_directory,
        config_dir,
        &mut messages,
    );
    if let Some(identity_directory) = identity_directory.as_deref() {
        validate_directory_file(
            "client.identity-directory",
            identity_directory,
            CLIENT_CERT_FILENAME,
            &mut messages,
        );
        validate_directory_file(
            "client.identity-directory",
            identity_directory,
            CLIENT_KEY_FILENAME,
            &mut messages,
        );
        validate_directory_file(
            "client.identity-directory",
            identity_directory,
            CLIENT_IDENTITY_FILENAME,
            &mut messages,
        );
    }

    let reconnect_interval_secs = raw
        .reconnect_interval
        .unwrap_or(DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS);
    if reconnect_interval_secs < 1 {
        messages.push("client.reconnect-interval must be at least 1".to_owned());
    }

    let service_count = raw.services.len();
    let services = raw
        .services
        .into_iter()
        .filter_map(|service| validate_client_service(service, &mut messages))
        .collect();
    if service_count != 1 {
        messages.push("phase-2 client mode requires exactly one Catch-all Service".to_owned());
    }

    if messages.is_empty() {
        Ok(ClientSettings {
            server_hostname,
            server_ca_file,
            identity_directory: identity_directory.expect("validated client.identity-directory"),
            reconnect_interval: Duration::from_secs(reconnect_interval_secs),
            services,
        })
    } else {
        Err(SettingsError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages,
        })
    }
}

fn validate_required_path(
    field_name: &str,
    raw_path: Option<PathBuf>,
    config_dir: &Path,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    let Some(raw_path) = raw_path else {
        messages.push(format!("{field_name} is required"));
        return None;
    };
    validate_optional_path(field_name, raw_path, config_dir, messages)
}

fn validate_optional_path(
    field_name: &str,
    raw_path: PathBuf,
    config_dir: &Path,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    let resolved = resolve_path(config_dir, &raw_path);
    if !resolved.is_file() {
        messages.push(format!(
            "{field_name} file not found: {}",
            resolved.display()
        ));
        return None;
    }
    Some(resolved)
}

fn validate_required_directory(
    field_name: &str,
    raw_path: Option<PathBuf>,
    config_dir: &Path,
    messages: &mut Vec<String>,
) -> Option<PathBuf> {
    let Some(raw_path) = raw_path else {
        messages.push(format!("{field_name} is required"));
        return None;
    };
    let resolved = resolve_path(config_dir, &raw_path);
    if !resolved.is_dir() {
        messages.push(format!(
            "{field_name} directory not found: {}",
            resolved.display()
        ));
        return None;
    }
    Some(resolved)
}

fn validate_directory_file(
    field_name: &str,
    directory: &Path,
    filename: &str,
    messages: &mut Vec<String>,
) {
    let path = directory.join(filename);
    if !path.is_file() {
        messages.push(format!("{field_name} file not found: {}", path.display()));
    }
}

fn validate_server_tunnel(
    raw: RawServerTunnelConfig,
    messages: &mut Vec<String>,
) -> Option<ServerTunnelSettings> {
    if raw.hostnames.is_some() {
        messages.push("phase-2 server mode only supports a Catch-all Tunnel".to_owned());
    }

    let client_identity = match raw.client_public_key_fingerprint {
        Some(client_identity) => match client_identity.parse::<ClientIdentity>() {
            Ok(client_identity) => Some(client_identity),
            Err(error) => {
                messages.push(format!(
                    "server.tunnels[].client-public-key-fingerprint is invalid: {error}"
                ));
                None
            }
        },
        None => {
            messages.push("server.tunnels[].client-public-key-fingerprint is required".to_owned());
            None
        }
    };

    client_identity.map(|client_identity| ServerTunnelSettings { client_identity })
}

fn validate_client_service(
    raw: RawClientServiceConfig,
    messages: &mut Vec<String>,
) -> Option<ClientServiceSettings> {
    if raw.public_hostnames.is_some() {
        messages.push("phase-2 client mode only supports a Catch-all Service".to_owned());
    }

    let backend_addr = match raw.backend_address {
        Some(backend_addr) => {
            if !is_valid_backend_addr(&backend_addr) {
                messages.push(
                    "client.services[].backend-address must be a TCP address or host:port pair"
                        .to_owned(),
                );
                None
            } else {
                Some(backend_addr)
            }
        }
        None => {
            messages.push("client.services[].backend-address is required".to_owned());
            None
        }
    };

    backend_addr.map(|backend_addr| ClientServiceSettings { backend_addr })
}

fn is_valid_backend_addr(backend_addr: &str) -> bool {
    backend_addr.parse::<std::net::SocketAddr>().is_ok()
        || backend_addr
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

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawServerConfig {
    hostname: Option<String>,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    acme: Option<toml::Table>,
    #[serde(default)]
    tunnels: Vec<RawServerTunnelConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawServerTunnelConfig {
    hostnames: Option<Vec<String>>,
    client_public_key_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawClientConfig {
    server_hostname: Option<String>,
    server_ca_file: Option<PathBuf>,
    identity_directory: Option<PathBuf>,
    reconnect_interval: Option<u64>,
    #[serde(default)]
    services: Vec<RawClientServiceConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawClientServiceConfig {
    public_hostnames: Option<Vec<String>>,
    backend_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{is_valid_backend_addr, resolve_path};

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
        assert!(is_valid_backend_addr("caddy.local:443"));
        assert!(is_valid_backend_addr("127.0.0.1:443"));
        assert!(!is_valid_backend_addr("caddy.local"));
    }
}
