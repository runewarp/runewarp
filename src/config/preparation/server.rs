use std::fmt;
use std::path::{Path, PathBuf};

use crate::config::preparation::control::prepare_control_section;
use crate::config::preparation::material::{candidate_config_path, resolve_material_directory};
use crate::config::preparation::{
    MaterialDirectoryError, PreparedDirectory, PreparedValue, resolve_default_path, resolve_path,
    resolve_path_with_default,
};
use crate::config::{
    ConfigFileError, LogLevel, RawServerAcmeConfig, RawServerConfig, RawServerTunnelConfig,
    SERVER_HOSTNAME_ENV_VAR, collect_server_unknown_field_messages, deserialize_selected_section,
    load_log_level_from_path, load_optional_selected_section_value,
};
use crate::{
    ServerHostname, XdgPathError, default_config_path, default_server_acme_state_dir,
    default_server_cert_material_dir, default_server_identity_material_dir,
};
use std::env;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerRuntimeArgs {
    pub hostname: Option<String>,
    pub control_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerConfig {
    pub(crate) hostname: Option<String>,
    pub(crate) log_level: LogLevel,
    pub(crate) public_bind_address: String,
    pub(crate) tunnel_bind_address: String,
    pub(crate) readiness_bind_address: Option<String>,
    pub(crate) graceful_shutdown_duration: String,
    pub(crate) manual_cert_present: bool,
    pub(crate) acme_present: bool,
    pub(crate) manual_certificate_directory: Option<PreparedValue<PathBuf>>,
    pub(crate) acme: Option<PreparedServerAcmeConfig>,
    pub(crate) tunnels: Vec<PreparedServerTunnelConfig>,
    pub(crate) unknown_field_messages: Vec<String>,
    pub(crate) control: crate::config::preparation::control::PreparedControlSection,
    pub(crate) identity_directory: Option<PreparedValue<PathBuf>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerAcmeConfig {
    pub(crate) email: Option<String>,
    pub(crate) state_directory: PreparedDirectory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerTunnelConfig {
    pub(crate) public_hostnames: Option<Vec<String>>,
    pub(crate) client_identity: Option<String>,
    pub(crate) client_identities: Option<Vec<String>>,
}

pub(crate) fn select_server_config_path(config: Option<PathBuf>) -> Result<PathBuf, XdgPathError> {
    select_server_config_path_with_default(config, default_config_path)
}

pub(crate) fn prepare_server_config_from_path(
    path: &Path,
) -> Result<PreparedServerConfig, ConfigFileError> {
    prepare_server_config_from_cli(path, ServerRuntimeArgs::default())
}

pub(crate) fn prepare_server_config_from_cli(
    path: &Path,
    runtime: ServerRuntimeArgs,
) -> Result<PreparedServerConfig, ConfigFileError> {
    let Some(section_value) = load_optional_selected_section_value(path, "server")? else {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages: vec!["missing [server] section".to_owned()],
        });
    };
    let unknown_field_messages = collect_server_unknown_field_messages(&section_value);
    let mut raw = deserialize_selected_section::<RawServerConfig>(path, "server", &section_value)?;
    if let Some(hostname) = resolve_server_hostname_runtime_override(runtime.hostname) {
        raw.hostname = Some(hostname);
    }
    let log_level = load_log_level_from_path(path)?;
    let control = prepare_control_section(path, runtime.control_address)?;
    Ok(prepare_raw_server_config(
        path,
        log_level,
        raw,
        unknown_field_messages,
        control,
    ))
}

struct ServerPreparationDefaults<'a> {
    default_server_cert_directory: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_server_acme_state_dir: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_server_identity_directory: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
}

fn prepare_raw_server_config(
    path: &Path,
    log_level: LogLevel,
    raw: RawServerConfig,
    unknown_field_messages: Vec<String>,
    control: crate::config::preparation::control::PreparedControlSection,
) -> PreparedServerConfig {
    prepare_raw_server_config_with_defaults(
        path,
        log_level,
        raw,
        unknown_field_messages,
        control,
        &ServerPreparationDefaults {
            default_server_cert_directory: &default_server_cert_material_dir,
            default_server_acme_state_dir: &default_server_acme_state_dir,
            default_server_identity_directory: &default_server_identity_material_dir,
        },
    )
}

fn prepare_raw_server_config_with_defaults(
    path: &Path,
    log_level: LogLevel,
    raw: RawServerConfig,
    unknown_field_messages: Vec<String>,
    control: crate::config::preparation::control::PreparedControlSection,
    defaults: &ServerPreparationDefaults<'_>,
) -> PreparedServerConfig {
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let manual_cert_present = raw.cert_dir.is_some();
    let acme_present = raw.acme.is_some();
    let managed = control.address.is_some();

    PreparedServerConfig {
        hostname: raw.hostname,
        log_level,
        public_bind_address: raw
            .public_bind_address
            .unwrap_or_else(|| "0.0.0.0:443".to_owned()),
        tunnel_bind_address: raw
            .tunnel_bind_address
            .unwrap_or_else(|| "0.0.0.0:443".to_owned()),
        readiness_bind_address: raw.readiness_bind_address,
        graceful_shutdown_duration: raw
            .graceful_shutdown_duration
            .unwrap_or_else(|| "60s".to_owned()),
        manual_cert_present,
        acme_present,
        manual_certificate_directory: if !acme_present {
            Some(resolve_path_with_default(
                raw.cert_dir,
                config_dir,
                defaults.default_server_cert_directory,
            ))
        } else {
            None
        },
        acme: if acme_present && !manual_cert_present {
            raw.acme.map(|acme| {
                prepare_server_acme_config(acme, config_dir, defaults.default_server_acme_state_dir)
            })
        } else {
            None
        },
        tunnels: raw.tunnels.into_iter().map(prepare_server_tunnel).collect(),
        unknown_field_messages,
        control,
        identity_directory: prepare_server_identity_directory(
            raw.identity_dir,
            config_dir,
            managed,
            defaults.default_server_identity_directory,
        ),
    }
}

fn prepare_server_identity_directory(
    identity_dir: Option<PathBuf>,
    config_dir: &Path,
    managed: bool,
    default_server_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Option<PreparedValue<PathBuf>> {
    match identity_dir {
        Some(directory) => Some(PreparedValue::Ready(resolve_path(config_dir, &directory))),
        None if managed => Some(resolve_default_path(default_server_identity_directory)),
        None => None,
    }
}

fn prepare_server_acme_config(
    raw: RawServerAcmeConfig,
    config_dir: &Path,
    default_server_acme_state_dir: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedServerAcmeConfig {
    PreparedServerAcmeConfig {
        email: raw.email,
        state_directory: match raw.state_dir {
            Some(state_directory) => {
                PreparedDirectory::Explicit(resolve_path(config_dir, &state_directory))
            }
            None => {
                PreparedDirectory::Defaulted(resolve_default_path(default_server_acme_state_dir))
            }
        },
    }
}

fn prepare_server_tunnel(raw: RawServerTunnelConfig) -> PreparedServerTunnelConfig {
    PreparedServerTunnelConfig {
        public_hostnames: raw.public_hostnames,
        client_identity: raw.client_identity,
        client_identities: raw.client_identities,
    }
}

fn select_server_config_path_with_default(
    config: Option<PathBuf>,
    default_config_path: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> Result<PathBuf, XdgPathError> {
    match config {
        Some(path) => Ok(path),
        None => default_config_path(),
    }
}

pub(crate) fn resolve_server_hostname_runtime_override(hostname: Option<String>) -> Option<String> {
    hostname.or_else(|| env::var(SERVER_HOSTNAME_ENV_VAR).ok())
}

/// Projects an explicit `server.cert-dir` from config without applying XDG defaults.
pub(crate) fn project_server_cert_material_dir(
    path: &Path,
) -> Result<Option<PathBuf>, ConfigFileError> {
    let Some(raw) = load_optional_raw_server_section(path)? else {
        return Ok(None);
    };
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    Ok(raw.cert_dir.map(|path| resolve_path(config_dir, &path)))
}

/// Projects and validates an explicit `server.hostname` from config.
pub(crate) fn project_server_hostname(
    path: &Path,
) -> Result<Option<ServerHostname>, ConfigFileError> {
    let Some(raw) = load_optional_raw_server_section(path)? else {
        return Ok(None);
    };
    let mut messages = Vec::new();
    let hostname =
        raw.hostname.and_then(
            |hostname| match ServerHostname::try_from(hostname.as_str()) {
                Ok(hostname) => Some(hostname),
                Err(error) => {
                    messages.push(format!("server.hostname is invalid: {error}"));
                    None
                }
            },
        );
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

/// Resolves the Server certificate material directory for material-management commands.
pub(crate) fn resolve_server_cert_material_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, MaterialDirectoryError> {
    resolve_material_directory(
        config,
        directory,
        project_server_cert_material_dir,
        default_server_cert_material_dir,
    )
}

/// Resolves the Server hostname for certificate material commands.
pub(crate) fn resolve_server_cert_hostname(
    config: Option<PathBuf>,
    hostname: Option<String>,
) -> Result<String, ServerCertHostnameError> {
    let cli_hostname = hostname;
    let runtime_hostname = resolve_server_hostname_runtime_override(cli_hostname.clone());
    let configured_hostname = if let Some(config_path) = candidate_config_path(config) {
        project_server_hostname(&config_path).map_err(ServerCertHostnameError::ConfigFile)?
    } else {
        None
    };

    let hostname = match (cli_hostname, runtime_hostname, configured_hostname) {
        (Some(hostname), _, Some(configured_hostname)) => {
            let parsed = ServerHostname::try_from(hostname.as_str()).map_err(|error| {
                ServerCertHostnameError::Invalid {
                    message: format!("server.hostname is invalid: {error}"),
                }
            })?;
            if parsed != configured_hostname {
                return Err(ServerCertHostnameError::Mismatch {
                    cli_hostname: hostname,
                    configured_hostname: configured_hostname.to_string(),
                });
            }
            hostname
        }
        (Some(hostname), _, None) => hostname,
        (None, Some(hostname), _) => hostname,
        (None, None, Some(configured_hostname)) => configured_hostname.to_string(),
        (None, None, None) => return Err(ServerCertHostnameError::Missing),
    };

    ServerHostname::try_from(hostname.as_str()).map_err(|error| {
        ServerCertHostnameError::Invalid {
            message: format!("server.hostname is invalid: {error}"),
        }
    })?;
    Ok(hostname)
}

fn load_optional_raw_server_section(
    path: &Path,
) -> Result<Option<RawServerConfig>, ConfigFileError> {
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
    Ok(Some(deserialize_selected_section::<RawServerConfig>(
        path,
        "server",
        &section_value,
    )?))
}

#[derive(Debug)]
pub enum ServerCertHostnameError {
    ConfigFile(ConfigFileError),
    Missing,
    Mismatch {
        cli_hostname: String,
        configured_hostname: String,
    },
    Invalid {
        message: String,
    },
}

impl fmt::Display for ServerCertHostnameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigFile(error) => write!(formatter, "{error}"),
            Self::Missing => formatter.write_str(
                "server hostname is required via --hostname, RUNEWARP_SERVER_HOSTNAME, or server.hostname in config",
            ),
            Self::Mismatch {
                cli_hostname,
                configured_hostname,
            } => write!(
                formatter,
                "--hostname `{cli_hostname}` does not match configured server.hostname `{configured_hostname}`"
            ),
            Self::Invalid { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ServerCertHostnameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigFile(error) => Some(error),
            Self::Missing | Self::Mismatch { .. } | Self::Invalid { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        PreparedDirectory, PreparedValue, ServerRuntimeArgs, prepare_server_config_from_cli,
        prepare_server_config_from_path,
    };
    use crate::config::preparation::control::prepare_control_section_without_config;
    use crate::config::{LogLevel, RawServerAcmeConfig, RawServerConfig, RawServerTunnelConfig};

    #[test]
    fn server_config_selection_prefers_the_explicit_path() -> Result<(), Box<dyn std::error::Error>>
    {
        let explicit = PathBuf::from("/tmp/explicit-server.toml");

        let selected =
            super::select_server_config_path_with_default(Some(explicit.clone()), || {
                Ok(PathBuf::from("/tmp/default-server.toml"))
            })?;

        assert_eq!(selected, explicit);
        Ok(())
    }

    #[test]
    fn server_config_selection_uses_the_default_path_when_omitted()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = super::select_server_config_path_with_default(None, || {
            Ok(PathBuf::from("/tmp/default-server.toml"))
        })?;

        assert_eq!(selected, PathBuf::from("/tmp/default-server.toml"));
        Ok(())
    }

    #[test]
    fn server_preparation_defaults_bind_addresses_and_resolves_manual_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        fs::write(
            tempdir.path().join("config.toml"),
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
        )?;

        let prepared = prepare_server_config_from_path(&tempdir.path().join("config.toml"))?;

        assert_eq!(prepared.hostname, Some("tunnel.example.test".to_owned()));
        assert_eq!(prepared.log_level, LogLevel::Info);
        assert_eq!(prepared.public_bind_address, "0.0.0.0:443");
        assert_eq!(prepared.tunnel_bind_address, "0.0.0.0:443");
        assert_eq!(prepared.readiness_bind_address, None);
        assert_eq!(prepared.graceful_shutdown_duration, "60s");
        assert!(prepared.manual_cert_present);
        assert!(!prepared.acme_present);
        assert_eq!(
            prepared.manual_certificate_directory,
            Some(PreparedValue::Ready(tempdir.path().join("server-cert")))
        );
        assert_eq!(
            prepared.tunnels[0].public_hostnames,
            Some(vec!["app.example.test".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn server_preparation_overrides_hostname_from_runtime() -> Result<(), Box<dyn std::error::Error>>
    {
        let tempdir = tempdir()?;
        fs::write(
            tempdir.path().join("config.toml"),
            r#"
[server]
hostname = "configured.example.test"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
        )?;

        let prepared = prepare_server_config_from_cli(
            &tempdir.path().join("config.toml"),
            ServerRuntimeArgs {
                hostname: Some("overridden.example.test".to_owned()),
                control_address: None,
            },
        )?;

        assert_eq!(
            prepared.hostname,
            Some("overridden.example.test".to_owned())
        );
        Ok(())
    }

    #[test]
    fn server_preparation_uses_injected_xdg_defaults_for_manual_material_and_acme_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("config.toml");
        let default_cert_dir = tempdir.path().join("xdg-data/server/cert");
        let default_acme_state_dir = tempdir.path().join("xdg-state/server/acme");

        let control = prepare_control_section_without_config(None);

        let manual = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Info,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: None,
                identity_dir: None,
                acme: None,
                public_bind_address: None,
                tunnel_bind_address: None,
                readiness_bind_address: None,
                graceful_shutdown_duration: None,
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            control.clone(),
            &super::ServerPreparationDefaults {
                default_server_cert_directory: &|| Ok(default_cert_dir.clone()),
                default_server_acme_state_dir: &|| Ok(default_acme_state_dir.clone()),
                default_server_identity_directory: &|| {
                    Ok(tempdir.path().join("unused-identity-dir"))
                },
            },
        );

        assert_eq!(
            manual.manual_certificate_directory,
            Some(PreparedValue::Ready(default_cert_dir))
        );
        assert_eq!(manual.public_bind_address, "0.0.0.0:443");
        assert_eq!(manual.tunnel_bind_address, "0.0.0.0:443");
        assert_eq!(manual.readiness_bind_address, None);
        assert_eq!(manual.graceful_shutdown_duration, "60s");

        let acme = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Off,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: None,
                identity_dir: None,
                acme: Some(RawServerAcmeConfig {
                    email: Some("admin@example.test".to_owned()),
                    state_dir: None,
                }),
                public_bind_address: None,
                tunnel_bind_address: None,
                readiness_bind_address: None,
                graceful_shutdown_duration: None,
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            control,
            &super::ServerPreparationDefaults {
                default_server_cert_directory: &|| Ok(tempdir.path().join("unused-cert-dir")),
                default_server_acme_state_dir: &|| Ok(default_acme_state_dir.clone()),
                default_server_identity_directory: &|| {
                    Ok(tempdir.path().join("unused-identity-dir"))
                },
            },
        );

        assert_eq!(acme.log_level, LogLevel::Off);
        let prepared_acme = match acme.acme {
            Some(prepared_acme) => prepared_acme,
            None => panic!("expected prepared server acme config"),
        };
        assert_eq!(
            prepared_acme.state_directory,
            PreparedDirectory::Defaulted(PreparedValue::Ready(default_acme_state_dir))
        );
        Ok(())
    }

    #[test]
    fn server_preparation_resolves_relative_acme_state_dir_from_the_config_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("nested").join("server.toml");

        let prepared = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Off,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: None,
                identity_dir: None,
                acme: Some(RawServerAcmeConfig {
                    email: Some("admin@example.test".to_owned()),
                    state_dir: Some(PathBuf::from("acme-state")),
                }),
                public_bind_address: Some("127.0.0.1:8443".to_owned()),
                tunnel_bind_address: Some("127.0.0.1:9443".to_owned()),
                readiness_bind_address: Some("127.0.0.1:9000".to_owned()),
                graceful_shutdown_duration: Some("45s".to_owned()),
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            prepare_control_section_without_config(None),
            &super::ServerPreparationDefaults {
                default_server_cert_directory: &|| Ok(tempdir.path().join("unused-cert-dir")),
                default_server_acme_state_dir: &|| Ok(tempdir.path().join("unused-acme-state")),
                default_server_identity_directory: &|| {
                    Ok(tempdir.path().join("unused-identity-dir"))
                },
            },
        );

        assert_eq!(prepared.log_level, LogLevel::Off);
        assert_eq!(prepared.public_bind_address, "127.0.0.1:8443");
        assert_eq!(prepared.tunnel_bind_address, "127.0.0.1:9443");
        assert_eq!(
            prepared.readiness_bind_address,
            Some("127.0.0.1:9000".to_owned())
        );
        assert_eq!(prepared.graceful_shutdown_duration, "45s");
        let prepared_acme = match prepared.acme {
            Some(prepared_acme) => prepared_acme,
            None => panic!("expected prepared server acme config"),
        };
        assert_eq!(
            prepared_acme.state_directory,
            PreparedDirectory::Explicit(tempdir.path().join("nested/acme-state"))
        );
        Ok(())
    }

    #[test]
    fn server_preparation_defaults_managed_identity_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("config.toml");
        let default_identity_dir = tempdir.path().join("xdg-data/server/identity");

        let prepared = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Info,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: Some(PathBuf::from("server-cert")),
                identity_dir: None,
                acme: None,
                public_bind_address: None,
                tunnel_bind_address: None,
                readiness_bind_address: None,
                graceful_shutdown_duration: None,
                tunnels: Vec::new(),
            },
            Vec::new(),
            prepare_control_section_without_config(Some("https://control.example.test".to_owned())),
            &super::ServerPreparationDefaults {
                default_server_cert_directory: &|| Ok(tempdir.path().join("unused-cert-dir")),
                default_server_acme_state_dir: &|| Ok(tempdir.path().join("unused-acme-state")),
                default_server_identity_directory: &|| Ok(default_identity_dir.clone()),
            },
        );

        assert_eq!(
            prepared.identity_directory,
            Some(PreparedValue::Ready(default_identity_dir))
        );
        Ok(())
    }

    #[test]
    fn server_preparation_leaves_static_identity_directory_unset_when_omitted()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("config.toml");

        let prepared = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Info,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: Some(PathBuf::from("server-cert")),
                identity_dir: None,
                acme: None,
                public_bind_address: None,
                tunnel_bind_address: None,
                readiness_bind_address: None,
                graceful_shutdown_duration: None,
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            prepare_control_section_without_config(None),
            &super::ServerPreparationDefaults {
                default_server_cert_directory: &|| Ok(tempdir.path().join("unused-cert-dir")),
                default_server_acme_state_dir: &|| Ok(tempdir.path().join("unused-acme-state")),
                default_server_identity_directory: &|| {
                    panic!("static mode should not consult identity defaults")
                },
            },
        );

        assert_eq!(prepared.identity_directory, None);
        Ok(())
    }
}
