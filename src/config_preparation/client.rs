use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config_preparation::{
    PreparedDirectory, PreparedValue, resolve_default_path, resolve_path, resolve_path_with_default,
};
use crate::settings::{
    DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS, LogLevel, RawClientAcmeConfig, RawClientConfig,
    RawClientServiceConfig, SettingsError, collect_client_unknown_field_messages,
    deserialize_selected_section, load_log_level_from_path, load_optional_selected_section_value,
};
use crate::trust::{
    ClientServerTrust, ResolveClientServerTrustError, resolve_client_server_trust_with_default,
};
use crate::{
    ClientRuntimeArgs, ClientSettingsResolutionError, SelectedClientConfig, XdgPathError,
    default_client_acme_state_dir, default_client_server_ca_path, default_config_path,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedClientConfig {
    pub(crate) selected_path: Option<PathBuf>,
    pub(crate) server_address: Option<String>,
    pub(crate) log_level: LogLevel,
    pub(crate) trust: PreparedClientTrust,
    pub(crate) identity_directory: PreparedValue<PathBuf>,
    pub(crate) reconnect_interval: Duration,
    pub(crate) services: Vec<PreparedClientServiceConfig>,
    pub(crate) manual_public_cert_present: bool,
    pub(crate) manual_public_cert_directory: Option<PreparedValue<PathBuf>>,
    pub(crate) acme_present: bool,
    pub(crate) acme: Option<PreparedClientAcmeConfig>,
    pub(crate) unknown_field_messages: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedClientTrust {
    System,
    CaFile(PreparedValue<PathBuf>),
    InvalidMode(String),
    UnexpectedServerCaFile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedClientAcmeConfig {
    pub(crate) email: Option<String>,
    pub(crate) state_directory: PreparedDirectory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedClientServiceConfig {
    pub(crate) public_hostnames: Option<Vec<String>>,
    pub(crate) backend_address: Option<String>,
    pub(crate) tls_mode: PreparedClientTlsMode,
}

struct ClientPreparationDefaults<'a> {
    default_identity_directory: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_public_cert_directory: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_server_ca_path: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_client_acme_state_dir: &'a dyn Fn() -> Result<PathBuf, XdgPathError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedClientTlsMode {
    Passthrough,
    Terminate,
    Invalid(String),
}

pub(crate) fn prepare_client_settings_from_cli(
    config: Option<PathBuf>,
    runtime: ClientRuntimeArgs,
) -> Result<PreparedClientConfig, ClientSettingsResolutionError> {
    let selected_config = select_client_config_with_default(config, default_config_path)
        .map_err(ClientSettingsResolutionError::XdgPath)?;
    prepare_selected_client_config(
        selected_config,
        &runtime,
        &default_identity_material_dir,
        &default_public_cert_dir,
    )
}

pub(crate) fn select_client_config(
    config: Option<PathBuf>,
) -> Result<SelectedClientConfig, XdgPathError> {
    select_client_config_with_default(config, default_config_path)
}

pub(crate) fn prepare_client_config_from_path(
    path: &Path,
) -> Result<PreparedClientConfig, SettingsError> {
    let Some(prepared) = prepare_optional_client_config_from_path(path)? else {
        return Err(SettingsError::Validation {
            path: path.to_path_buf(),
            section: "client",
            messages: vec!["missing [client] section".to_owned()],
        });
    };
    Ok(prepared)
}

pub(crate) fn prepare_optional_client_config_from_path(
    path: &Path,
) -> Result<Option<PreparedClientConfig>, SettingsError> {
    let Some(section_value) = load_optional_selected_section_value(path, "client")? else {
        return Ok(None);
    };
    let unknown_field_messages = collect_client_unknown_field_messages(&section_value);
    let raw = deserialize_selected_section::<RawClientConfig>(path, "client", &section_value)?;
    let log_level = load_log_level_from_path(path)?;
    Ok(Some(prepare_raw_client_config(
        Some(path.to_path_buf()),
        log_level,
        raw,
        unknown_field_messages,
        &default_identity_material_dir,
        &default_public_cert_dir,
    )))
}

pub(crate) fn prepare_selected_client_config(
    selected_config: SelectedClientConfig,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_public_cert_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PreparedClientConfig, ClientSettingsResolutionError> {
    match selected_config {
        SelectedClientConfig::None => prepare_cli_only_client_config(
            None,
            LogLevel::default(),
            runtime,
            default_identity_directory,
            default_public_cert_directory,
        ),
        SelectedClientConfig::Explicit(path) | SelectedClientConfig::Discovered(path) => {
            prepare_selected_config_client_config(
                path,
                runtime,
                default_identity_directory,
                default_public_cert_directory,
            )
        }
    }
}

fn prepare_selected_config_client_config(
    path: PathBuf,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_public_cert_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PreparedClientConfig, ClientSettingsResolutionError> {
    let section_value = load_optional_selected_section_value(&path, "client")
        .map_err(ClientSettingsResolutionError::Settings)?;
    let log_level =
        load_log_level_from_path(&path).map_err(ClientSettingsResolutionError::Settings)?;
    let Some(section_value) = section_value else {
        return prepare_cli_only_client_config(
            Some(&path),
            log_level,
            runtime,
            default_identity_directory,
            default_public_cert_directory,
        );
    };

    let service_block_count = selected_service_block_count(&section_value);
    let mut messages = collect_client_unknown_field_messages(&section_value);
    let mut raw = deserialize_selected_section::<RawClientConfig>(&path, "client", &section_value)
        .map_err(ClientSettingsResolutionError::Settings)?;

    if let Some(server_address) = &runtime.server_address {
        raw.server_address = Some(server_address.clone());
    }

    if let Some(backend_address) = &runtime.backend_address {
        if service_block_count > 0 {
            messages.push(
                "--backend-address may be used only when the selected config contributes no [[client.services]] blocks"
                    .to_owned(),
            );
        } else {
            raw.services = vec![RawClientServiceConfig {
                public_hostnames: None,
                backend_address: Some(backend_address.clone()),
                tls_mode: None,
            }];
        }
    }

    Ok(prepare_raw_client_config(
        Some(path),
        log_level,
        raw,
        messages,
        default_identity_directory,
        default_public_cert_directory,
    ))
}

fn prepare_cli_only_client_config(
    selected_path: Option<&Path>,
    log_level: LogLevel,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_public_cert_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PreparedClientConfig, ClientSettingsResolutionError> {
    let mut messages = Vec::new();
    let missing_context = match selected_path {
        Some(_) => "the selected config has no [client] section",
        None => "no selected client config is available",
    };
    if runtime.server_address.is_none() {
        messages.push(format!(
            "--server-address is required when {missing_context}"
        ));
    }
    if runtime.backend_address.is_none() {
        messages.push(format!(
            "--backend-address is required when {missing_context}"
        ));
    }
    if !messages.is_empty() {
        return Err(ClientSettingsResolutionError::Validation {
            path: selected_path.map(Path::to_path_buf),
            messages,
        });
    }

    Ok(prepare_raw_client_config(
        selected_path.map(Path::to_path_buf),
        log_level,
        RawClientConfig {
            server_address: runtime.server_address.clone(),
            server_trust: None,
            server_ca_file: None,
            identity_dir: None,
            public_cert_dir: None,
            acme: None,
            services: vec![RawClientServiceConfig {
                public_hostnames: None,
                backend_address: runtime.backend_address.clone(),
                tls_mode: None,
            }],
        },
        Vec::new(),
        default_identity_directory,
        default_public_cert_directory,
    ))
}

pub(crate) fn prepare_raw_client_config(
    selected_path: Option<PathBuf>,
    log_level: LogLevel,
    raw: RawClientConfig,
    unknown_field_messages: Vec<String>,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_public_cert_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedClientConfig {
    prepare_raw_client_config_with_defaults(
        selected_path,
        log_level,
        raw,
        unknown_field_messages,
        &ClientPreparationDefaults {
            default_identity_directory,
            default_public_cert_directory,
            default_server_ca_path: &default_client_server_ca_path,
            default_client_acme_state_dir: &default_client_acme_state_dir,
        },
    )
}

fn prepare_raw_client_config_with_defaults(
    selected_path: Option<PathBuf>,
    log_level: LogLevel,
    raw: RawClientConfig,
    unknown_field_messages: Vec<String>,
    defaults: &ClientPreparationDefaults<'_>,
) -> PreparedClientConfig {
    let config_dir = selected_path
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let manual_public_cert_present = raw.public_cert_dir.is_some();
    let acme_present = raw.acme.is_some();
    let has_terminating_service = raw
        .services
        .iter()
        .any(|service| service.tls_mode.as_deref() == Some("terminate"));

    PreparedClientConfig {
        selected_path,
        server_address: raw.server_address,
        log_level,
        trust: prepare_client_trust(
            raw.server_trust.as_deref(),
            raw.server_ca_file,
            &config_dir,
            defaults.default_server_ca_path,
        ),
        identity_directory: resolve_path_with_default(
            raw.identity_dir,
            &config_dir,
            defaults.default_identity_directory,
        ),
        reconnect_interval: Duration::from_secs(DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS),
        services: raw
            .services
            .into_iter()
            .map(prepare_client_service)
            .collect(),
        manual_public_cert_present,
        manual_public_cert_directory: match raw.public_cert_dir {
            Some(directory) => Some(PreparedValue::Ready(resolve_path(&config_dir, &directory))),
            None if !acme_present && has_terminating_service => {
                Some(resolve_default_path(defaults.default_public_cert_directory))
            }
            None => None,
        },
        acme_present,
        acme: if acme_present && !manual_public_cert_present {
            raw.acme.map(|acme| {
                prepare_client_acme_config(
                    acme,
                    &config_dir,
                    defaults.default_client_acme_state_dir,
                )
            })
        } else {
            None
        },
        unknown_field_messages,
    }
}

fn prepare_client_trust(
    trust_mode: Option<&str>,
    server_ca_file: Option<PathBuf>,
    config_dir: &Path,
    default_server_ca_path: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedClientTrust {
    match resolve_client_server_trust_with_default(
        trust_mode,
        server_ca_file,
        config_dir,
        default_server_ca_path,
    ) {
        Ok(ClientServerTrust::System) => PreparedClientTrust::System,
        Ok(ClientServerTrust::CaFile(server_ca_file)) => {
            PreparedClientTrust::CaFile(PreparedValue::Ready(server_ca_file))
        }
        Err(ResolveClientServerTrustError::InvalidMode { value }) => {
            PreparedClientTrust::InvalidMode(value)
        }
        Err(ResolveClientServerTrustError::UnexpectedServerCaFile) => {
            PreparedClientTrust::UnexpectedServerCaFile
        }
        Err(ResolveClientServerTrustError::DefaultCaPath(error)) => {
            PreparedClientTrust::CaFile(PreparedValue::Error(error.to_string()))
        }
    }
}

fn prepare_client_acme_config(
    raw: RawClientAcmeConfig,
    config_dir: &Path,
    default_client_acme_state_dir: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedClientAcmeConfig {
    PreparedClientAcmeConfig {
        email: raw.email,
        state_directory: match raw.state_dir {
            Some(state_directory) => {
                PreparedDirectory::Explicit(resolve_path(config_dir, &state_directory))
            }
            None => {
                PreparedDirectory::Defaulted(resolve_default_path(default_client_acme_state_dir))
            }
        },
    }
}

fn prepare_client_service(raw: RawClientServiceConfig) -> PreparedClientServiceConfig {
    PreparedClientServiceConfig {
        public_hostnames: raw.public_hostnames,
        backend_address: raw.backend_address,
        tls_mode: match raw.tls_mode.as_deref() {
            None | Some("passthrough") => PreparedClientTlsMode::Passthrough,
            Some("terminate") => PreparedClientTlsMode::Terminate,
            Some(value) => PreparedClientTlsMode::Invalid(value.to_owned()),
        },
    }
}

fn selected_service_block_count(section_value: &toml::Value) -> usize {
    section_value
        .as_table()
        .and_then(|client| client.get("services"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len)
}

fn select_client_config_with_default(
    config: Option<PathBuf>,
    default_config_path: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> Result<SelectedClientConfig, XdgPathError> {
    match config {
        Some(path) => Ok(SelectedClientConfig::Explicit(path)),
        None => {
            let path = default_config_path()?;
            if path.is_file() {
                Ok(SelectedClientConfig::Discovered(path))
            } else {
                Ok(SelectedClientConfig::None)
            }
        }
    }
}

fn default_identity_material_dir() -> Result<PathBuf, XdgPathError> {
    crate::default_client_identity_material_dir()
}

fn default_public_cert_dir() -> Result<PathBuf, XdgPathError> {
    crate::default_client_public_cert_material_dir()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::{
        ClientPreparationDefaults, PreparedClientTlsMode, PreparedClientTrust, PreparedDirectory,
        PreparedValue, prepare_selected_client_config,
    };
    use crate::settings::{LogLevel, RawClientAcmeConfig, RawClientConfig, RawClientServiceConfig};
    use crate::{ClientRuntimeArgs, SelectedClientConfig};

    #[test]
    fn client_config_selection_discovers_the_default_config_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let discovered_path = tempdir.path().join("config.toml");
        fs::write(
            &discovered_path,
            "[client]\nserver-address = \"tunnel.example.test\"\n",
        )?;

        let selected =
            super::select_client_config_with_default(None, || Ok(discovered_path.clone()))?;

        assert_eq!(selected, SelectedClientConfig::Discovered(discovered_path));
        Ok(())
    }

    #[test]
    fn cli_only_preparation_builds_a_catch_all_service_when_no_config_is_selected()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let identity_directory = tempdir.path().join("client-identity");

        let prepared = prepare_selected_client_config(
            SelectedClientConfig::None,
            &ClientRuntimeArgs {
                server_address: Some("tunnel.example.test".to_owned()),
                backend_address: Some("backend.internal:443".to_owned()),
            },
            &|| Ok(identity_directory.clone()),
            &|| Ok(tempdir.path().join("unused-public-cert")),
        )?;

        assert_eq!(prepared.selected_path, None);
        assert_eq!(
            prepared.server_address,
            Some("tunnel.example.test".to_owned())
        );
        assert_eq!(prepared.log_level, LogLevel::Info);
        assert_eq!(
            prepared.reconnect_interval,
            Duration::from_secs(crate::DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS)
        );
        assert_eq!(prepared.trust, PreparedClientTrust::System);
        assert_eq!(
            prepared.identity_directory,
            PreparedValue::Ready(identity_directory)
        );
        assert_eq!(prepared.services.len(), 1);
        assert_eq!(prepared.services[0].public_hostnames, None);
        assert_eq!(
            prepared.services[0].backend_address,
            Some("backend.internal:443".to_owned())
        );
        assert_eq!(
            prepared.services[0].tls_mode,
            PreparedClientTlsMode::Passthrough
        );
        Ok(())
    }

    #[test]
    fn selected_config_without_a_client_section_still_supports_runtime_only_startup()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("config.toml");
        let identity_directory = tempdir.path().join("client-identity");
        fs::write(
            &config_path,
            r#"
[server]
hostname = "tunnel.example.test"
"#,
        )?;

        let prepared = prepare_selected_client_config(
            SelectedClientConfig::Explicit(config_path.clone()),
            &ClientRuntimeArgs {
                server_address: Some("tunnel.example.test".to_owned()),
                backend_address: Some("backend.internal:443".to_owned()),
            },
            &|| Ok(identity_directory.clone()),
            &|| Ok(tempdir.path().join("unused-public-cert")),
        )?;

        assert_eq!(prepared.selected_path, Some(config_path));
        assert_eq!(
            prepared.identity_directory,
            PreparedValue::Ready(identity_directory)
        );
        assert_eq!(prepared.services.len(), 1);
        assert_eq!(prepared.services[0].public_hostnames, None);
        assert_eq!(
            prepared.services[0].backend_address,
            Some("backend.internal:443".to_owned())
        );
        Ok(())
    }

    #[test]
    fn preparation_uses_injected_xdg_defaults_for_trust_identity_and_acme()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("config.toml");
        let identity_directory = tempdir.path().join("xdg-data/client/identity");
        let server_ca_path = tempdir.path().join("xdg-data/client/server-ca.crt");
        let public_cert_directory = tempdir.path().join("xdg-data/client/public-cert");
        let acme_state_dir = tempdir.path().join("xdg-state/client/acme");

        let prepared = super::prepare_raw_client_config_with_defaults(
            Some(config_path),
            LogLevel::Info,
            RawClientConfig {
                server_address: Some("tunnel.example.test".to_owned()),
                server_trust: Some("ca-file".to_owned()),
                server_ca_file: None,
                identity_dir: None,
                public_cert_dir: None,
                acme: Some(RawClientAcmeConfig {
                    email: Some("admin@example.test".to_owned()),
                    state_dir: None,
                }),
                services: vec![RawClientServiceConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    backend_address: Some("127.0.0.1:443".to_owned()),
                    tls_mode: Some("terminate".to_owned()),
                }],
            },
            Vec::new(),
            &ClientPreparationDefaults {
                default_identity_directory: &|| Ok(identity_directory.clone()),
                default_public_cert_directory: &|| Ok(public_cert_directory.clone()),
                default_server_ca_path: &|| Ok(server_ca_path.clone()),
                default_client_acme_state_dir: &|| Ok(acme_state_dir.clone()),
            },
        );

        assert_eq!(prepared.log_level, LogLevel::Info);
        assert_eq!(
            prepared.reconnect_interval,
            Duration::from_secs(crate::DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS)
        );
        assert_eq!(
            prepared.identity_directory,
            PreparedValue::Ready(identity_directory)
        );
        assert_eq!(
            prepared.trust,
            PreparedClientTrust::CaFile(PreparedValue::Ready(server_ca_path))
        );
        let prepared_acme = match prepared.acme {
            Some(prepared_acme) => prepared_acme,
            None => panic!("expected prepared client acme config"),
        };
        assert_eq!(
            prepared_acme.state_directory,
            PreparedDirectory::Defaulted(PreparedValue::Ready(acme_state_dir))
        );
        Ok(())
    }

    #[test]
    fn preparation_resolves_relative_paths_from_the_selected_config_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("nested").join("config.toml");
        let default_identity_directory = tempdir.path().join("unused-identity");
        let default_server_ca_path = tempdir.path().join("unused-server-ca.crt");
        let default_public_cert_directory = tempdir.path().join("unused-public-cert");
        let default_acme_state_dir = tempdir.path().join("unused-acme-state");

        let prepared = super::prepare_raw_client_config_with_defaults(
            Some(config_path.clone()),
            LogLevel::Off,
            RawClientConfig {
                server_address: Some("tunnel.example.test".to_owned()),
                server_trust: Some("ca-file".to_owned()),
                server_ca_file: Some(PathBuf::from("trust/server-ca.pem")),
                identity_dir: Some(PathBuf::from("identity")),
                public_cert_dir: Some(PathBuf::from("public-cert")),
                acme: None,
                services: vec![RawClientServiceConfig {
                    public_hostnames: None,
                    backend_address: Some("127.0.0.1:443".to_owned()),
                    tls_mode: None,
                }],
            },
            Vec::new(),
            &ClientPreparationDefaults {
                default_identity_directory: &|| Ok(default_identity_directory.clone()),
                default_public_cert_directory: &|| Ok(default_public_cert_directory.clone()),
                default_server_ca_path: &|| Ok(default_server_ca_path.clone()),
                default_client_acme_state_dir: &|| Ok(default_acme_state_dir.clone()),
            },
        );

        assert_eq!(prepared.log_level, LogLevel::Off);
        assert_eq!(
            prepared.identity_directory,
            PreparedValue::Ready(tempdir.path().join("nested/identity"))
        );
        assert_eq!(
            prepared.trust,
            PreparedClientTrust::CaFile(PreparedValue::Ready(
                tempdir.path().join("nested/trust/server-ca.pem")
            ))
        );
        assert_eq!(
            prepared.manual_public_cert_directory,
            Some(PreparedValue::Ready(
                tempdir.path().join("nested/public-cert")
            ))
        );
        Ok(())
    }

    #[test]
    fn selected_config_preparation_applies_runtime_overrides_before_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let identity_directory = tempdir.path().join("client-identity");
        fs::create_dir(&identity_directory)?;
        fs::write(
            tempdir.path().join("config.toml"),
            r#"
log-level = "off"

[client]
"#,
        )?;

        let prepared = prepare_selected_client_config(
            SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
            &ClientRuntimeArgs {
                server_address: Some("Tunnel.Example.Test.".to_owned()),
                backend_address: Some("backend.internal:443".to_owned()),
            },
            &|| Ok(identity_directory.clone()),
            &|| Ok(tempdir.path().join("unused-public-cert")),
        )?;

        assert_eq!(
            prepared.selected_path,
            Some(tempdir.path().join("config.toml"))
        );
        assert_eq!(
            prepared.server_address,
            Some("Tunnel.Example.Test.".to_owned())
        );
        assert_eq!(prepared.log_level, LogLevel::Off);
        assert_eq!(prepared.services.len(), 1);
        assert_eq!(prepared.services[0].public_hostnames, None);
        assert_eq!(
            prepared.services[0].backend_address,
            Some("backend.internal:443".to_owned())
        );
        assert_eq!(
            prepared.services[0].tls_mode,
            PreparedClientTlsMode::Passthrough
        );
        assert_eq!(
            prepared.identity_directory,
            super::PreparedValue::Ready(identity_directory)
        );
        assert_eq!(prepared.trust, PreparedClientTrust::System);
        Ok(())
    }
}
