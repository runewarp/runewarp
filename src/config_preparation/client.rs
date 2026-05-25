use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config_preparation::{
    PreparedDirectory, PreparedValue, resolve_default_path, resolve_path, resolve_path_with_default,
};
use crate::settings::{
    DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS, RawClientAcmeConfig, RawClientConfig,
    RawClientServiceConfig, SettingsError, collect_client_unknown_field_messages,
    deserialize_selected_section, load_optional_selected_section_value,
};
use crate::trust::{ClientServerTrust, ResolveClientServerTrustError, resolve_client_server_trust};
use crate::{
    ClientRuntimeArgs, ClientSettingsResolutionError, SelectedClientConfig, XdgPathError,
    default_client_acme_state_dir,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedClientConfig {
    pub(crate) selected_path: Option<PathBuf>,
    pub(crate) server_address: Option<String>,
    pub(crate) logs: bool,
    pub(crate) trust: PreparedClientTrust,
    pub(crate) identity_directory: PreparedValue<PathBuf>,
    pub(crate) reconnect_interval: Duration,
    pub(crate) services: Vec<PreparedClientServiceConfig>,
    pub(crate) manual_public_cert_present: bool,
    pub(crate) manual_public_cert_directory: Option<PathBuf>,
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
    let selected_config =
        crate::select_client_config(config).map_err(ClientSettingsResolutionError::XdgPath)?;
    prepare_selected_client_config(selected_config, &runtime, &default_identity_material_dir)
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
    Ok(Some(prepare_raw_client_config(
        Some(path.to_path_buf()),
        raw,
        unknown_field_messages,
        &default_identity_material_dir,
    )))
}

pub(crate) fn prepare_selected_client_config(
    selected_config: SelectedClientConfig,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PreparedClientConfig, ClientSettingsResolutionError> {
    match selected_config {
        SelectedClientConfig::None => {
            prepare_cli_only_client_config(None, runtime, default_identity_directory)
        }
        SelectedClientConfig::Explicit(path) | SelectedClientConfig::Discovered(path) => {
            prepare_selected_config_client_config(path, runtime, default_identity_directory)
        }
    }
}

fn prepare_selected_config_client_config(
    path: PathBuf,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PreparedClientConfig, ClientSettingsResolutionError> {
    let section_value = load_optional_selected_section_value(&path, "client")
        .map_err(ClientSettingsResolutionError::Settings)?;
    let Some(section_value) = section_value else {
        return prepare_cli_only_client_config(Some(&path), runtime, default_identity_directory);
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
        raw,
        messages,
        default_identity_directory,
    ))
}

fn prepare_cli_only_client_config(
    selected_path: Option<&Path>,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
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
        RawClientConfig {
            server_address: runtime.server_address.clone(),
            logs: None,
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
    ))
}

pub(crate) fn prepare_raw_client_config(
    selected_path: Option<PathBuf>,
    raw: RawClientConfig,
    unknown_field_messages: Vec<String>,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedClientConfig {
    let config_dir = selected_path
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let manual_public_cert_present = raw.public_cert_dir.is_some();
    let acme_present = raw.acme.is_some();

    PreparedClientConfig {
        selected_path,
        server_address: raw.server_address,
        logs: raw.logs.unwrap_or(true),
        trust: prepare_client_trust(raw.server_trust.as_deref(), raw.server_ca_file, &config_dir),
        identity_directory: resolve_path_with_default(
            raw.identity_dir,
            &config_dir,
            default_identity_directory,
        ),
        reconnect_interval: Duration::from_secs(DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS),
        services: raw
            .services
            .into_iter()
            .map(prepare_client_service)
            .collect(),
        manual_public_cert_present,
        manual_public_cert_directory: raw
            .public_cert_dir
            .map(|directory| resolve_path(&config_dir, &directory)),
        acme_present,
        acme: if acme_present && !manual_public_cert_present {
            raw.acme
                .map(|acme| prepare_client_acme_config(acme, &config_dir))
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
) -> PreparedClientTrust {
    match resolve_client_server_trust(trust_mode, server_ca_file, config_dir) {
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

fn default_identity_material_dir() -> Result<PathBuf, XdgPathError> {
    crate::default_client_identity_material_dir()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{PreparedClientTlsMode, PreparedClientTrust, prepare_selected_client_config};
    use crate::{ClientRuntimeArgs, SelectedClientConfig};

    #[test]
    fn selected_config_preparation_applies_runtime_overrides_before_validation() {
        let tempdir = tempdir().unwrap();
        let identity_directory = tempdir.path().join("client-identity");
        fs::create_dir(&identity_directory).unwrap();
        fs::write(
            tempdir.path().join("config.toml"),
            r#"
[client]
logs = false
"#,
        )
        .unwrap();

        let prepared = prepare_selected_client_config(
            SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
            &ClientRuntimeArgs {
                server_address: Some("Tunnel.Example.Test.".to_owned()),
                backend_address: Some("backend.internal:443".to_owned()),
            },
            &|| Ok(identity_directory.clone()),
        )
        .unwrap();

        assert_eq!(
            prepared.selected_path,
            Some(tempdir.path().join("config.toml"))
        );
        assert_eq!(
            prepared.server_address,
            Some("Tunnel.Example.Test.".to_owned())
        );
        assert!(!prepared.logs);
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
    }
}
