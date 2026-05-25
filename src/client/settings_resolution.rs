use std::fmt;
use std::path::{Path, PathBuf};

use crate::settings::{
    RawClientConfig, RawClientServiceConfig, collect_client_unknown_field_messages,
    deserialize_selected_section, load_optional_selected_section_value,
    validate_client_settings_with_default_identity_dir,
};
use crate::{
    ClientSettings, SettingsError, XdgPathError, default_client_identity_material_dir,
    default_config_path,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientRuntimeArgs {
    pub server_address: Option<String>,
    pub backend_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSettingsResolutionDefaults {
    pub identity_directory: PathBuf,
}

impl ClientSettingsResolutionDefaults {
    pub fn from_xdg() -> Result<Self, XdgPathError> {
        Ok(Self {
            identity_directory: default_client_identity_material_dir()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedClientConfig {
    Explicit(PathBuf),
    Discovered(PathBuf),
    None,
}

#[derive(Debug)]
pub enum ClientSettingsResolutionError {
    XdgPath(XdgPathError),
    Settings(SettingsError),
    Validation {
        path: Option<PathBuf>,
        messages: Vec<String>,
    },
}

impl ClientSettingsResolutionError {
    pub fn validation_messages(&self) -> Option<&[String]> {
        match self {
            Self::Settings(SettingsError::Validation { messages, .. }) => Some(messages),
            Self::Validation { messages, .. } => Some(messages),
            Self::XdgPath(_)
            | Self::Settings(SettingsError::Read { .. } | SettingsError::Parse { .. }) => None,
        }
    }

    pub fn selected_config_path(&self) -> Option<&Path> {
        match self {
            Self::Settings(SettingsError::Read { path, .. })
            | Self::Settings(SettingsError::Parse { path, .. })
            | Self::Settings(SettingsError::Validation { path, .. }) => Some(path.as_path()),
            Self::Validation {
                path: Some(path), ..
            } => Some(path.as_path()),
            Self::XdgPath(_) | Self::Validation { path: None, .. } => None,
        }
    }
}

impl fmt::Display for ClientSettingsResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XdgPath(error) => write!(formatter, "{error}"),
            Self::Settings(error) => write!(formatter, "{error}"),
            Self::Validation {
                path: Some(path),
                messages,
            } => {
                write!(formatter, "invalid client config in {}:", path.display())?;
                for message in messages {
                    write!(formatter, "\n- {message}")?;
                }
                Ok(())
            }
            Self::Validation {
                path: None,
                messages,
            } => {
                formatter.write_str("invalid client settings:")?;
                for message in messages {
                    write!(formatter, "\n- {message}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ClientSettingsResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::XdgPath(error) => Some(error),
            Self::Settings(error) => Some(error),
            Self::Validation { .. } => None,
        }
    }
}

pub fn select_client_config(config: Option<PathBuf>) -> Result<SelectedClientConfig, XdgPathError> {
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

pub fn resolve_client_settings_from_cli(
    config: Option<PathBuf>,
    runtime: ClientRuntimeArgs,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let selected_config =
        select_client_config(config).map_err(ClientSettingsResolutionError::XdgPath)?;
    resolve_selected_client_settings_with_default_identity_dir(
        selected_config,
        &runtime,
        &default_client_identity_material_dir,
    )
}

pub fn resolve_selected_client_settings(
    selected_config: SelectedClientConfig,
    runtime: &ClientRuntimeArgs,
    defaults: &ClientSettingsResolutionDefaults,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let default_identity_directory = || Ok(defaults.identity_directory.clone());
    resolve_selected_client_settings_with_default_identity_dir(
        selected_config,
        runtime,
        &default_identity_directory,
    )
}

fn resolve_selected_client_settings_with_default_identity_dir(
    selected_config: SelectedClientConfig,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    match selected_config {
        SelectedClientConfig::None => {
            resolve_cli_only_settings(None, runtime, default_identity_directory)
        }
        SelectedClientConfig::Explicit(path) | SelectedClientConfig::Discovered(path) => {
            resolve_selected_config_settings(path, runtime, default_identity_directory)
        }
    }
}

fn resolve_cli_only_settings(
    selected_path: Option<&Path>,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
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

    validate_resolved_client_settings(
        selected_path,
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
    )
}

fn resolve_selected_config_settings(
    path: PathBuf,
    runtime: &ClientRuntimeArgs,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let section_value = load_optional_selected_section_value(&path, "client")
        .map_err(ClientSettingsResolutionError::Settings)?;
    let Some(section_value) = section_value else {
        return resolve_cli_only_settings(Some(&path), runtime, default_identity_directory);
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

    validate_resolved_client_settings(Some(&path), raw, messages, default_identity_directory)
}

fn selected_service_block_count(section_value: &toml::Value) -> usize {
    section_value
        .as_table()
        .and_then(|client| client.get("services"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len)
}

fn validate_resolved_client_settings(
    selected_path: Option<&Path>,
    raw: RawClientConfig,
    messages: Vec<String>,
    default_identity_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let validation_path = selected_path.unwrap_or_else(|| Path::new("."));
    validate_client_settings_with_default_identity_dir(validation_path, raw, messages, || {
        default_identity_directory()
    })
    .map_err(|error| match (selected_path, error) {
        (
            None,
            SettingsError::Validation {
                messages,
                section: _,
                path: _,
            },
        ) => ClientSettingsResolutionError::Validation {
            path: None,
            messages,
        },
        (_, error) => ClientSettingsResolutionError::Settings(error),
    })
}
