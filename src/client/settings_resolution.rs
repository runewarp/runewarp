use std::fmt;
use std::path::{Path, PathBuf};

use crate::config_preparation::client::{
    PreparedClientConfig, prepare_client_settings_from_cli, prepare_selected_client_config,
};
use crate::settings::validate_prepared_client_settings;
use crate::{
    ClientSettings, SettingsError, XdgPathError, default_client_identity_material_dir,
    default_client_public_cert_material_dir,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientRuntimeArgs {
    pub server_address: Option<String>,
    pub backend_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSettingsResolutionDefaults {
    pub identity_directory: PathBuf,
    pub public_cert_directory: PathBuf,
}

impl ClientSettingsResolutionDefaults {
    pub fn from_xdg() -> Result<Self, XdgPathError> {
        Ok(Self {
            identity_directory: default_client_identity_material_dir()?,
            public_cert_directory: default_client_public_cert_material_dir()?,
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
    crate::config_preparation::client::select_client_config(config)
}

pub fn resolve_client_settings_from_cli(
    config: Option<PathBuf>,
    runtime: ClientRuntimeArgs,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let prepared = prepare_client_settings_from_cli(config, runtime)?;
    validate_resolved_client_settings(prepared)
}

pub fn resolve_selected_client_settings(
    selected_config: SelectedClientConfig,
    runtime: &ClientRuntimeArgs,
    defaults: &ClientSettingsResolutionDefaults,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let default_identity_directory = || Ok(defaults.identity_directory.clone());
    let default_public_cert_directory = || Ok(defaults.public_cert_directory.clone());
    let prepared = prepare_selected_client_config(
        selected_config,
        runtime,
        &default_identity_directory,
        &default_public_cert_directory,
    )?;
    validate_resolved_client_settings(prepared)
}

fn validate_resolved_client_settings(
    prepared: PreparedClientConfig,
) -> Result<ClientSettings, ClientSettingsResolutionError> {
    let selected_path = prepared.selected_path.clone();
    let validation_path = selected_path.as_deref().unwrap_or_else(|| Path::new("."));
    validate_prepared_client_settings(validation_path, prepared).map_err(|error| {
        match (selected_path.as_deref(), error) {
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
        }
    })
}
