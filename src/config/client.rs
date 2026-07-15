use std::fmt;
use std::path::{Path, PathBuf};

use super::preparation::client::{
    PreparedClientConfig, prepare_client_config_from_cli, prepare_selected_client_config,
};
pub use super::{
    ClientConfig, ClientPublicCertConfig, ClientTlsMode, ConfigFileError, ServiceConfig,
    load_client_config, resolve_client_identity_material_dir,
    resolve_client_identity_material_dir_from_config, resolve_client_public_cert_material_dir,
    resolve_client_public_cert_material_dir_from_config, resolve_terminating_hostnames_from_config,
};
use crate::XdgPathError;
use crate::{default_client_identity_material_dir, default_client_public_cert_material_dir};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientRuntimeArgs {
    pub server_addresses: Vec<String>,
    pub backend_address: Option<String>,
    pub control_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfigResolutionDefaults {
    pub identity_directory: PathBuf,
    pub public_cert_directory: PathBuf,
}

impl ClientConfigResolutionDefaults {
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
pub enum ClientConfigResolutionError {
    XdgPath(XdgPathError),
    ConfigFile(ConfigFileError),
    Validation {
        path: Option<PathBuf>,
        messages: Vec<String>,
    },
}

impl ClientConfigResolutionError {
    pub fn validation_messages(&self) -> Option<&[String]> {
        match self {
            Self::ConfigFile(ConfigFileError::Validation { messages, .. }) => Some(messages),
            Self::Validation { messages, .. } => Some(messages),
            Self::XdgPath(_)
            | Self::ConfigFile(ConfigFileError::Read { .. } | ConfigFileError::Parse { .. }) => {
                None
            }
        }
    }

    pub fn selected_config_path(&self) -> Option<&Path> {
        match self {
            Self::ConfigFile(ConfigFileError::Read { path, .. })
            | Self::ConfigFile(ConfigFileError::Parse { path, .. })
            | Self::ConfigFile(ConfigFileError::Validation { path, .. }) => Some(path.as_path()),
            Self::Validation {
                path: Some(path), ..
            } => Some(path.as_path()),
            Self::XdgPath(_) | Self::Validation { path: None, .. } => None,
        }
    }
}

impl fmt::Display for ClientConfigResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XdgPath(error) => write!(formatter, "{error}"),
            Self::ConfigFile(error) => write!(formatter, "{error}"),
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
                formatter.write_str("invalid client config:")?;
                for message in messages {
                    write!(formatter, "\n- {message}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ClientConfigResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::XdgPath(error) => Some(error),
            Self::ConfigFile(error) => Some(error),
            Self::Validation { .. } => None,
        }
    }
}

pub fn select_client_config(config: Option<PathBuf>) -> Result<SelectedClientConfig, XdgPathError> {
    super::preparation::client::select_client_config(config)
}

pub fn resolve_client_config_from_cli(
    config: Option<PathBuf>,
    runtime: ClientRuntimeArgs,
) -> Result<ClientConfig, ClientConfigResolutionError> {
    let prepared = prepare_client_config_from_cli(config, runtime)?;
    validate_resolved_client_config(prepared)
}

pub fn resolve_selected_client_config(
    selected_config: SelectedClientConfig,
    runtime: &ClientRuntimeArgs,
    defaults: &ClientConfigResolutionDefaults,
) -> Result<ClientConfig, ClientConfigResolutionError> {
    let default_identity_directory = || Ok(defaults.identity_directory.clone());
    let default_public_cert_directory = || Ok(defaults.public_cert_directory.clone());
    let prepared = prepare_selected_client_config(
        selected_config,
        runtime,
        &default_identity_directory,
        &default_public_cert_directory,
    )?;
    validate_resolved_client_config(prepared)
}

fn validate_resolved_client_config(
    prepared: PreparedClientConfig,
) -> Result<ClientConfig, ClientConfigResolutionError> {
    let selected_path = prepared.selected_path.clone();
    let validation_path = selected_path.as_deref().unwrap_or_else(|| Path::new("."));
    super::validate_prepared_client_config(validation_path, prepared).map_err(|error| {
        match (selected_path.as_deref(), error) {
            (
                None,
                ConfigFileError::Validation {
                    messages,
                    section: _,
                    path: _,
                },
            ) => ClientConfigResolutionError::Validation {
                path: None,
                messages,
            },
            (_, error) => ClientConfigResolutionError::ConfigFile(error),
        }
    })
}
