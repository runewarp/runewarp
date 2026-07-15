use std::fmt;
use std::path::{Path, PathBuf};

use crate::config::ConfigFileError;
use crate::{XdgPathError, default_config_path};

/// Shared material-directory resolution for certificate and identity commands.
///
/// Precedence: explicit CLI directory, then an explicit configured path from a
/// selected config file, then the XDG default.
pub(crate) fn resolve_material_directory(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
    configured_dir: impl FnOnce(&Path) -> Result<Option<PathBuf>, ConfigFileError>,
    default_dir: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> Result<PathBuf, MaterialDirectoryError> {
    resolve_material_directory_with_candidate(
        config,
        directory,
        candidate_config_path,
        configured_dir,
        default_dir,
    )
}

pub(crate) fn resolve_material_directory_with_candidate(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
    candidate_path: impl FnOnce(Option<PathBuf>) -> Option<PathBuf>,
    configured_dir: impl FnOnce(&Path) -> Result<Option<PathBuf>, ConfigFileError>,
    default_dir: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> Result<PathBuf, MaterialDirectoryError> {
    if let Some(directory) = directory {
        return Ok(directory);
    }

    if let Some(config_path) = candidate_path(config)
        && let Some(configured_dir) = configured_dir(&config_path)?
    {
        return Ok(configured_dir);
    }

    default_dir().map_err(MaterialDirectoryError::XdgPath)
}

/// Selects an optional config path for material commands: explicit `--config`,
/// otherwise the default path when that file already exists.
pub(crate) fn candidate_config_path(config: Option<PathBuf>) -> Option<PathBuf> {
    match config {
        Some(config) => Some(config),
        None => default_config_path()
            .ok()
            .filter(|default_config_path| default_config_path.is_file()),
    }
}

#[derive(Debug)]
pub enum MaterialDirectoryError {
    ConfigFile(ConfigFileError),
    XdgPath(XdgPathError),
}

impl fmt::Display for MaterialDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigFile(error) => write!(formatter, "{error}"),
            Self::XdgPath(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for MaterialDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigFile(error) => Some(error),
            Self::XdgPath(error) => Some(error),
        }
    }
}

impl From<ConfigFileError> for MaterialDirectoryError {
    fn from(error: ConfigFileError) -> Self {
        Self::ConfigFile(error)
    }
}

impl From<XdgPathError> for MaterialDirectoryError {
    fn from(error: XdgPathError) -> Self {
        Self::XdgPath(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{candidate_config_path, resolve_material_directory};
    use crate::config::ConfigFileError;
    use std::path::PathBuf;

    #[test]
    fn material_directory_prefers_explicit_cli_directory() {
        let resolved = resolve_material_directory(
            Some(PathBuf::from("/tmp/config.toml")),
            Some(PathBuf::from("/tmp/cli-dir")),
            |_| panic!("configured dir should not be consulted"),
            || panic!("default dir should not be consulted"),
        )
        .expect("cli directory");

        assert_eq!(resolved, PathBuf::from("/tmp/cli-dir"));
    }

    #[test]
    fn material_directory_uses_configured_path_when_present() {
        let config_path = PathBuf::from("/tmp/config.toml");
        let configured = PathBuf::from("/tmp/configured-dir");
        let resolved = resolve_material_directory(
            Some(config_path.clone()),
            None,
            |path| {
                assert_eq!(path, config_path);
                Ok(Some(configured.clone()))
            },
            || panic!("default dir should not be consulted"),
        )
        .expect("configured directory");

        assert_eq!(resolved, configured);
    }

    #[test]
    fn material_directory_falls_back_to_xdg_when_config_omits_key() {
        let default_dir = PathBuf::from("/tmp/xdg-dir");
        let resolved = resolve_material_directory(
            Some(PathBuf::from("/tmp/config.toml")),
            None,
            |_| Ok(None),
            || Ok(default_dir.clone()),
        )
        .expect("xdg directory");

        assert_eq!(resolved, default_dir);
    }

    #[test]
    fn material_directory_falls_back_to_xdg_when_no_candidate_config() {
        let default_dir = PathBuf::from("/tmp/xdg-dir");
        let resolved = super::resolve_material_directory_with_candidate(
            None,
            None,
            |_| None,
            |_| panic!("configured dir should not be consulted without a candidate"),
            || Ok(default_dir.clone()),
        )
        .expect("xdg directory");

        assert_eq!(resolved, default_dir);
    }

    #[test]
    fn material_directory_surfaces_config_projection_errors() {
        let error = resolve_material_directory(
            Some(PathBuf::from("/tmp/config.toml")),
            None,
            |_| {
                Err(ConfigFileError::Validation {
                    path: PathBuf::from("/tmp/config.toml"),
                    section: "server",
                    messages: vec!["unknown field `bad`".to_owned()],
                })
            },
            || panic!("default dir should not be consulted"),
        )
        .expect_err("projection error");

        assert!(error.to_string().contains("unknown field `bad`"));
    }

    #[test]
    fn candidate_config_path_prefers_explicit_path() {
        let explicit = PathBuf::from("/tmp/explicit.toml");
        assert_eq!(
            candidate_config_path(Some(explicit.clone())),
            Some(explicit)
        );
    }
}
