use std::path::{Path, PathBuf};

use crate::XdgPathError;

pub(crate) mod client;
pub(crate) mod control;
pub(crate) mod material;
pub(crate) mod server;

pub(crate) use material::{MaterialDirectoryError, resolve_material_directory};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedValue<T> {
    Ready(T),
    Error(String),
}

impl<T> PreparedValue<T> {
    pub(crate) fn into_option(self, messages: &mut Vec<String>) -> Option<T> {
        match self {
            Self::Ready(value) => Some(value),
            Self::Error(message) => {
                messages.push(message);
                None
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedDirectory {
    Explicit(PathBuf),
    Defaulted(PreparedValue<PathBuf>),
}

pub(crate) fn resolve_path(config_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

pub(crate) fn resolve_default_path(
    default_path: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> PreparedValue<PathBuf> {
    match default_path() {
        Ok(path) => PreparedValue::Ready(path),
        Err(error) => PreparedValue::Error(error.to_string()),
    }
}

pub(crate) fn resolve_path_with_default(
    raw_path: Option<PathBuf>,
    config_dir: &Path,
    default_path: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> PreparedValue<PathBuf> {
    match raw_path {
        Some(path) => PreparedValue::Ready(resolve_path(config_dir, &path)),
        None => resolve_default_path(default_path),
    }
}

#[cfg(test)]
mod resolve_path_tests {
    use super::resolve_path;
    use std::path::PathBuf;

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
    fn preserves_absolute_paths() {
        assert_eq!(
            resolve_path(
                PathBuf::from("/tmp/runewarp").as_path(),
                PathBuf::from("/abs/server.crt").as_path()
            ),
            PathBuf::from("/abs/server.crt")
        );
    }
}
