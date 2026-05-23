use std::fmt;
use std::path::{Path, PathBuf};

use crate::{XdgPathError, default_client_server_ca_path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientServerTrust {
    System,
    CaFile(PathBuf),
}

#[derive(Debug)]
pub enum ResolveClientServerTrustError {
    InvalidMode { value: String },
    UnexpectedServerCaFile,
    DefaultCaPath(XdgPathError),
}

impl fmt::Display for ResolveClientServerTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMode { value } => write!(
                formatter,
                "client.server-trust must be one of `system` or `ca-file`, got `{value}`"
            ),
            Self::UnexpectedServerCaFile => formatter.write_str(
                "client.server-ca-file may be set only when client.server-trust = \"ca-file\"",
            ),
            Self::DefaultCaPath(source) => write!(formatter, "{source}"),
        }
    }
}

impl std::error::Error for ResolveClientServerTrustError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DefaultCaPath(source) => Some(source),
            Self::InvalidMode { .. } | Self::UnexpectedServerCaFile => None,
        }
    }
}

pub fn resolve_client_server_trust(
    trust_mode: Option<&str>,
    server_ca_file: Option<PathBuf>,
    config_dir: &Path,
) -> Result<ClientServerTrust, ResolveClientServerTrustError> {
    resolve_client_server_trust_with_default(
        trust_mode,
        server_ca_file,
        config_dir,
        default_client_server_ca_path,
    )
}

fn resolve_client_server_trust_with_default(
    trust_mode: Option<&str>,
    server_ca_file: Option<PathBuf>,
    config_dir: &Path,
    default_ca_path: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> Result<ClientServerTrust, ResolveClientServerTrustError> {
    let trust_mode = match trust_mode.unwrap_or("system") {
        "system" => ClientServerTrustMode::System,
        "ca-file" => ClientServerTrustMode::CaFile,
        value => {
            return Err(ResolveClientServerTrustError::InvalidMode {
                value: value.to_owned(),
            });
        }
    };

    match trust_mode {
        ClientServerTrustMode::System => {
            if server_ca_file.is_some() {
                return Err(ResolveClientServerTrustError::UnexpectedServerCaFile);
            }
            Ok(ClientServerTrust::System)
        }
        ClientServerTrustMode::CaFile => Ok(ClientServerTrust::CaFile(match server_ca_file {
            Some(server_ca_file) => resolve_path(config_dir, &server_ca_file),
            None => default_ca_path().map_err(ResolveClientServerTrustError::DefaultCaPath)?,
        })),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientServerTrustMode {
    System,
    CaFile,
}

fn resolve_path(config_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        ClientServerTrust, ResolveClientServerTrustError, resolve_client_server_trust_with_default,
    };

    #[test]
    fn defaults_to_system_trust() {
        let trust = resolve_client_server_trust_with_default(
            None,
            None,
            PathBuf::from("/tmp/runewarp").as_path(),
            || Ok(PathBuf::from("/unused/server-ca.crt")),
        )
        .unwrap();

        assert_eq!(trust, ClientServerTrust::System);
    }

    #[test]
    fn ca_file_trust_uses_the_default_ca_path_when_no_explicit_file_is_set() {
        let trust = resolve_client_server_trust_with_default(
            Some("ca-file"),
            None,
            PathBuf::from("/tmp/runewarp").as_path(),
            || Ok(PathBuf::from("/xdg-data/runewarp/client/server-ca.crt")),
        )
        .unwrap();

        assert_eq!(
            trust,
            ClientServerTrust::CaFile(PathBuf::from("/xdg-data/runewarp/client/server-ca.crt"))
        );
    }

    #[test]
    fn ca_file_trust_resolves_relative_paths_from_the_config_directory() {
        let trust = resolve_client_server_trust_with_default(
            Some("ca-file"),
            Some(PathBuf::from("server-ca.pem")),
            PathBuf::from("/tmp/runewarp").as_path(),
            || Ok(PathBuf::from("/unused/server-ca.crt")),
        )
        .unwrap();

        assert_eq!(
            trust,
            ClientServerTrust::CaFile(PathBuf::from("/tmp/runewarp/server-ca.pem"))
        );
    }

    #[test]
    fn system_trust_rejects_server_ca_files() {
        let error = resolve_client_server_trust_with_default(
            Some("system"),
            Some(PathBuf::from("server-ca.pem")),
            PathBuf::from("/tmp/runewarp").as_path(),
            || Ok(PathBuf::from("/unused/server-ca.crt")),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ResolveClientServerTrustError::UnexpectedServerCaFile
        ));
    }

    #[test]
    fn rejects_unknown_trust_modes() {
        let error = resolve_client_server_trust_with_default(
            Some("hybrid"),
            None,
            PathBuf::from("/tmp/runewarp").as_path(),
            || Ok(PathBuf::from("/unused/server-ca.crt")),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ResolveClientServerTrustError::InvalidMode { value } if value == "hybrid"
        ));
    }
}
