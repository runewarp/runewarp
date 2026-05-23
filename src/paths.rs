use std::env;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XdgDirectory {
    Config,
    Data,
    State,
}

impl XdgDirectory {
    fn env_var(self) -> &'static str {
        match self {
            Self::Config => "XDG_CONFIG_HOME",
            Self::Data => "XDG_DATA_HOME",
            Self::State => "XDG_STATE_HOME",
        }
    }

    fn fallback_suffix(self) -> &'static str {
        match self {
            Self::Config => ".config",
            Self::Data => ".local/share",
            Self::State => ".local/state",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Data => "data",
            Self::State => "state",
        }
    }
}

#[derive(Debug)]
pub struct XdgPathError {
    directory: XdgDirectory,
}

impl fmt::Display for XdgPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unable to resolve the XDG {} base directory: set {} or HOME",
            self.directory.label(),
            self.directory.env_var()
        )
    }
}

impl std::error::Error for XdgPathError {}

pub fn default_config_path() -> Result<PathBuf, XdgPathError> {
    Ok(runewarp_dir(XdgDirectory::Config)?.join("config.toml"))
}

pub fn default_client_identity_material_dir() -> Result<PathBuf, XdgPathError> {
    Ok(runewarp_dir(XdgDirectory::Data)?
        .join("client")
        .join("identity"))
}

pub fn default_client_server_ca_path() -> Result<PathBuf, XdgPathError> {
    Ok(runewarp_dir(XdgDirectory::Data)?
        .join("client")
        .join("server-ca.crt"))
}

pub fn default_server_cert_material_dir() -> Result<PathBuf, XdgPathError> {
    Ok(runewarp_dir(XdgDirectory::Data)?
        .join("server")
        .join("cert"))
}

pub fn default_server_acme_state_dir() -> Result<PathBuf, XdgPathError> {
    Ok(runewarp_dir(XdgDirectory::State)?
        .join("server")
        .join("acme"))
}

fn runewarp_dir(directory: XdgDirectory) -> Result<PathBuf, XdgPathError> {
    Ok(xdg_base_dir(directory)?.join("runewarp"))
}

fn xdg_base_dir(directory: XdgDirectory) -> Result<PathBuf, XdgPathError> {
    if let Some(path) = env::var_os(directory.env_var()).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) else {
        return Err(XdgPathError { directory });
    };

    Ok(PathBuf::from(home).join(directory.fallback_suffix()))
}
