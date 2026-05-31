use std::path::{Path, PathBuf};

pub use super::{
    ConfigFileError, ServerCertificateConfig, ServerConfig, ServerConfigResolutionError,
    ServerTunnelConfig, load_server_config as load_config,
    resolve_server_cert_material_dir_from_config as resolve_cert_material_dir_from_config,
    resolve_server_hostname_from_config as resolve_hostname_from_config,
};

pub fn resolve_config_from_cli(
    config: Option<PathBuf>,
) -> Result<ServerConfig, ServerConfigResolutionError> {
    super::resolve_server_config_from_cli(config)
}

pub fn load_config_from_path(path: &Path) -> Result<ServerConfig, ConfigFileError> {
    load_config(path)
}
