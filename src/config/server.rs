use std::path::PathBuf;

pub use super::preparation::server::ServerRuntimeArgs;
pub use super::{
    ConfigFileError, ServerCertificateConfig, ServerConfig, ServerConfigResolutionError,
    ServerTunnelConfig, load_server_config, resolve_server_cert_hostname,
    resolve_server_cert_material_dir, resolve_server_cert_material_dir_from_config,
    resolve_server_hostname_from_config,
};

pub fn resolve_server_config_from_cli(
    config: Option<PathBuf>,
    runtime: ServerRuntimeArgs,
) -> Result<ServerConfig, ServerConfigResolutionError> {
    super::resolve_server_config_from_cli(config, runtime)
}
