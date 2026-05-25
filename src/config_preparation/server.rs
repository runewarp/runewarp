use std::path::{Path, PathBuf};

use crate::config_preparation::{
    PreparedDirectory, PreparedValue, resolve_default_path, resolve_path, resolve_path_with_default,
};
use crate::settings::{
    RawServerAcmeConfig, RawServerConfig, RawServerTunnelConfig, SettingsError,
    collect_server_unknown_field_messages, deserialize_selected_section,
    load_optional_selected_section_value,
};
use crate::{default_server_acme_state_dir, default_server_cert_material_dir};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerConfig {
    pub(crate) hostname: Option<String>,
    pub(crate) logs: bool,
    pub(crate) public_bind_address: String,
    pub(crate) tunnel_bind_address: String,
    pub(crate) manual_cert_present: bool,
    pub(crate) acme_present: bool,
    pub(crate) manual_certificate_directory: Option<PreparedValue<PathBuf>>,
    pub(crate) acme: Option<PreparedServerAcmeConfig>,
    pub(crate) tunnels: Vec<PreparedServerTunnelConfig>,
    pub(crate) unknown_field_messages: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerAcmeConfig {
    pub(crate) email: Option<String>,
    pub(crate) state_directory: PreparedDirectory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerTunnelConfig {
    pub(crate) public_hostnames: Option<Vec<String>>,
    pub(crate) client_identity: Option<String>,
}

pub(crate) fn prepare_server_config_from_path(
    path: &Path,
) -> Result<PreparedServerConfig, SettingsError> {
    let Some(section_value) = load_optional_selected_section_value(path, "server")? else {
        return Err(SettingsError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages: vec!["missing [server] section".to_owned()],
        });
    };
    let unknown_field_messages = collect_server_unknown_field_messages(&section_value);
    let raw = deserialize_selected_section::<RawServerConfig>(path, "server", &section_value)?;
    Ok(prepare_raw_server_config(path, raw, unknown_field_messages))
}

fn prepare_raw_server_config(
    path: &Path,
    raw: RawServerConfig,
    unknown_field_messages: Vec<String>,
) -> PreparedServerConfig {
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let manual_cert_present = raw.cert_dir.is_some();
    let acme_present = raw.acme.is_some();

    PreparedServerConfig {
        hostname: raw.hostname,
        logs: raw.logs.unwrap_or(true),
        public_bind_address: raw
            .public_bind_address
            .unwrap_or_else(|| "0.0.0.0:443".to_owned()),
        tunnel_bind_address: raw
            .tunnel_bind_address
            .unwrap_or_else(|| "0.0.0.0:443".to_owned()),
        manual_cert_present,
        acme_present,
        manual_certificate_directory: if !acme_present {
            Some(resolve_path_with_default(
                raw.cert_dir,
                config_dir,
                default_server_cert_material_dir,
            ))
        } else {
            None
        },
        acme: if acme_present && !manual_cert_present {
            raw.acme
                .map(|acme| prepare_server_acme_config(acme, config_dir))
        } else {
            None
        },
        tunnels: raw.tunnels.into_iter().map(prepare_server_tunnel).collect(),
        unknown_field_messages,
    }
}

fn prepare_server_acme_config(
    raw: RawServerAcmeConfig,
    config_dir: &Path,
) -> PreparedServerAcmeConfig {
    PreparedServerAcmeConfig {
        email: raw.email,
        state_directory: match raw.state_dir {
            Some(state_directory) => {
                PreparedDirectory::Explicit(resolve_path(config_dir, &state_directory))
            }
            None => {
                PreparedDirectory::Defaulted(resolve_default_path(default_server_acme_state_dir))
            }
        },
    }
}

fn prepare_server_tunnel(raw: RawServerTunnelConfig) -> PreparedServerTunnelConfig {
    PreparedServerTunnelConfig {
        public_hostnames: raw.public_hostnames,
        client_identity: raw.client_identity,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{PreparedValue, prepare_server_config_from_path};

    #[test]
    fn server_preparation_defaults_bind_addresses_and_resolves_manual_dir() {
        let tempdir = tempdir().unwrap();
        fs::write(
            tempdir.path().join("config.toml"),
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
        )
        .unwrap();

        let prepared =
            prepare_server_config_from_path(&tempdir.path().join("config.toml")).unwrap();

        assert_eq!(prepared.hostname, Some("tunnel.example.test".to_owned()));
        assert!(prepared.logs);
        assert_eq!(prepared.public_bind_address, "0.0.0.0:443");
        assert_eq!(prepared.tunnel_bind_address, "0.0.0.0:443");
        assert!(prepared.manual_cert_present);
        assert!(!prepared.acme_present);
        assert_eq!(
            prepared.manual_certificate_directory,
            Some(PreparedValue::Ready(tempdir.path().join("server-cert")))
        );
        assert_eq!(
            prepared.tunnels[0].public_hostnames,
            Some(vec!["app.example.test".to_owned()])
        );
    }
}
