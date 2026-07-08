use std::path::{Path, PathBuf};

use crate::config::preparation::{
    PreparedDirectory, PreparedValue, resolve_default_path, resolve_path, resolve_path_with_default,
};
use crate::config::{
    ConfigFileError, LogLevel, RawServerAcmeConfig, RawServerConfig, RawServerTunnelConfig,
    collect_server_unknown_field_messages, deserialize_selected_section, load_log_level_from_path,
    load_optional_selected_section_value,
};
use crate::{
    XdgPathError, default_config_path, default_server_acme_state_dir,
    default_server_cert_material_dir,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerRuntimeArgs {
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedServerConfig {
    pub(crate) hostname: Option<String>,
    pub(crate) log_level: LogLevel,
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
    pub(crate) client_identities: Option<Vec<String>>,
}

pub(crate) fn select_server_config_path(config: Option<PathBuf>) -> Result<PathBuf, XdgPathError> {
    select_server_config_path_with_default(config, default_config_path)
}

pub(crate) fn prepare_server_config_from_path(
    path: &Path,
) -> Result<PreparedServerConfig, ConfigFileError> {
    prepare_server_config_from_cli(path, ServerRuntimeArgs::default())
}

pub(crate) fn prepare_server_config_from_cli(
    path: &Path,
    runtime: ServerRuntimeArgs,
) -> Result<PreparedServerConfig, ConfigFileError> {
    let Some(section_value) = load_optional_selected_section_value(path, "server")? else {
        return Err(ConfigFileError::Validation {
            path: path.to_path_buf(),
            section: "server",
            messages: vec!["missing [server] section".to_owned()],
        });
    };
    let unknown_field_messages = collect_server_unknown_field_messages(&section_value);
    let mut raw = deserialize_selected_section::<RawServerConfig>(path, "server", &section_value)?;
    if runtime.hostname.is_some() {
        raw.hostname = runtime.hostname;
    }
    let log_level = load_log_level_from_path(path)?;
    Ok(prepare_raw_server_config(
        path,
        log_level,
        raw,
        unknown_field_messages,
    ))
}

fn prepare_raw_server_config(
    path: &Path,
    log_level: LogLevel,
    raw: RawServerConfig,
    unknown_field_messages: Vec<String>,
) -> PreparedServerConfig {
    prepare_raw_server_config_with_defaults(
        path,
        log_level,
        raw,
        unknown_field_messages,
        &default_server_cert_material_dir,
        &default_server_acme_state_dir,
    )
}

fn prepare_raw_server_config_with_defaults(
    path: &Path,
    log_level: LogLevel,
    raw: RawServerConfig,
    unknown_field_messages: Vec<String>,
    default_server_cert_directory: &dyn Fn() -> Result<PathBuf, XdgPathError>,
    default_server_acme_state_dir: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedServerConfig {
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let manual_cert_present = raw.cert_dir.is_some();
    let acme_present = raw.acme.is_some();

    PreparedServerConfig {
        hostname: raw.hostname,
        log_level,
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
                default_server_cert_directory,
            ))
        } else {
            None
        },
        acme: if acme_present && !manual_cert_present {
            raw.acme.map(|acme| {
                prepare_server_acme_config(acme, config_dir, default_server_acme_state_dir)
            })
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
    default_server_acme_state_dir: &dyn Fn() -> Result<PathBuf, XdgPathError>,
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
        client_identities: raw.client_identities,
    }
}

fn select_server_config_path_with_default(
    config: Option<PathBuf>,
    default_config_path: impl FnOnce() -> Result<PathBuf, XdgPathError>,
) -> Result<PathBuf, XdgPathError> {
    match config {
        Some(path) => Ok(path),
        None => default_config_path(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        PreparedDirectory, PreparedValue, ServerRuntimeArgs, prepare_server_config_from_cli,
        prepare_server_config_from_path,
    };
    use crate::config::{LogLevel, RawServerAcmeConfig, RawServerConfig, RawServerTunnelConfig};

    #[test]
    fn server_config_selection_prefers_the_explicit_path() -> Result<(), Box<dyn std::error::Error>>
    {
        let explicit = PathBuf::from("/tmp/explicit-server.toml");

        let selected =
            super::select_server_config_path_with_default(Some(explicit.clone()), || {
                Ok(PathBuf::from("/tmp/default-server.toml"))
            })?;

        assert_eq!(selected, explicit);
        Ok(())
    }

    #[test]
    fn server_config_selection_uses_the_default_path_when_omitted()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = super::select_server_config_path_with_default(None, || {
            Ok(PathBuf::from("/tmp/default-server.toml"))
        })?;

        assert_eq!(selected, PathBuf::from("/tmp/default-server.toml"));
        Ok(())
    }

    #[test]
    fn server_preparation_defaults_bind_addresses_and_resolves_manual_dir()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
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
        )?;

        let prepared = prepare_server_config_from_path(&tempdir.path().join("config.toml"))?;

        assert_eq!(prepared.hostname, Some("tunnel.example.test".to_owned()));
        assert_eq!(prepared.log_level, LogLevel::Info);
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
        Ok(())
    }

    #[test]
    fn server_preparation_overrides_hostname_from_runtime() -> Result<(), Box<dyn std::error::Error>>
    {
        let tempdir = tempdir()?;
        fs::write(
            tempdir.path().join("config.toml"),
            r#"
[server]
hostname = "configured.example.test"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
        )?;

        let prepared = prepare_server_config_from_cli(
            &tempdir.path().join("config.toml"),
            ServerRuntimeArgs {
                hostname: Some("overridden.example.test".to_owned()),
            },
        )?;

        assert_eq!(
            prepared.hostname,
            Some("overridden.example.test".to_owned())
        );
        Ok(())
    }

    #[test]
    fn server_preparation_uses_injected_xdg_defaults_for_manual_material_and_acme_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("config.toml");
        let default_cert_dir = tempdir.path().join("xdg-data/server/cert");
        let default_acme_state_dir = tempdir.path().join("xdg-state/server/acme");

        let manual = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Info,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: None,
                acme: None,
                public_bind_address: None,
                tunnel_bind_address: None,
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            &|| Ok(default_cert_dir.clone()),
            &|| Ok(default_acme_state_dir.clone()),
        );

        assert_eq!(
            manual.manual_certificate_directory,
            Some(PreparedValue::Ready(default_cert_dir))
        );
        assert_eq!(manual.public_bind_address, "0.0.0.0:443");
        assert_eq!(manual.tunnel_bind_address, "0.0.0.0:443");

        let acme = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Off,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: None,
                acme: Some(RawServerAcmeConfig {
                    email: Some("admin@example.test".to_owned()),
                    state_dir: None,
                }),
                public_bind_address: None,
                tunnel_bind_address: None,
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            &|| Ok(tempdir.path().join("unused-cert-dir")),
            &|| Ok(default_acme_state_dir.clone()),
        );

        assert_eq!(acme.log_level, LogLevel::Off);
        let prepared_acme = match acme.acme {
            Some(prepared_acme) => prepared_acme,
            None => panic!("expected prepared server acme config"),
        };
        assert_eq!(
            prepared_acme.state_directory,
            PreparedDirectory::Defaulted(PreparedValue::Ready(default_acme_state_dir))
        );
        Ok(())
    }

    #[test]
    fn server_preparation_resolves_relative_acme_state_dir_from_the_config_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempdir()?;
        let config_path = tempdir.path().join("nested").join("server.toml");

        let prepared = super::prepare_raw_server_config_with_defaults(
            &config_path,
            LogLevel::Off,
            RawServerConfig {
                hostname: Some("tunnel.example.test".to_owned()),
                cert_dir: None,
                acme: Some(RawServerAcmeConfig {
                    email: Some("admin@example.test".to_owned()),
                    state_dir: Some(PathBuf::from("acme-state")),
                }),
                public_bind_address: Some("127.0.0.1:8443".to_owned()),
                tunnel_bind_address: Some("127.0.0.1:9443".to_owned()),
                tunnels: vec![RawServerTunnelConfig {
                    public_hostnames: Some(vec!["app.example.test".to_owned()]),
                    client_identity: Some(
                        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                            .to_owned(),
                    ),
                    client_identities: None,
                }],
            },
            Vec::new(),
            &|| Ok(tempdir.path().join("unused-cert-dir")),
            &|| Ok(tempdir.path().join("unused-acme-state")),
        );

        assert_eq!(prepared.log_level, LogLevel::Off);
        assert_eq!(prepared.public_bind_address, "127.0.0.1:8443");
        assert_eq!(prepared.tunnel_bind_address, "127.0.0.1:9443");
        let prepared_acme = match prepared.acme {
            Some(prepared_acme) => prepared_acme,
            None => panic!("expected prepared server acme config"),
        };
        assert_eq!(
            prepared_acme.state_directory,
            PreparedDirectory::Explicit(tempdir.path().join("nested/acme-state"))
        );
        Ok(())
    }
}
