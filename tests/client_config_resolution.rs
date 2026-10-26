use std::error::Error;
use std::fs;

use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME,
    ClientConfigResolutionDefaults, ClientConfigResolutionError, ClientPublicCertConfig,
    ClientRuntimeArgs, LogLevel, SelectedClientConfig, resolve_selected_client_config,
};
use tempfile::tempdir;

#[test]
fn effective_static_client_address_lists_are_limited_across_config_and_cli_paths()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let identity_directory = directory.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    let config_path = directory.path().join("client.toml");
    fs::write(
        &config_path,
        "[client]\nserver-address = \"configured.example.test\"\n",
    )?;
    let other_role_path = directory.path().join("server.toml");
    fs::write(
        &other_role_path,
        "[server]\nhostname = \"server.example.test\"\n",
    )?;
    let defaults = ClientConfigResolutionDefaults {
        identity_directory,
        public_cert_directory: directory.path().join("unused-public-cert"),
    };
    for selected in [
        SelectedClientConfig::None,
        SelectedClientConfig::Explicit(config_path.clone()),
        SelectedClientConfig::Discovered(config_path),
        SelectedClientConfig::Explicit(other_role_path),
    ] {
        for count in [256, 257] {
            let runtime = ClientRuntimeArgs {
                server_addresses: (0..count)
                    .map(|index| format!("Edge-{index}.Example.Test."))
                    .collect(),
                backend_address: Some("localhost:8443".to_owned()),
                control_address: None,
            };
            match resolve_selected_client_config(selected.clone(), &runtime, &defaults) {
                Ok(config) if count == 256 => {
                    assert_eq!(config.server_addresses.len(), 256);
                    assert_eq!(
                        config.server_addresses[255].hostname().as_str(),
                        "edge-255.example.test"
                    );
                }
                Ok(_) => panic!("{selected:?} must reject 257 effective static Server addresses"),
                Err(error) if count == 257 => {
                    let messages = error
                        .validation_messages()
                        .expect("an effective list exceeding the cap is a validation error");
                    assert!(
                        messages
                            .iter()
                            .any(|message| message.contains("client.server-addresses")
                                && message.contains("at most 256")
                                && message.contains("static")),
                        "{selected:?}: {error}"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

#[test]
fn runtime_server_address_overrides_replace_invalid_file_lists_before_validation()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let identity_directory = directory.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    let path = directory.path().join("client.toml");
    let defaults = ClientConfigResolutionDefaults {
        identity_directory,
        public_cert_directory: directory.path().join("unused-public-cert"),
    };
    let oversized = (0..257)
        .map(|index| format!("\"edge-{index}.example.test\""))
        .collect::<Vec<_>>()
        .join(",");
    for list in [
        "[]".to_owned(),
        r#"["invalid/address"]"#.to_owned(),
        format!("[{oversized}]"),
    ] {
        // Both raw address keys are present and invalid until runtime overrides replace them.
        fs::write(
            &path,
            format!("[client]\nserver-address = \"invalid/address\"\nserver-addresses = {list}\n"),
        )?;
        for addresses in [
            vec!["Primary.Example.Test.".to_owned()],
            vec![
                "Primary.Example.Test.".to_owned(),
                "backup.example.test:9443".to_owned(),
            ],
        ] {
            let config = resolve_selected_client_config(
                SelectedClientConfig::Explicit(path.clone()),
                &ClientRuntimeArgs {
                    server_addresses: addresses.clone(),
                    backend_address: Some("localhost:8443".to_owned()),
                    control_address: None,
                },
                &defaults,
            )?;
            assert_eq!(config.server_addresses.len(), addresses.len());
            assert_eq!(
                config.server_addresses[0].hostname().as_str(),
                "primary.example.test"
            );
            if addresses.len() == 2 {
                assert_eq!(config.server_addresses[1].port(), 9443);
            }
        }
    }
    Ok(())
}

#[test]
fn cli_only_resolution_uses_the_runtime_owned_client_retry_defaults() -> Result<(), Box<dyn Error>>
{
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_addresses: vec!["Tunnel.Example.Test.".to_owned()],
            backend_address: Some("localhost:8443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory: identity_directory.clone(),
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert_eq!(settings.log_level, LogLevel::Info);
    assert_eq!(settings.server_trust, runewarp::ClientServerTrust::System);
    assert_eq!(settings.identity_directory, identity_directory);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "localhost:8443");
    Ok(())
}

#[test]
fn cli_only_resolution_requires_backend_address_without_a_selected_config()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;

    let error = resolve_selected_client_config(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_addresses: vec!["tunnel.example.test".to_owned()],
            backend_address: None,
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )
    .expect_err("expected backend-address validation error");

    match error {
        ClientConfigResolutionError::Validation {
            path: None,
            messages,
        } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(
                messages[0],
                "--backend-address is required when no selected client config is available"
            );
        }
        other => panic!("expected a CLI-only validation error, got {other}"),
    }

    Ok(())
}

#[test]
fn cli_only_resolution_accepts_repeated_server_address_flags_without_a_selected_config()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_addresses: vec![
                "Tunnel.Example.Test.".to_owned(),
                "backup.example.test:9443".to_owned(),
            ],
            backend_address: Some("localhost:8443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_addresses.len(), 2);
    assert_eq!(
        settings.server_addresses[0].hostname().as_str(),
        "tunnel.example.test"
    );
    assert_eq!(settings.server_addresses[0].port(), 443);
    assert_eq!(
        settings.server_addresses[1].hostname().as_str(),
        "backup.example.test"
    );
    assert_eq!(settings.server_addresses[1].port(), 9443);
    Ok(())
}

#[test]
fn selected_config_without_a_client_section_can_still_resolve_from_runtime_flags()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
"#,
    )?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_addresses: vec!["tunnel.example.test:9443".to_owned()],
            backend_address: Some("backend.internal:443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.server_port, 9443);
    assert_eq!(settings.log_level, LogLevel::Info);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "backend.internal:443");
    Ok(())
}

#[test]
fn server_address_runtime_flag_overrides_a_selected_config_before_validation()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
log-level = "off"

[client]
"#,
    )?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_addresses: vec!["Tunnel.Example.Test.".to_owned()],
            backend_address: Some("backend.internal:443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert_eq!(settings.log_level, LogLevel::Off);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "backend.internal:443");
    Ok(())
}

#[test]
fn server_address_runtime_flag_rescues_an_invalid_selected_config_value()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
log-level = "off"

[client]
server-address = "127.0.0.1:443"
"#,
    )?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_addresses: vec!["Tunnel.Example.Test.".to_owned()],
            backend_address: Some("backend.internal:443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert_eq!(settings.log_level, LogLevel::Off);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "backend.internal:443");
    Ok(())
}

#[test]
fn repeated_server_address_runtime_flags_replace_either_config_target_shape()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
backend-address = "backend.internal:443"
"#,
    )?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_addresses: vec![
                "Tunnel.Example.Test.".to_owned(),
                "backup.example.test:9443".to_owned(),
            ],
            backend_address: None,
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_addresses.len(), 2);
    assert_eq!(
        settings.server_addresses[0].hostname().as_str(),
        "tunnel.example.test"
    );
    assert_eq!(settings.server_addresses[0].port(), 443);
    assert_eq!(
        settings.server_addresses[1].hostname().as_str(),
        "backup.example.test"
    );
    assert_eq!(settings.server_addresses[1].port(), 9443);
    Ok(())
}

#[test]
fn backend_address_runtime_flag_is_rejected_when_selected_config_already_has_services()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
backend-address = "backend.internal:443"
"#,
    )?;

    let error = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_addresses: Vec::new(),
            backend_address: Some("override.internal:8443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )
    .expect_err("expected backend-address conflict");

    let messages = error
        .validation_messages()
        .expect("selected config validation messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "--backend-address may be used only when the selected config contributes no [[client.services]] blocks"
    );
    Ok(())
}

#[test]
fn malformed_selected_services_are_not_masked_by_backend_address_runtime_flags()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
public-hostnames = ["app.example.test"]
"#,
    )?;

    let error = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_addresses: Vec::new(),
            backend_address: Some("override.internal:8443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )
    .expect_err("expected malformed service validation");

    let messages = error
        .validation_messages()
        .expect("selected config validation messages");
    assert!(messages.contains(
        &"--backend-address may be used only when the selected config contributes no [[client.services]] blocks"
            .to_owned()
    ));
    assert!(messages.contains(&"client.services[].backend-address is required".to_owned()));
    Ok(())
}

#[test]
fn cli_only_resolution_rejects_ip_literal_server_addresses() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;

    let error = resolve_selected_client_config(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_addresses: vec!["127.0.0.1:443".to_owned()],
            backend_address: Some("backend.internal:443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )
    .expect_err("expected IP literal validation");

    let messages = error
        .validation_messages()
        .expect("CLI-only validation messages");
    assert!(
        messages.contains(
            &"client.server-address is invalid: IP literals are not supported".to_owned()
        )
    );
    Ok(())
}

#[test]
fn selected_config_uses_the_injected_default_public_cert_dir_for_terminate_mode()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    let public_cert_directory = tempdir.path().join("xdg-data/client/public-cert");
    write_identity_material(&identity_directory)?;
    fs::create_dir_all(&public_cert_directory)?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "backend.internal:443"
tls-mode = "terminate"
"#,
    )?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs::default(),
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: public_cert_directory.clone(),
        },
    )?;

    assert!(matches!(
        settings.public_cert_config,
        Some(ClientPublicCertConfig::Manual { directory }) if directory == public_cert_directory
    ));
    Ok(())
}

fn write_identity_material(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(path)?;
    fs::write(path.join(CLIENT_CERT_FILENAME), "placeholder certificate")?;
    fs::write(path.join(CLIENT_KEY_FILENAME), "placeholder key")?;
    fs::write(
        path.join(CLIENT_IDENTITY_FILENAME),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )?;
    Ok(())
}
