use std::fs;
use std::time::Duration;

use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientRuntimeArgs,
    ClientSettingsResolutionDefaults, ClientSettingsResolutionError,
    DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS, SelectedClientConfig, resolve_selected_client_settings,
};
use tempfile::tempdir;

#[test]
fn cli_only_resolution_builds_a_catch_all_service_without_a_selected_config() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);

    let settings = resolve_selected_client_settings(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_address: Some("Tunnel.Example.Test.".to_owned()),
            backend_address: Some("caddy.local:443".to_owned()),
        },
        &ClientSettingsResolutionDefaults {
            identity_directory: identity_directory.clone(),
        },
    )
    .unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert!(settings.logs);
    assert_eq!(settings.server_ca_file, None);
    assert_eq!(settings.identity_directory, identity_directory);
    assert_eq!(
        settings.reconnect_interval,
        Duration::from_secs(DEFAULT_CLIENT_RECONNECT_INTERVAL_SECS)
    );
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "caddy.local:443");
}

#[test]
fn cli_only_resolution_requires_backend_address_without_a_selected_config() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);

    let error = resolve_selected_client_settings(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_address: Some("tunnel.example.test".to_owned()),
            backend_address: None,
        },
        &ClientSettingsResolutionDefaults { identity_directory },
    )
    .unwrap_err();

    match error {
        ClientSettingsResolutionError::Validation {
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
}

#[test]
fn selected_config_without_a_client_section_can_still_resolve_from_runtime_flags() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
"#,
    )
    .unwrap();

    let settings = resolve_selected_client_settings(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_address: Some("tunnel.example.test:9443".to_owned()),
            backend_address: Some("backend.internal:443".to_owned()),
        },
        &ClientSettingsResolutionDefaults { identity_directory },
    )
    .unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert_eq!(settings.server_port, 9443);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "backend.internal:443");
}

#[test]
fn server_address_runtime_flag_overrides_a_selected_config_before_validation() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
logs = false
"#,
    )
    .unwrap();

    let settings = resolve_selected_client_settings(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_address: Some("Tunnel.Example.Test.".to_owned()),
            backend_address: Some("backend.internal:443".to_owned()),
        },
        &ClientSettingsResolutionDefaults { identity_directory },
    )
    .unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert!(!settings.logs);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].public_hostnames, None);
    assert_eq!(settings.services[0].backend_address, "backend.internal:443");
}

#[test]
fn backend_address_runtime_flag_is_rejected_when_selected_config_already_has_services() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
backend-address = "backend.internal:443"
"#,
    )
    .unwrap();

    let error = resolve_selected_client_settings(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_address: None,
            backend_address: Some("override.internal:8443".to_owned()),
        },
        &ClientSettingsResolutionDefaults { identity_directory },
    )
    .unwrap_err();

    let messages = error
        .validation_messages()
        .expect("selected config validation messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0],
        "--backend-address may be used only when the selected config contributes no [[client.services]] blocks"
    );
}

#[test]
fn malformed_selected_services_are_not_masked_by_backend_address_runtime_flags() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
public-hostnames = ["app.example.test"]
"#,
    )
    .unwrap();

    let error = resolve_selected_client_settings(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &ClientRuntimeArgs {
            server_address: None,
            backend_address: Some("override.internal:8443".to_owned()),
        },
        &ClientSettingsResolutionDefaults { identity_directory },
    )
    .unwrap_err();

    let messages = error
        .validation_messages()
        .expect("selected config validation messages");
    assert!(messages.contains(
        &"--backend-address may be used only when the selected config contributes no [[client.services]] blocks"
            .to_owned()
    ));
    assert!(messages.contains(&"client.services[].backend-address is required".to_owned()));
}

#[test]
fn cli_only_resolution_rejects_ip_literal_server_addresses() {
    let tempdir = tempdir().unwrap();
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory);

    let error = resolve_selected_client_settings(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_address: Some("127.0.0.1:443".to_owned()),
            backend_address: Some("backend.internal:443".to_owned()),
        },
        &ClientSettingsResolutionDefaults { identity_directory },
    )
    .unwrap_err();

    let messages = error
        .validation_messages()
        .expect("CLI-only validation messages");
    assert!(
        messages.contains(
            &"client.server-address is invalid: IP literals are not supported".to_owned()
        )
    );
}

fn write_identity_material(path: &std::path::Path) {
    fs::create_dir_all(path).unwrap();
    fs::write(path.join(CLIENT_CERT_FILENAME), "placeholder certificate").unwrap();
    fs::write(path.join(CLIENT_KEY_FILENAME), "placeholder key").unwrap();
    fs::write(
        path.join(CLIENT_IDENTITY_FILENAME),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
}
