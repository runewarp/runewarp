use std::fs;

use runewarp::load_client_settings;
use tempfile::tempdir;

#[test]
fn client_settings_accept_exact_match_services_and_default_logs_to_true() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(tempdir.path().join("client-identity/client.crt"), "placeholder").unwrap();
    fs::write(tempdir.path().join("client-identity/client.key"), "placeholder").unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-hostname = "Tunnel.Example.Test."
identity-directory = "client-identity"

[[client.services]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert!(settings.logs);
    assert_eq!(
        settings.services[0].public_hostnames,
        Some(vec![
            "app.example.test".to_owned(),
            "api.example.test".to_owned(),
        ])
    );
}

#[test]
fn client_settings_report_all_selected_mode_errors_together() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
reconnect-interval = 0

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local"

[[client.services]]
backend-address = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("client.server-hostname is required"));
    assert!(message.contains("client.identity-directory is required"));
    assert!(message.contains("client.reconnect-interval must be at least 1"));
    assert!(
        message.contains("client.services[].public-hostnames may be omitted only when there is exactly one service")
    );
    assert!(
        message
            .contains("client.services[].backend-address must be a TCP address or host:port pair")
    );
}

#[test]
fn client_settings_reject_the_legacy_flat_client_surface() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
cert-file = "client.crt"
key-file = "client.key"

[[client.services]]
local-addr = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(!message.contains("failed to parse [client]"));
    assert!(message.contains("unknown field `cert-file`"));
    assert!(message.contains("unknown field `key-file`"));
    assert!(message.contains("unknown field `local-addr`"));
    assert!(message.contains("client.identity-directory is required"));
    assert!(message.contains("client.services[].backend-address is required"));
}

#[test]
fn client_settings_reject_duplicate_public_hostnames_after_normalization() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(tempdir.path().join("client-identity/client.crt"), "placeholder").unwrap();
    fs::write(tempdir.path().join("client-identity/client.key"), "placeholder").unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
identity-directory = "client-identity"

[[client.services]]
public-hostnames = ["App.Example.Test."]
backend-address = "caddy.local:443"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "nginx.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains(
        "client.services[].public-hostnames must be unique after normalization: app.example.test"
    ));
}

#[test]
fn client_settings_reject_empty_public_hostname_lists() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(tempdir.path().join("client-identity/client.crt"), "placeholder").unwrap();
    fs::write(tempdir.path().join("client-identity/client.key"), "placeholder").unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
identity-directory = "client-identity"

[[client.services]]
public-hostnames = []
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("client.services[].public-hostnames must not be empty")
    );
}
