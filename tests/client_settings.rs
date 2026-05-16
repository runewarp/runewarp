use std::fs;

use runewarp::load_client_settings;
use tempfile::tempdir;

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
    assert!(message.contains("phase-2 client mode requires exactly one Catch-all Service"));
    assert!(message.contains("phase-2 client mode only supports a Catch-all Service"));
    assert!(
        message.contains("client.services[].backend-address must be a TCP address or host:port pair")
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
retry-interval = 5

[[client.services]]
local-addr = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse [client]"));
    assert!(message.contains("unknown field `cert-file`"));
}
