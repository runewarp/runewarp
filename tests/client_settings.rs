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
retry-interval = 0

[[client.services]]
hostnames = ["app.example.test"]
local-addr = "caddy.local"

[[client.services]]
local-addr = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("client.server-hostname is required"));
    assert!(message.contains("client.cert-file is required"));
    assert!(message.contains("client.key-file is required"));
    assert!(message.contains("client.retry-interval must be at least 1"));
    assert!(message.contains("phase-2 client mode requires exactly one Catch-all Service"));
    assert!(message.contains("phase-2 client mode only supports a Catch-all Service"));
    assert!(
        message.contains("client.services[].local-addr must be a TCP address or host:port pair")
    );
}
