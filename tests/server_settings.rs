use std::fs;

use runewarp::load_server_settings;
use tempfile::tempdir;

#[test]
fn server_settings_report_all_selected_mode_errors_together() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]

[[server.tunnels]]
client-public-key-fingerprint = "not-lowercase-hex"

[[server.tunnels]]
client-public-key-fingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("server.hostname is required"));
    assert!(message.contains("server.cert-file is required"));
    assert!(message.contains("server.key-file is required"));
    assert!(message.contains("phase-2 server mode requires exactly one Catch-all Tunnel"));
}
