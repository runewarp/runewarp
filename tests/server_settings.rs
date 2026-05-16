use std::fs;

use rcgen::generate_simple_self_signed;
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
hostnames = ["app.example.test"]
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
    assert!(message.contains("phase-2 server mode only supports a Catch-all Tunnel"));
    assert!(message.contains("server.tunnels[].client-public-key-fingerprint is invalid"));
}

#[test]
fn server_settings_reject_invalid_manual_tls_material_during_validation() {
    let tempdir = tempdir().unwrap();
    let server_cert = generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let mismatched_key =
        generate_simple_self_signed(vec!["other.example.test".to_owned()]).unwrap();
    fs::write(tempdir.path().join("server.crt"), server_cert.cert.pem()).unwrap();
    fs::write(
        tempdir.path().join("server.key"),
        mismatched_key.signing_key.serialize_pem(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-file = "server.crt"
key-file = "server.key"

[[server.tunnels]]
client-public-key-fingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server TLS material is invalid"));
}
