use std::fs;

use rcgen::generate_simple_self_signed;
use runewarp::{initialize_manual_server_certificate, load_server_settings};
use tempfile::tempdir;

#[test]
fn server_settings_accept_exact_match_tunnels_and_default_logs_to_true() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "Tunnel.Example.Test."

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.hostname, "tunnel.example.test");
    assert!(settings.logs);
    assert_eq!(
        settings.tunnels[0].public_hostnames,
        vec!["app.example.test", "api.example.test"]
    );
}

#[test]
fn server_settings_report_all_selected_mode_errors_together() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "not-lowercase-hex"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("server.hostname is required"));
    assert!(message.contains("exactly one of [server.cert] or [server.acme] must be configured"));
    assert!(message.contains("server.tunnels[].client-identity is invalid"));
    assert!(message.contains("server.tunnels[].public-hostnames is required"));
}

#[test]
fn server_settings_reject_invalid_manual_tls_material_during_validation() {
    let tempdir = tempdir().unwrap();
    let mismatched_key =
        generate_simple_self_signed(vec!["other.example.test".to_owned()]).unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("server-cert/server.key"),
        mismatched_key.signing_key.serialize_pem(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server TLS material is invalid"));
}

#[test]
fn server_settings_require_the_manual_server_ca_certificate() {
    let tempdir = tempdir().unwrap();
    let server_cert = generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    fs::create_dir(tempdir.path().join("server-cert")).unwrap();
    fs::write(
        tempdir.path().join("server-cert/server.crt"),
        server_cert.cert.pem(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("server-cert/server.key"),
        server_cert.signing_key.serialize_pem(),
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server-ca.crt"));
}

#[test]
fn server_settings_reject_manual_tls_material_for_the_wrong_server_hostname() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "other.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server TLS material is invalid"));
}

#[test]
fn server_settings_reject_the_legacy_flat_server_surface() {
    let tempdir = tempdir().unwrap();
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
    let message = error.to_string();

    assert!(!message.contains("failed to parse [server]"));
    assert!(message.contains("unknown field `cert-file`"));
    assert!(message.contains("unknown field `key-file`"));
    assert!(message.contains("unknown field `client-public-key-fingerprint`"));
    assert!(message.contains("exactly one of [server.cert] or [server.acme] must be configured"));
    assert!(message.contains("server.tunnels[].client-identity is required"));
}

#[test]
fn server_settings_require_the_acme_state_directory_to_exist() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.acme]
email = "admin@example.test"
state-directory = "missing-acme-state"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("server.acme.state-directory directory not found")
    );
}

#[test]
fn server_settings_reject_duplicate_public_hostnames_and_server_hostname_reuse() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test."]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[[server.tunnels]]
public-hostnames = ["app.example.test", "tunnel.example.test"]
client-identity = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(
        "server.tunnels[].public-hostnames must be unique after normalization: app.example.test"
    ));
    assert!(message.contains(
        "server.tunnels[].public-hostnames must not include server.hostname `tunnel.example.test`"
    ));
}

#[test]
fn server_settings_report_duplicate_hostnames_even_when_another_hostname_is_invalid() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test."]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[[server.tunnels]]
public-hostnames = ["app.example.test", "*.bad.example.test"]
client-identity = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(
        "server.tunnels[].public-hostnames contains invalid hostname `*.bad.example.test`"
    ));
    assert!(message.contains(
        "server.tunnels[].public-hostnames must be unique after normalization: app.example.test"
    ));
}

#[test]
fn server_settings_reject_empty_public_hostname_lists() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = []
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("server.tunnels[].public-hostnames must not be empty")
    );
}

#[test]
fn server_settings_reject_duplicate_client_identities() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[[server.tunnels]]
public-hostnames = ["api.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("server.tunnels[].client-identity must be unique")
    );
}
