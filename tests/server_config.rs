use std::fs;

use rcgen::generate_simple_self_signed;
use runewarp::{
    LogLevel, ServerCertificateConfig, initialize_manual_server_certificate, load_server_config,
};
use tempfile::tempdir;

fn hostname_strings(hostnames: &[runewarp::PublicHostname]) -> Vec<&str> {
    hostnames.iter().map(|hostname| hostname.as_str()).collect()
}

#[test]
fn server_config_accept_exact_match_tunnels_and_default_logs_to_true() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.log_level, LogLevel::Info);
    assert_eq!(
        hostname_strings(&settings.tunnels[0].public_hostnames),
        vec!["app.example.test", "api.example.test"]
    );
    assert_eq!(
        settings.tunnels[0]
            .authorized_client_identities
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"]
    );
}

#[test]
fn server_config_accept_plural_client_identities() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
client-identities = [
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
]
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(
        settings.tunnels[0]
            .authorized_client_identities
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
        ]
    );
}

#[test]
fn server_config_accept_flat_cert_dir_and_default_to_manual_mode() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.log_level, LogLevel::Info);
    assert_eq!(
        settings.certificate,
        ServerCertificateConfig::Manual {
            directory: tempdir.path().join("server-cert"),
        }
    );
    assert_eq!(settings.public_bind_address, "0.0.0.0:443".parse().unwrap());
    assert_eq!(
        settings.tunnel_connection_bind_address,
        "0.0.0.0:443".parse().unwrap()
    );
    assert_eq!(
        hostname_strings(&settings.tunnels[0].public_hostnames),
        vec!["app.example.test", "api.example.test"]
    );
}

#[test]
fn server_config_accept_explicit_listener_bind_addresses() {
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
cert-dir = "server-cert"
public-bind-address = "127.0.0.1:8443"
tunnel-bind-address = "127.0.0.1:9443"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(
        settings.public_bind_address,
        "127.0.0.1:8443".parse().unwrap()
    );
    assert_eq!(
        settings.tunnel_connection_bind_address,
        "127.0.0.1:9443".parse().unwrap()
    );
    assert_eq!(settings.readiness_bind_address, None);
    assert_eq!(
        settings.graceful_shutdown_duration,
        std::time::Duration::from_secs(60)
    );
}

#[test]
fn server_config_accepts_readiness_bind_address_and_graceful_shutdown_duration() {
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
cert-dir = "server-cert"
readiness-bind-address = "127.0.0.1:9000"
graceful-shutdown-duration = "45s"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(
        settings.readiness_bind_address,
        Some("127.0.0.1:9000".parse().unwrap())
    );
    assert_eq!(
        settings.graceful_shutdown_duration,
        std::time::Duration::from_secs(45)
    );
}

#[test]
fn server_config_accept_top_level_log_level() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
log-level = "debug"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.log_level, LogLevel::Debug);
}

#[test]
fn server_config_reject_legacy_server_logs_as_an_unknown_field() {
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
cert-dir = "server-cert"
logs = false

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(!message.contains("failed to parse [server]"));
    assert!(message.contains("unknown field `logs`"));
}

#[test]
fn server_config_reject_non_literal_listener_bind_addresses() {
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
cert-dir = "server-cert"
public-bind-address = "public.example.test:443"
tunnel-bind-address = "tunnel.example.test:443"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("server.public-bind-address is invalid"));
    assert!(message.contains("server.tunnel-bind-address is invalid"));
    assert!(!message.contains("failed to parse [server]"));
}

#[test]
fn server_config_rejects_invalid_readiness_bind_address_and_shutdown_duration() {
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
cert-dir = "server-cert"
readiness-bind-address = "readiness.example.test:9000"
graceful-shutdown-duration = "abc"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("server.readiness-bind-address is invalid"));
    assert!(message.contains("server.graceful-shutdown-duration is invalid"));
}

#[test]
fn server_config_report_all_selected_mode_errors_together() {
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

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("server.hostname is required"));
    assert!(message.contains("server.cert-dir directory not found"));
    assert!(message.contains("server.tunnels[].client-identity is invalid"));
    assert!(message.contains("server.tunnels[].public-hostnames is required"));
}

#[test]
fn server_config_reject_acme_and_cert_dir_together() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[server.acme]
email = "admin@example.test"
state-dir = "acme-state"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("[server.acme] and server.cert-dir are mutually exclusive")
    );
}

#[test]
fn server_config_reject_invalid_manual_tls_material_during_validation() {
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
cert-dir = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server TLS material is invalid"));
}

#[test]
fn server_config_require_the_manual_server_ca_certificate() {
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
cert-dir = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server-ca.crt"));
}

#[test]
fn server_config_reject_manual_tls_material_for_the_wrong_server_hostname() {
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
cert-dir = "server-cert"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains("server TLS material is invalid"));
}

#[test]
fn server_config_reject_the_legacy_flat_server_surface() {
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

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(!message.contains("failed to parse [server]"));
    assert!(message.contains("unknown field `cert-file`"));
    assert!(message.contains("unknown field `key-file`"));
    assert!(message.contains("unknown field `client-public-key-fingerprint`"));
    assert!(message.contains("server.cert-dir directory not found"));
    assert!(message.contains(
        "one of server.tunnels[].client-identity or server.tunnels[].client-identities is required"
    ));
}

#[test]
fn server_config_require_the_acme_state_directory_to_exist() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.acme]
email = "admin@example.test"
state-dir = "missing-acme-state"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("server.acme.state-dir directory not found")
    );
}

#[test]
fn server_config_reject_duplicate_public_hostnames_and_server_hostname_reuse() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test."]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[[server.tunnels]]
public-hostnames = ["app.example.test", "tunnel.example.test"]
client-identity = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(
        "server.tunnels[].public-hostnames must be unique after normalization: app.example.test"
    ));
    assert!(message.contains(
        "server.tunnels[].public-hostnames must not include server.hostname `tunnel.example.test`"
    ));
}

#[test]
fn server_config_report_duplicate_hostnames_even_when_another_hostname_is_invalid() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["App.Example.Test."]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[[server.tunnels]]
public-hostnames = ["app.example.test", "*.bad.example.test"]
client-identity = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(
        "server.tunnels[].public-hostnames contains invalid hostname `*.bad.example.test`"
    ));
    assert!(message.contains(
        "server.tunnels[].public-hostnames must be unique after normalization: app.example.test"
    ));
}

#[test]
fn server_config_reject_empty_public_hostname_lists() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = []
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("server.tunnels[].public-hostnames must not be empty")
    );
}

#[test]
fn server_config_reject_duplicate_client_identities() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[[server.tunnels]]
public-hostnames = ["api.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("authorized Client identities must be unique across all Server Tunnels")
    );
}

#[test]
fn server_config_requires_one_authorized_client_identity_shape() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains(
        "one of server.tunnels[].client-identity or server.tunnels[].client-identities is required"
    ));
}

#[test]
fn server_config_reject_singular_and_plural_client_identity_keys_together() {
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
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
client-identities = ["111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"]
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(error.to_string().contains(
        "server.tunnels[].client-identity and server.tunnels[].client-identities are mutually exclusive"
    ));
}
