use std::fs;

use runewarp::{ClientTlsMode, load_client_settings};
use tempfile::tempdir;

#[test]
fn client_settings_accept_exact_match_services_and_default_logs_to_true() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "Tunnel.Example.Test."
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
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
fn client_settings_accept_server_address_with_default_port_and_flat_identity_dir() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "Tunnel.Example.Test."
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["App.Example.Test.", "api.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert_eq!(
        settings.identity_directory,
        tempdir.path().join("client-identity")
    );
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
fn client_settings_accept_server_address_with_an_explicit_port() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "Tunnel.Example.Test.:9443"
identity-dir = "client-identity"

[[client.services]]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.server_hostname, "tunnel.example.test");
    assert_eq!(settings.server_port, 9443);
}

#[test]
fn client_settings_reject_ip_literals_in_server_address() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "127.0.0.1:443"
identity-dir = "client-identity"

[[client.services]]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("client.server-address is invalid: IP literals are not supported")
    );
}

#[test]
fn client_settings_reject_invalid_ports_in_server_address() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test:65536"
identity-dir = "client-identity"

[[client.services]]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("client.server-address is invalid: port must be a valid u16")
    );
}

#[test]
fn client_settings_report_all_selected_mode_errors_together() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
identity-dir = "missing-client"
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

    assert!(message.contains("client.server-address is required"));
    assert!(message.contains("client.identity-dir directory not found"));
    assert!(message.contains("unknown field `reconnect-interval`"));
    assert!(message.contains(
        "client.services[].public-hostnames may be omitted only when there is exactly one service"
    ));
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
server-address = "tunnel.example.test"
identity-dir = "client-identity"
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
    assert!(message.contains("client.identity-dir directory not found"));
    assert!(message.contains("client.services[].backend-address is required"));
}

#[test]
fn client_settings_reject_server_ca_file_without_ca_file_trust_mode() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(tempdir.path().join("server-ca.pem"), "placeholder").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
server-ca-file = "server-ca.pem"
identity-dir = "client-identity"

[[client.services]]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error.to_string().contains(
            "client.server-ca-file may be set only when client.server-trust = \"ca-file\""
        )
    );
}

#[test]
fn client_settings_accept_ca_file_trust_with_an_explicit_server_ca_file() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(tempdir.path().join("server-ca.pem"), "placeholder").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-dir = "client-identity"

[[client.services]]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(
        settings.server_ca_file,
        Some(tempdir.path().join("server-ca.pem"))
    );
}

#[test]
fn client_settings_reject_duplicate_public_hostnames_after_normalization() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

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
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

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

#[test]
fn client_settings_report_duplicate_hostnames_even_when_another_hostname_is_invalid() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.key"),
        "placeholder",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["App.Example.Test."]
backend-address = "caddy.local:443"

[[client.services]]
public-hostnames = ["app.example.test", "*.bad.example.test"]
backend-address = "nginx.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(
        "client.services[].public-hostnames contains invalid hostname `*.bad.example.test`"
    ));
    assert!(message.contains(
        "client.services[].public-hostnames must be unique after normalization: app.example.test"
    ));
}

// ── Slice 1: tls-mode field on services ──────────────────────────────────────

fn write_base_client_identity(tempdir: &std::path::Path) {
    fs::create_dir(tempdir.join("client-identity")).unwrap();
    fs::write(tempdir.join("client-identity/client.crt"), "placeholder").unwrap();
    fs::write(tempdir.join("client-identity/client.key"), "placeholder").unwrap();
    fs::write(
        tempdir.join("client-identity/client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();
}

#[test]
fn client_settings_default_tls_mode_is_passthrough() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.services[0].tls_mode, ClientTlsMode::Passthrough);
}

#[test]
fn client_settings_accept_explicit_passthrough_tls_mode() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "passthrough"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.services[0].tls_mode, ClientTlsMode::Passthrough);
}

#[test]
fn client_settings_reject_unknown_tls_mode_value() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "proxy"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("client.services[].tls-mode must be \"passthrough\" or \"terminate\""),
        "unexpected error: {error}"
    );
}

// ── Slice 2: catch-all cannot opt into termination ───────────────────────────

#[test]
fn client_settings_reject_terminate_on_catch_all_service() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("certs")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"
public-cert-dir = "certs"

[[client.services]]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error.to_string().contains(
            "client.services[].tls-mode = \"terminate\" requires explicit public-hostnames"
        ),
        "unexpected error: {error}"
    );
}

// ── Slice 3: terminating service requires a Client public-cert config ─────────

#[test]
fn client_settings_reject_terminate_without_any_cert_config() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error.to_string().contains(
            "client.public-cert-dir or [client.acme] is required when any service uses tls-mode = \"terminate\""
        ),
        "unexpected error: {error}"
    );
}

// ── Slice 4: client.public-cert-dir validation ────────────────────────────────

#[test]
fn client_settings_accept_terminate_with_public_cert_dir() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("certs")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"
public-cert-dir = "certs"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.services[0].tls_mode, ClientTlsMode::Terminate);
    assert!(
        matches!(
            &settings.public_cert_config,
            Some(runewarp::ClientPublicCertConfig::Manual { directory }) if *directory == tempdir.path().join("certs")
        ),
        "expected Manual cert config, got {:?}",
        settings.public_cert_config
    );
}

#[test]
fn client_settings_reject_public_cert_dir_not_found() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"
public-cert-dir = "missing-certs"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("client.public-cert-dir directory not found"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_settings_reject_public_cert_dir_without_any_terminating_service() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("certs")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"
public-cert-dir = "certs"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error.to_string().contains(
            "client.public-cert-dir and [client.acme] require at least one service with tls-mode = \"terminate\""
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn client_settings_reject_acme_without_any_terminating_service() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[client.acme]
email = "admin@example.test"
state-dir = "acme-state"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error.to_string().contains(
            "client.public-cert-dir and [client.acme] require at least one service with tls-mode = \"terminate\""
        ),
        "unexpected error: {error}"
    );
}

// ── Slice 5: [client.acme] validation ────────────────────────────────────────

#[test]
fn client_settings_accept_terminate_with_acme_and_explicit_state_dir() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[client.acme]
email = "admin@example.test"
state-dir = "acme-state"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let settings = load_client_settings(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.services[0].tls_mode, ClientTlsMode::Terminate);
    assert!(
        matches!(
            &settings.public_cert_config,
            Some(runewarp::ClientPublicCertConfig::Acme { email, .. }) if email == "admin@example.test"
        ),
        "expected ACME cert config, got {:?}",
        settings.public_cert_config
    );
}

#[test]
fn client_settings_reject_acme_without_email() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[client.acme]
state-dir = "acme-state"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error.to_string().contains("client.acme.email is required"),
        "unexpected error: {error}"
    );
}

#[test]
fn client_settings_reject_acme_state_dir_not_found() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[client.acme]
email = "admin@example.test"
state-dir = "missing-acme-state"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("client.acme.state-dir directory not found"),
        "unexpected error: {error}"
    );
}

// ── Slice 6: mutual exclusion of cert config modes ───────────────────────────

#[test]
fn client_settings_reject_both_public_cert_dir_and_acme() {
    let tempdir = tempdir().unwrap();
    write_base_client_identity(tempdir.path());
    fs::create_dir(tempdir.path().join("certs")).unwrap();
    fs::create_dir(tempdir.path().join("acme-state")).unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"
public-cert-dir = "certs"

[client.acme]
email = "admin@example.test"
state-dir = "acme-state"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "caddy.local:443"
"#,
    )
    .unwrap();

    let error = load_client_settings(&tempdir.path().join("config.toml")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("[client.acme] and client.public-cert-dir are mutually exclusive"),
        "unexpected error: {error}"
    );
}
