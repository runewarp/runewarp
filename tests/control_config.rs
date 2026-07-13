use std::fs;
use std::path::Path;

use runewarp::{
    ControlTrust, LogLevel, ServerCertificateConfig, ServerConfigResolutionError,
    ServerRuntimeArgs, initialize_manual_server_certificate, load_server_config,
    resolve_server_config_from_cli,
};
use tempfile::tempdir;

mod common;

fn write_managed_server_material(
    base: &Path,
    cert_dir: &str,
    identity_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    initialize_manual_server_certificate(&base.join(cert_dir), "tunnel.example.test")?;
    common::write_server_identity_material(&base.join(identity_dir));
    Ok(())
}

#[test]
fn server_loads_managed_config_with_control_identity_and_empty_tunnels() {
    let tempdir = tempdir().unwrap();
    write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"
trust = "system"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();

    assert_eq!(settings.log_level, LogLevel::Info);
    assert!(settings.tunnels.is_empty());
    let control = settings.control.expect("managed server control config");
    assert_eq!(control.address.to_string(), "control.example.test");
    assert_eq!(control.trust, ControlTrust::System);
    let identity = settings.identity.expect("managed server identity config");
    assert_eq!(identity.directory, tempdir.path().join("server-identity"));
    assert!(!identity.identity.to_string().is_empty());
    assert_eq!(
        settings.certificate,
        ServerCertificateConfig::Manual {
            directory: tempdir.path().join("server-cert"),
        }
    );
}

#[test]
fn unknown_control_keys_are_rejected() {
    let tempdir = tempdir().unwrap();
    write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"
unexpected = true

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("unknown field `unexpected`"));
}

#[test]
fn invalid_control_addresses_are_rejected() {
    let cases = [
        ("https://control.example.test", "scheme"),
        ("control.example.test/v1", "path"),
        ("127.0.0.1", "IP"),
    ];

    for (address, label) in cases {
        let tempdir = tempdir().unwrap();
        write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
        fs::write(
            tempdir.path().join("config.toml"),
            format!(
                r#"
[control]
address = "{address}"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#
            ),
        )
        .unwrap();

        let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("control.address is invalid"),
            "expected invalid control address for {label}, got: {message}"
        );
    }
}

#[test]
fn managed_server_rejects_tunnels() {
    let tempdir = tempdir().unwrap();
    write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"

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
            .contains("[[server.tunnels]] may not be configured in managed mode")
    );
}

#[test]
fn static_server_rejects_identity_dir() {
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
identity-dir = "server-identity"

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
            .contains("server.identity-dir may be set only in managed mode")
    );
}

#[test]
fn identity_dir_and_cert_dir_must_differ() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-cert"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    assert!(error.to_string().contains(
        "server.identity-dir must resolve to a different directory than server.cert-dir"
    ));
}

#[test]
fn identity_key_fingerprint_mismatch_is_rejected() {
    let tempdir = tempdir().unwrap();
    initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )
    .unwrap();
    let identity_dir = tempdir.path().join("server-identity");
    common::write_server_identity_material(&identity_dir);
    fs::write(
        identity_dir.join("server-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )
    .unwrap();

    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("server identity material is invalid")
    );
}

#[test]
fn control_ca_file_trust_defaults_and_resolves_relative_paths() {
    let tempdir = tempdir().unwrap();
    write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
    fs::create_dir_all(tempdir.path().join("trust")).unwrap();
    fs::write(tempdir.path().join("trust/control-ca.pem"), "ca").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"
trust = "ca-file"
ca-file = "trust/control-ca.pem"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#,
    )
    .unwrap();

    let settings = load_server_config(&tempdir.path().join("config.toml")).unwrap();
    let control = settings.control.expect("control config");
    assert_eq!(
        control.trust,
        ControlTrust::CaFile(tempdir.path().join("trust/control-ca.pem"))
    );
}

#[test]
fn control_ca_file_is_rejected_with_system_trust() {
    let tempdir = tempdir().unwrap();
    write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
address = "control.example.test"
trust = "system"
ca-file = "trust/control-ca.pem"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("control.ca-file may be set only when control.trust = \"ca-file\"")
    );
}

#[test]
fn present_control_without_address_is_rejected_unless_cli_overrides() {
    let tempdir = tempdir().unwrap();
    write_managed_server_material(tempdir.path(), "server-cert", "server-identity").unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[control]
trust = "system"

[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
identity-dir = "server-identity"
"#,
    )
    .unwrap();

    let error = load_server_config(&tempdir.path().join("config.toml")).unwrap_err();
    assert!(error.to_string().contains("control.address is required"));

    let settings = resolve_server_config_from_cli(
        Some(tempdir.path().join("config.toml")),
        ServerRuntimeArgs {
            control_address: Some("control.example.test".to_owned()),
            ..ServerRuntimeArgs::default()
        },
    )
    .expect("CLI control address should satisfy managed config");
    assert_eq!(
        settings
            .control
            .expect("control config")
            .address
            .to_string(),
        "control.example.test"
    );
    assert!(matches!(
        resolve_server_config_from_cli(
            Some(tempdir.path().join("config.toml")),
            ServerRuntimeArgs::default(),
        ),
        Err(ServerConfigResolutionError::ConfigFile(_))
    ));
}
