use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn client_help_prints_usage_and_subcommands() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("runewarp client"));
    assert!(stdout.contains("identity"));
    assert!(stdout.contains("--config"));
}

#[test]
fn client_help_shows_the_config_shorthand() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("-c, --config <PATH>"));
}

#[test]
fn client_help_includes_examples_and_default_config_guidance() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("runewarp client"));
    assert!(
        stdout
            .contains("Commands use the default Runewarp config path unless -c, --config is set.")
    );
}

#[test]
fn client_help_subcommand_prints_client_help() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage: runewarp client [OPTIONS] [COMMAND]"));
    assert!(stdout.contains("Examples:"));
}

#[test]
fn client_help_lists_runtime_only_routing_flags() -> Result<(), Box<dyn std::error::Error>> {
    let assert = Command::cargo_bin("runewarp")?
        .args(["client", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.contains("--server-address"));
    assert!(stdout.contains("--backend-address"));
    Ok(())
}

#[test]
fn client_uses_the_xdg_default_config_path_and_ignores_server_side_errors() {
    let tempdir = tempdir().unwrap();
    let current_dir = tempdir.path().join("cwd");
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_runewarp_dir = xdg_config_home.join("runewarp");
    fs::create_dir(&current_dir).unwrap();
    fs::create_dir_all(&xdg_runewarp_dir).unwrap();
    fs::write(
        current_dir.join("config.toml"),
        r#"
[server]
acme = {}

[client]
server-address = "tunnel.example.test"
identity-dir = "cwd-ignored"

[[client.services]]
backend-address = "127.0.0.1:443"
"#,
    )
    .unwrap();
    fs::write(
        xdg_runewarp_dir.join("config.toml"),
        r#"
[server]
acme = {}

[client]
server-address = "tunnel.example.test"
identity-dir = "missing-client"

[[client.services]]
backend-address = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(&current_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("client")
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("missing-client"));
    assert!(stderr.contains("runewarp client identity init"));
    assert!(!stderr.contains("cwd-ignored"));
    assert!(!stderr.contains("acme"));
    assert!(!stderr.contains("--config"));
}

#[test]
fn client_uses_a_custom_config_path_when_requested() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "missing-client"

[[client.services]]
backend-address = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "--config", "custom.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("missing-client"));
    assert!(stderr.contains("runewarp client identity init --config custom.toml"));
}

#[test]
fn client_reports_missing_identity_files_with_a_recovery_hint() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder certificate",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "client-identity"

[[client.services]]
backend-address = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "--config", "custom.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("client-identity/client.key"));
    assert!(stderr.contains("client-identity/client-identity.txt"));
    assert!(stderr.contains("runewarp client identity init --config custom.toml"));
}

#[test]
fn client_uses_the_default_identity_material_dir_when_config_omits_it() {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    fs::create_dir_all(xdg_config_home.join("runewarp")).unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "identity", "init"])
        .assert()
        .success();

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "--config", "client.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("at least one [[client.services]] entry is required"));
    assert!(!stderr.contains("identity-dir"));
}

#[test]
fn client_can_use_runtime_flags_without_a_discovered_config()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    fs::create_dir_all(xdg_config_home.join("runewarp"))?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args([
            "client",
            "--server-address",
            "tunnel.example.test",
            "--backend-address",
            "127.0.0.1:443",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("client.identity-dir directory not found"));
    assert!(stderr.contains("runewarp client identity init"));
    assert!(!stderr.contains("failed to read"));
    Ok(())
}

#[test]
fn discovered_config_remains_authoritative_when_runtime_flags_are_present()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    let xdg_runewarp_dir = xdg_config_home.join("runewarp");
    fs::create_dir_all(&xdg_runewarp_dir)?;
    fs::write(
        xdg_runewarp_dir.join("config.toml"),
        r#"
[client]
identity-dir = "missing-client"
"#,
    )?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args([
            "client",
            "--server-address",
            "tunnel.example.test",
            "--backend-address",
            "127.0.0.1:443",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("missing-client"));
    assert!(stderr.contains("runewarp client identity init"));
    assert!(!stderr.contains("failed to read"));
    Ok(())
}

#[test]
fn explicit_missing_config_path_remains_a_hard_error_even_with_runtime_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .args([
            "client",
            "--config",
            "missing.toml",
            "--server-address",
            "tunnel.example.test",
            "--backend-address",
            "127.0.0.1:443",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("failed to read missing.toml"));
    assert!(!stderr.contains("runewarp client identity init"));
    Ok(())
}

#[test]
fn explicit_missing_config_path_still_wins_when_xdg_data_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .env_remove("HOME")
        .env_remove("XDG_DATA_HOME")
        .args([
            "client",
            "--config",
            "missing.toml",
            "--server-address",
            "tunnel.example.test",
            "--backend-address",
            "127.0.0.1:443",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("failed to read missing.toml"));
    assert!(!stderr.contains("unable to resolve the XDG data base directory"));
    Ok(())
}

#[test]
fn configured_identity_dir_still_wins_when_xdg_data_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "missing-client"

[[client.services]]
backend-address = "127.0.0.1:443"
"#,
    )?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .env_remove("HOME")
        .env_remove("XDG_DATA_HOME")
        .args(["client", "--config", "client.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("missing-client"));
    assert!(!stderr.contains("unable to resolve the XDG data base directory"));
    Ok(())
}

#[test]
fn client_auto_creates_the_default_acme_state_dir_after_validation_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    let xdg_state_home = tempdir.path().join("xdg-state");
    let default_state_dir = xdg_state_home.join("runewarp/client/acme");

    Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();
    fs::write(tempdir.path().join("server-ca.pem"), "not a certificate")?;

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "localhost"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-dir = "client-identity"

[client.acme]
email = "admin@example.test"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:443"
tls-mode = "terminate"
"#,
    )?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .env("XDG_STATE_HOME", &xdg_state_home)
        .args(["client", "--config", "client.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(!stderr.contains("client.acme.state-dir"));
    assert!(default_state_dir.is_dir());
    Ok(())
}
