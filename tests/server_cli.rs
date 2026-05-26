use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn server_help_prints_usage_and_subcommands() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["server", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("runewarp server"));
    assert!(stdout.contains("cert"));
    assert!(stdout.contains("--config"));
}

#[test]
fn server_uses_the_xdg_default_config_path_and_ignores_client_side_errors() {
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
hostname = "tunnel.example.test"
cert-dir = "cwd-ignored"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();
    fs::write(
        xdg_runewarp_dir.join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "missing-server"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[client]
retry-interval = 0
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(&current_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("server")
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("missing-server"));
    assert!(stderr.contains("runewarp server cert init"));
    assert!(!stderr.contains("cwd-ignored"));
    assert!(!stderr.contains("retry-interval"));
    assert!(!stderr.contains("--config"));
}

#[test]
fn server_uses_a_custom_config_path_when_requested() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "missing-server"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["server", "--config", "custom.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("missing-server"));
    assert!(stderr.contains("runewarp server cert init --config custom.toml"));
}

#[test]
fn server_reports_missing_material_files_with_a_recovery_hint() {
    let tempdir = tempdir().unwrap();
    fs::create_dir(tempdir.path().join("server-cert")).unwrap();
    fs::write(
        tempdir.path().join("server-cert/server.crt"),
        "placeholder certificate",
    )
    .unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["server", "--config", "custom.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("server-cert/server.key"));
    assert!(stderr.contains("server-cert/server-ca.crt"));
    assert!(stderr.contains("runewarp server cert init --config custom.toml"));
}

#[test]
fn server_uses_the_default_material_dir_when_config_omits_it() {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    fs::create_dir_all(xdg_config_home.join("runewarp")).unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args([
            "server",
            "cert",
            "init",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["server", "--config", "server.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("server.tunnels[].public-hostnames is required"));
    assert!(!stderr.contains("server.cert-dir"));
}

#[test]
fn server_does_not_create_the_default_acme_state_dir_when_validation_fails() {
    let tempdir = tempdir().unwrap();
    let xdg_state_home = tempdir.path().join("xdg-state");
    let default_state_dir = xdg_state_home.join("runewarp/server/acme");

    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.acme]
email = "admin@example.test"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_STATE_HOME", &xdg_state_home)
        .args(["server", "--config", "server.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("server.tunnels[].public-hostnames is required"));
    assert!(!stderr.contains("server.acme.state-dir"));
    assert!(!default_state_dir.exists());
}

#[test]
fn server_does_not_create_the_default_acme_state_dir_for_invalid_dual_mode_config() {
    let tempdir = tempdir().unwrap();
    let xdg_state_home = tempdir.path().join("xdg-state");
    let default_state_dir = xdg_state_home.join("runewarp/server/acme");

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--dir",
            "server-cert",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[server.acme]
email = "admin@example.test"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_STATE_HOME", &xdg_state_home)
        .args(["server", "--config", "server.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("[server.acme] and server.cert-dir are mutually exclusive"));
    assert!(!default_state_dir.exists());
}

#[test]
fn server_runtime_bind_failures_are_logged_as_runtime_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    let occupied_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let public_bind_address = occupied_listener.local_addr()?;

    Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--dir",
            "server-cert",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
public-bind-address = "{public_bind_address}"
tunnel-bind-address = "127.0.0.1:0"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#
        ),
    )?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .args(["server", "--config", "server.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("ERROR"));
    assert!(stderr.contains("failed to bind server.public-bind-address"));
    Ok(())
}
