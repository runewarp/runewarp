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
fn client_uses_the_default_identity_material_dir_when_config_omits_it() {
    let tempdir = tempdir().unwrap();
    let xdg_data_home = tempdir.path().join("xdg-data");

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
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
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "--config", "client.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("at least one [[client.services]] entry is required"));
    assert!(!stderr.contains("identity-dir"));
}
