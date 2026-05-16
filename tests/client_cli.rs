use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn client_uses_the_default_config_path_and_ignores_server_side_errors() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
acme = {}

[client]
server-hostname = "tunnel.example.test"
cert-file = "missing-client.crt"
key-file = "missing-client.key"

[[client.services]]
local-addr = "127.0.0.1:443"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .arg("client")
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("missing-client.crt"));
    assert!(!stderr.contains("acme"));
}

#[test]
fn client_uses_a_custom_config_path_when_requested() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        r#"
[client]
server-hostname = "tunnel.example.test"
cert-file = "missing-client.crt"
key-file = "missing-client.key"

[[client.services]]
local-addr = "127.0.0.1:443"
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
    assert!(stderr.contains("missing-client.crt"));
}
