use std::fs;

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn server_uses_the_default_config_path_and_ignores_client_side_errors() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "missing-server"

[[server.tunnels]]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[client]
retry-interval = 0
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .arg("server")
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("missing-server"));
    assert!(!stderr.contains("retry-interval"));
}

#[test]
fn server_uses_a_custom_config_path_when_requested() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        r#"
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "missing-server"

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
}
