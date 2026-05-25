use std::fs;
use std::path::Path;

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn client_public_cert_init_writes_all_artifacts_to_the_requested_directory() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "client-public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    assert_exists(tempdir.path().join("client-public-cert/public-ca.crt").as_path());
    assert_exists(tempdir.path().join("client-public-cert/state/public-ca.key").as_path());
    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/server.crt")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/server.key")
            .as_path(),
    );
}

#[test]
fn client_public_cert_init_normalizes_hostname_in_subdirectory() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "client-public-cert",
            "--hostname",
            "App.Example.Test.",
        ])
        .assert()
        .success();

    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/server.crt")
            .as_path(),
    );
}

#[test]
fn client_public_cert_init_writes_pem_artifacts_and_reports_output() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "client-public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    let ca_pem =
        fs::read_to_string(tempdir.path().join("client-public-cert/public-ca.crt")).unwrap();
    let leaf_cert_pem = fs::read_to_string(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/server.crt"),
    )
    .unwrap();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(leaf_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(stdout.contains("public-ca.crt"));
    assert!(stdout.contains("90 days"));
}

#[test]
fn client_public_cert_init_refuses_to_overwrite_existing_artifacts() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "client-public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "client-public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .failure();
}

#[test]
fn client_public_cert_init_requires_hostname() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "client-public-cert",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("--hostname") || stderr.contains("hostname"));
}

#[test]
fn client_public_cert_init_uses_the_xdg_default_directory_when_dir_is_omitted() {
    let tempdir = tempdir().unwrap();
    let xdg_data_home = tempdir.path().join("xdg-data");

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args([
            "client",
            "public-cert",
            "init",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    assert_exists(
        xdg_data_home
            .join("runewarp/client/public-cert/public-ca.crt")
            .as_path(),
    );
    assert_exists(
        xdg_data_home
            .join("runewarp/client/public-cert/app.example.test/server.crt")
            .as_path(),
    );
}

#[test]
fn client_public_cert_init_uses_configured_dir_when_config_is_provided() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/public-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
public-cert-dir = "configured/public-cert"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--config",
            "client.toml",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    assert_exists(configured_dir.join("public-ca.crt").as_path());
    assert_exists(configured_dir.join("app.example.test/server.crt").as_path());
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist after `runewarp client public-cert init`",
        path.display()
    );
}

#[test]
fn client_public_cert_second_init_with_different_hostname_succeeds() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "public-cert",
            "--hostname",
            "api.example.test",
        ])
        .assert()
        .success();

    assert_exists(
        tempdir
            .path()
            .join("public-cert/api.example.test/server.crt")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("public-cert/api.example.test/server.key")
            .as_path(),
    );
}

#[test]
fn client_public_cert_second_init_keeps_ca_cert_stable() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    let ca_pem_before = fs::read(tempdir.path().join("public-cert/public-ca.crt")).unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "init",
            "--dir",
            "public-cert",
            "--hostname",
            "api.example.test",
        ])
        .assert()
        .success();

    let ca_pem_after = fs::read(tempdir.path().join("public-cert/public-ca.crt")).unwrap();

    assert_eq!(
        ca_pem_before, ca_pem_after,
        "public-ca.crt must not change on second init with a different hostname"
    );
}
