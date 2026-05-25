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

    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/public-ca.crt")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/state/public-ca.key")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/public.crt")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/public.key")
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
            .join("client-public-cert/app.example.test/public.crt")
            .as_path(),
    );
}

#[test]
fn client_public_cert_init_writes_public_named_leaf_files() {
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

    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/public.crt")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/public.key")
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
            .join("client-public-cert/app.example.test/public.crt"),
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
fn client_public_cert_init_requires_hostname_or_config() {
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
    assert!(
        stderr.contains("--hostname") || stderr.contains("config"),
        "expected error mentioning --hostname or config, got: {stderr}"
    );
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
            .join("runewarp/client/public-cert/app.example.test/public.crt")
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
    assert_exists(configured_dir.join("app.example.test/public.crt").as_path());
}

#[test]
fn client_public_cert_init_without_hostname_uses_configured_terminating_hostnames() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/public-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
public-cert-dir = "configured/public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:3000"
tls-mode = "terminate"

[[client.services]]
public-hostnames = ["api.example.test"]
backend-address = "127.0.0.1:4000"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "--config", "client.toml", "public-cert", "init"])
        .assert()
        .success();

    assert_exists(configured_dir.join("public-ca.crt").as_path());
    assert_exists(configured_dir.join("app.example.test/public.crt").as_path());
    assert_exists(configured_dir.join("api.example.test/public.crt").as_path());
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist after `runewarp client public-cert init`",
        path.display()
    );
}

// ── renew ─────────────────────────────────────────────────────────────────────

#[test]
fn client_public_cert_renew_with_hostname_replaces_leaf_but_keeps_ca() {
    let tempdir = tempdir().unwrap();

    // Set up initial certs.
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

    let original_ca = fs::read(tempdir.path().join("public-cert/public-ca.crt")).unwrap();
    let original_leaf = fs::read(
        tempdir
            .path()
            .join("public-cert/app.example.test/public.crt"),
    )
    .unwrap();
    let original_key = fs::read(
        tempdir
            .path()
            .join("public-cert/app.example.test/public.key"),
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "public-cert",
            "renew",
            "--dir",
            "public-cert",
            "--hostname",
            "app.example.test",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(tempdir.path().join("public-cert/public-ca.crt")).unwrap(),
        original_ca,
        "renew should preserve the Public hostname CA certificate"
    );
    assert_ne!(
        fs::read(
            tempdir
                .path()
                .join("public-cert/app.example.test/public.crt")
        )
        .unwrap(),
        original_leaf,
        "renew should replace the leaf certificate"
    );
    assert_ne!(
        fs::read(
            tempdir
                .path()
                .join("public-cert/app.example.test/public.key")
        )
        .unwrap(),
        original_key,
        "renew should replace the leaf private key"
    );
}

#[test]
fn client_public_cert_renew_requires_hostname_or_config() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "public-cert", "renew", "--dir", "public-cert"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("--hostname") || stderr.contains("config"),
        "expected error mentioning --hostname or config, got: {stderr}"
    );
}

#[test]
fn client_public_cert_renew_with_config_renews_all_terminating_hostnames() {
    let tempdir = tempdir().unwrap();

    // Write config with two terminating services.
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
public-cert-dir = "public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:3000"
tls-mode = "terminate"

[[client.services]]
public-hostnames = ["api.example.test"]
backend-address = "127.0.0.1:4000"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    // Initialize both hostnames.
    for hostname in &["app.example.test", "api.example.test"] {
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
                hostname,
            ])
            .assert()
            .success();
    }

    let original_app_leaf = fs::read(
        tempdir
            .path()
            .join("public-cert/app.example.test/public.crt"),
    )
    .unwrap();
    let original_api_leaf = fs::read(
        tempdir
            .path()
            .join("public-cert/api.example.test/public.crt"),
    )
    .unwrap();

    // Renew without --hostname; should derive targets from config.
    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "--config", "client.toml", "public-cert", "renew"])
        .assert()
        .success();

    assert_ne!(
        fs::read(
            tempdir
                .path()
                .join("public-cert/app.example.test/public.crt")
        )
        .unwrap(),
        original_app_leaf,
        "renew should replace app leaf when driven by config"
    );
    assert_ne!(
        fs::read(
            tempdir
                .path()
                .join("public-cert/api.example.test/public.crt")
        )
        .unwrap(),
        original_api_leaf,
        "renew should replace api leaf when driven by config"
    );
}

// ── rotate-ca ─────────────────────────────────────────────────────────────────

#[test]
fn client_public_cert_rotate_ca_requires_config() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "public-cert", "rotate-ca", "--dir", "public-cert"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("config") || stderr.contains("hostname"),
        "expected error mentioning config or hostname, got: {stderr}"
    );
}

#[test]
fn client_public_cert_rotate_ca_replaces_ca_and_reissues_all_leaves() {
    let tempdir = tempdir().unwrap();

    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
public-cert-dir = "public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:3000"
tls-mode = "terminate"

[[client.services]]
public-hostnames = ["api.example.test"]
backend-address = "127.0.0.1:4000"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    for hostname in &["app.example.test", "api.example.test"] {
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
                hostname,
            ])
            .assert()
            .success();
    }

    let original_ca = fs::read(tempdir.path().join("public-cert/public-ca.crt")).unwrap();
    let original_ca_key = fs::read(tempdir.path().join("public-cert/state/public-ca.key")).unwrap();
    let original_app_leaf = fs::read(
        tempdir
            .path()
            .join("public-cert/app.example.test/public.crt"),
    )
    .unwrap();
    let original_api_leaf = fs::read(
        tempdir
            .path()
            .join("public-cert/api.example.test/public.crt"),
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "--config",
            "client.toml",
            "public-cert",
            "rotate-ca",
        ])
        .assert()
        .success();

    assert_ne!(
        fs::read(tempdir.path().join("public-cert/public-ca.crt")).unwrap(),
        original_ca,
        "rotate-ca should replace the Public hostname CA certificate"
    );
    assert_ne!(
        fs::read(tempdir.path().join("public-cert/state/public-ca.key")).unwrap(),
        original_ca_key,
        "rotate-ca should replace the CA private key"
    );
    assert_ne!(
        fs::read(
            tempdir
                .path()
                .join("public-cert/app.example.test/public.crt")
        )
        .unwrap(),
        original_app_leaf,
        "rotate-ca should reissue the app leaf certificate"
    );
    assert_ne!(
        fs::read(
            tempdir
                .path()
                .join("public-cert/api.example.test/public.crt")
        )
        .unwrap(),
        original_api_leaf,
        "rotate-ca should reissue the api leaf certificate"
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
            .join("public-cert/api.example.test/public.crt")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("public-cert/api.example.test/public.key")
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
