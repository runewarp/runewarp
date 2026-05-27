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
fn client_public_cert_help_uses_concise_public_certificate_copy() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "public-cert", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.starts_with("Runewarp Public Hostname Certificates"));
    assert!(stdout.contains("Manage Public hostname certificates"));
    assert!(stdout.contains("init       Initialize Public hostname certificates"));
    assert!(stdout.contains("renew      Renew Public hostname certificates"));
    assert!(stdout.contains("rotate-ca  Rotate the Public hostname CA"));
    assert!(!stdout.contains("Config defaults:"));
}

#[test]
fn client_public_cert_rotate_ca_help_uses_the_public_hostname_term_and_its_own_example() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "public-cert", "rotate-ca", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.starts_with("Runewarp Public Hostname Certificates"));
    assert!(stdout.contains("Rotate the Public hostname CA"));
    assert!(stdout.contains("runewarp client public-cert rotate-ca"));
    assert!(!stdout.contains("runewarp client public-cert init --hostname"));
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
fn client_public_cert_init_succeeds_when_artifacts_already_exist() {
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
        .success();
}

#[test]
fn client_public_cert_init_is_idempotent_when_hostname_material_already_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

    Command::cargo_bin("runewarp")?
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

    let original_ca = fs::read(tempdir.path().join("client-public-cert/public-ca.crt"))?;

    let assert = Command::cargo_bin("runewarp")?
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

    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;
    let current_ca = fs::read(tempdir.path().join("client-public-cert/public-ca.crt"))?;

    assert_eq!(current_ca, original_ca);
    assert!(stdout.contains("Public hostname certificate material already exists"));
    assert!(!stdout.contains("os error"));
    Ok(())
}

#[test]
fn client_public_cert_init_reports_repair_guidance_for_partial_material()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    fs::create_dir_all(tempdir.path().join("client-public-cert/app.example.test"))?;
    fs::write(
        tempdir
            .path()
            .join("client-public-cert/app.example.test/public.crt"),
        "placeholder certificate",
    )?;

    let assert = Command::cargo_bin("runewarp")?
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

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("incomplete or inconsistent"));
    assert!(stderr.contains("runewarp client public-cert init"));
    assert!(stderr.contains("client-public-cert/app.example.test/public.crt"));
    assert!(!stderr.contains("os error"));
    Ok(())
}

#[test]
fn client_public_cert_init_reports_paths_and_utc_timestamps()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

    let assert = Command::cargo_bin("runewarp")?
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

    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.contains("Public hostname CA: client-public-cert/public-ca.crt"));
    assert!(stdout.contains("Initialized leaf certificate(s) for: app.example.test"));
    assert!(stdout.contains("Issued at (UTC):"));
    assert!(stdout.contains("Renew after (UTC):"));
    assert!(stdout.contains("Expires at (UTC):"));
    Ok(())
}

#[test]
fn client_public_cert_init_requires_hostname_or_config() {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    fs::create_dir_all(&xdg_config_home).unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
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
fn client_public_cert_init_without_hostname_surfaces_xdg_config_resolution_errors() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .args(["client", "public-cert", "init"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("unable to resolve the XDG config base directory"));
    assert!(!stderr.contains("--hostname is required"));
}

#[test]
fn client_public_cert_init_uses_the_xdg_default_directory_when_dir_is_omitted() {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    std::fs::create_dir_all(xdg_config_home.join("runewarp")).unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
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
fn client_public_cert_init_without_hostname_uses_the_discovered_default_config_and_implicit_xdg_dir()
 {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    let xdg_runewarp_dir = xdg_config_home.join("runewarp");
    fs::create_dir_all(&xdg_runewarp_dir).unwrap();
    fs::write(
        xdg_runewarp_dir.join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:3000"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "public-cert", "init"])
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
    let xdg_config_home = tempdir.path().join("xdg-config");
    fs::create_dir_all(&xdg_config_home).unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
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

#[test]
fn client_public_cert_renew_without_hostname_uses_the_discovered_default_config() {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    let xdg_runewarp_dir = xdg_config_home.join("runewarp");
    fs::create_dir_all(&xdg_runewarp_dir).unwrap();
    fs::write(
        xdg_runewarp_dir.join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:3000"
tls-mode = "terminate"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
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

    let original_leaf =
        fs::read(xdg_data_home.join("runewarp/client/public-cert/app.example.test/public.crt"))
            .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "public-cert", "renew"])
        .assert()
        .success();

    assert_ne!(
        fs::read(xdg_data_home.join("runewarp/client/public-cert/app.example.test/public.crt"))
            .unwrap(),
        original_leaf,
        "renew should replace the leaf when driven by the discovered default config"
    );
}

// ── rotate-ca ─────────────────────────────────────────────────────────────────

#[test]
fn client_public_cert_rotate_ca_uses_the_discovered_default_config()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_runewarp_dir = xdg_config_home.join("runewarp");
    fs::create_dir_all(&xdg_runewarp_dir)?;
    fs::write(
        xdg_runewarp_dir.join("config.toml"),
        r#"
[client]
server-address = "tunnel.example.test"
public-cert-dir = "public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:3000"
tls-mode = "terminate"
"#,
    )?;

    Command::cargo_bin("runewarp")?
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

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .args(["client", "public-cert", "rotate-ca", "--dir", "public-cert"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;
    assert!(stdout.contains("Public hostname CA rotated"));
    Ok(())
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
