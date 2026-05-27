use std::fs;
use std::path::Path;

use assert_cmd::Command;
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn server_cert_init_writes_the_manual_server_ca_layout() {
    let tempdir = tempdir().unwrap();

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
            "Tunnel.Example.Test.",
        ])
        .assert()
        .success();

    assert_exists(tempdir.path().join("server-cert/server.crt").as_path());
    assert_exists(tempdir.path().join("server-cert/server.key").as_path());
    assert_exists(tempdir.path().join("server-cert/server-ca.crt").as_path());
    assert_exists(
        tempdir
            .path()
            .join("server-cert/state/server-ca.key")
            .as_path(),
    );
    assert_exists(
        tempdir
            .path()
            .join("server-cert/state/server-hostname.txt")
            .as_path(),
    );

    let server_cert = fs::read_to_string(tempdir.path().join("server-cert/server.crt")).unwrap();
    let server_key = fs::read_to_string(tempdir.path().join("server-cert/server.key")).unwrap();
    let server_ca = fs::read_to_string(tempdir.path().join("server-cert/server-ca.crt")).unwrap();
    let server_hostname =
        fs::read_to_string(tempdir.path().join("server-cert/state/server-hostname.txt")).unwrap();

    assert!(server_cert.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(server_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(server_ca.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(server_hostname.trim(), "tunnel.example.test");
}

#[test]
fn server_cert_help_shows_the_config_flag() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["server", "cert", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("runewarp server cert"));
    assert!(stdout.contains("--config"));
}

#[test]
fn server_cert_help_uses_concise_server_certificate_copy() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["server", "cert", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.starts_with("Runewarp Server Certificates"));
    assert!(stdout.contains("Manage Server certificates"));
    assert!(stdout.contains("init       Initialize Server certificates"));
    assert!(stdout.contains("renew      Renew Server certificates"));
    assert!(stdout.contains("rotate-ca  Rotate the Server CA"));
    assert!(!stdout.contains("Config defaults:"));
}

#[test]
fn server_cert_init_uses_the_xdg_default_directory_when_dir_is_omitted() {
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

    assert_exists(
        xdg_data_home
            .join("runewarp/server/cert/server.crt")
            .as_path(),
    );
    assert_exists(
        xdg_data_home
            .join("runewarp/server/cert/server.key")
            .as_path(),
    );
    assert_exists(
        xdg_data_home
            .join("runewarp/server/cert/server-ca.crt")
            .as_path(),
    );
}

#[test]
fn server_cert_init_uses_the_configured_material_dir_when_config_is_provided() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/server-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
cert-dir = "configured/server-cert"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--config",
            "server.toml",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    assert_exists(configured_dir.join("server.crt").as_path());
    assert_exists(configured_dir.join("server.key").as_path());
    assert_exists(configured_dir.join("server-ca.crt").as_path());
}

#[test]
fn server_cert_init_uses_the_configured_hostname_when_hostname_is_omitted() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/server-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "Tunnel.Example.Test."
cert-dir = "configured/server-cert"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["server", "cert", "init", "--config", "server.toml"])
        .assert()
        .success();

    assert_exists(configured_dir.join("server.crt").as_path());
    assert_exists(configured_dir.join("server.key").as_path());
    assert_exists(configured_dir.join("server-ca.crt").as_path());

    let stored_hostname =
        fs::read_to_string(configured_dir.join("state/server-hostname.txt")).unwrap();
    assert_eq!(stored_hostname.trim(), "tunnel.example.test");
}

#[test]
fn server_cert_init_rejects_a_hostname_that_conflicts_with_config() {
    let tempdir = tempdir().unwrap();
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "configured/server-cert"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--config",
            "server.toml",
            "--hostname",
            "other.example.test",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("--hostname `other.example.test`"));
    assert!(stderr.contains("configured server.hostname `tunnel.example.test`"));
}

#[test]
fn server_cert_init_is_idempotent_when_material_already_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

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

    let original_hostname =
        fs::read_to_string(tempdir.path().join("server-cert/state/server-hostname.txt"))?;

    let assert = Command::cargo_bin("runewarp")?
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

    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;
    let current_hostname =
        fs::read_to_string(tempdir.path().join("server-cert/state/server-hostname.txt"))?;

    assert_eq!(current_hostname, original_hostname);
    assert!(stdout.contains("Server certificate material already exists"));
    assert!(stdout.contains("Issued at (UTC):"));
    assert!(stdout.contains("Renew after (UTC):"));
    assert!(stdout.contains("Expires at (UTC):"));
    assert!(!stdout.contains("os error"));
    Ok(())
}

#[test]
fn server_cert_init_reports_repair_guidance_for_partial_material()
-> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;
    fs::create_dir_all(tempdir.path().join("server-cert"))?;
    fs::write(
        tempdir.path().join("server-cert/server.crt"),
        "placeholder certificate",
    )?;

    let assert = Command::cargo_bin("runewarp")?
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
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("incomplete or inconsistent"));
    assert!(stderr.contains("runewarp server cert init"));
    assert!(stderr.contains("server-cert/server.crt"));
    assert!(!stderr.contains("os error"));
    Ok(())
}

#[test]
fn server_cert_init_reports_paths_and_utc_timestamps() -> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

    let assert = Command::cargo_bin("runewarp")?
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

    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.contains("Server hostname: tunnel.example.test"));
    assert!(stdout.contains("Certificate directory: server-cert"));
    assert!(stdout.contains("Issued at (UTC):"));
    assert!(stdout.contains("Renew after (UTC):"));
    assert!(stdout.contains("Expires at (UTC):"));
    Ok(())
}

#[test]
fn server_cert_rotate_ca_uses_the_configured_hostname_when_hostname_is_omitted() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/server-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "rotated.example.test"
cert-dir = "configured/server-cert"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--dir",
            "configured/server-cert",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["server", "cert", "rotate-ca", "--config", "server.toml"])
        .assert()
        .success();

    let stored_hostname =
        fs::read_to_string(configured_dir.join("state/server-hostname.txt")).unwrap();
    assert_eq!(stored_hostname.trim(), "rotated.example.test");
}

#[test]
fn server_cert_rotate_ca_rejects_a_hostname_that_conflicts_with_config() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/server-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "configured/server-cert"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--dir",
            "configured/server-cert",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "rotate-ca",
            "--config",
            "server.toml",
            "--hostname",
            "other.example.test",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("--hostname `other.example.test`"));
    assert!(stderr.contains("configured server.hostname `tunnel.example.test`"));
    assert!(configured_dir.join("server.crt").is_file());
}

#[test]
fn server_cert_renew_accepts_config_before_the_leaf_subcommand() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/server-cert");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]
cert-dir = "configured/server-cert"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--config",
            "server.toml",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    let original_server_certificate =
        fs::read(configured_dir.join("server.crt")).expect("original server certificate");

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["server", "cert", "--config", "server.toml", "renew"])
        .assert()
        .success();

    assert_ne!(
        fs::read(configured_dir.join("server.crt")).expect("renewed server certificate"),
        original_server_certificate,
        "renew should use the configured material directory",
    );
}

#[test]
fn server_cert_init_rejects_the_legacy_nested_cert_table_in_config() {
    let tempdir = tempdir().unwrap();
    let xdg_data_home = tempdir.path().join("xdg-data");
    fs::write(
        tempdir.path().join("server.toml"),
        r#"
[server]

[server.cert]
directory = "legacy/server-cert"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args([
            "server",
            "cert",
            "init",
            "--config",
            "server.toml",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("unknown field `cert`"));
    assert!(
        !xdg_data_home
            .join("runewarp/server/cert/server.crt")
            .exists()
    );
}

#[test]
fn server_cert_init_succeeds_when_material_already_exists() {
    let tempdir = tempdir().unwrap();

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
}

#[cfg(unix)]
#[test]
fn server_cert_init_writes_private_keys_with_owner_only_permissions() {
    let tempdir = tempdir().unwrap();

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

    let server_key_mode = fs::metadata(tempdir.path().join("server-cert/server.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let ca_key_mode = fs::metadata(tempdir.path().join("server-cert/state/server-ca.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(server_key_mode, 0o600);
    assert_eq!(ca_key_mode, 0o600);
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist after `runewarp server cert init`",
        path.display()
    );
}

#[test]
fn server_cert_renew_reissues_the_leaf_without_changing_the_server_ca() {
    let temp_dir = tempdir().expect("create temporary directory");
    let cert_directory = temp_dir.path().join("server-cert");

    assert_cmd::Command::cargo_bin("runewarp")
        .expect("binary path")
        .args([
            "server",
            "cert",
            "init",
            "--dir",
            cert_directory
                .to_str()
                .expect("utf-8 certificate directory"),
            "--hostname",
            "Tunnel.EXAMPLE.test",
        ])
        .assert()
        .success();

    let original_server_certificate =
        fs::read(cert_directory.join("server.crt")).expect("original server certificate");
    let original_server_key =
        fs::read(cert_directory.join("server.key")).expect("original server key");
    let original_server_ca =
        fs::read(cert_directory.join("server-ca.crt")).expect("original server CA certificate");
    let original_server_ca_key =
        fs::read(cert_directory.join("state/server-ca.key")).expect("original server CA key");
    let original_hostname = fs::read_to_string(cert_directory.join("state/server-hostname.txt"))
        .expect("original stored hostname");

    assert_cmd::Command::cargo_bin("runewarp")
        .expect("binary path")
        .args([
            "server",
            "cert",
            "renew",
            "--dir",
            cert_directory
                .to_str()
                .expect("utf-8 certificate directory"),
        ])
        .assert()
        .success();

    assert_ne!(
        fs::read(cert_directory.join("server.crt")).expect("renewed server certificate"),
        original_server_certificate,
        "renew should replace the server leaf certificate",
    );
    assert_ne!(
        fs::read(cert_directory.join("server.key")).expect("renewed server key"),
        original_server_key,
        "renew should replace the server leaf private key",
    );
    assert_eq!(
        fs::read(cert_directory.join("server-ca.crt")).expect("renewed server CA certificate"),
        original_server_ca,
        "renew should preserve the existing server CA certificate",
    );
    assert_eq!(
        fs::read(cert_directory.join("state/server-ca.key")).expect("renewed server CA key"),
        original_server_ca_key,
        "renew should preserve the existing server CA private key",
    );
    assert_eq!(
        fs::read_to_string(cert_directory.join("state/server-hostname.txt"))
            .expect("renewed stored hostname"),
        original_hostname,
        "renew should preserve the stored normalized hostname",
    );
}

#[test]
fn server_cert_rotate_ca_replaces_the_ca_and_updates_the_stored_hostname() {
    let temp_dir = tempdir().expect("create temporary directory");
    let cert_directory = temp_dir.path().join("server-cert");

    assert_cmd::Command::cargo_bin("runewarp")
        .expect("binary path")
        .args([
            "server",
            "cert",
            "init",
            "--dir",
            cert_directory
                .to_str()
                .expect("utf-8 certificate directory"),
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    let original_server_certificate =
        fs::read(cert_directory.join("server.crt")).expect("original server certificate");
    let original_server_key =
        fs::read(cert_directory.join("server.key")).expect("original server key");
    let original_server_ca =
        fs::read(cert_directory.join("server-ca.crt")).expect("original server CA certificate");
    let original_server_ca_key =
        fs::read(cert_directory.join("state/server-ca.key")).expect("original server CA key");
    let original_hostname = fs::read_to_string(cert_directory.join("state/server-hostname.txt"))
        .expect("original stored hostname");

    assert_cmd::Command::cargo_bin("runewarp")
        .expect("binary path")
        .args([
            "server",
            "cert",
            "rotate-ca",
            "--dir",
            cert_directory
                .to_str()
                .expect("utf-8 certificate directory"),
            "--hostname",
            "Rotated.EXAMPLE.test",
        ])
        .assert()
        .success();

    assert_ne!(
        fs::read(cert_directory.join("server.crt")).expect("rotated server certificate"),
        original_server_certificate,
        "rotate-ca should replace the server leaf certificate",
    );
    assert_ne!(
        fs::read(cert_directory.join("server.key")).expect("rotated server key"),
        original_server_key,
        "rotate-ca should replace the server leaf private key",
    );
    assert_ne!(
        fs::read(cert_directory.join("server-ca.crt")).expect("rotated server CA certificate"),
        original_server_ca,
        "rotate-ca should replace the server CA certificate",
    );
    assert_ne!(
        fs::read(cert_directory.join("state/server-ca.key")).expect("rotated server CA key"),
        original_server_ca_key,
        "rotate-ca should replace the server CA private key",
    );
    assert_ne!(
        fs::read_to_string(cert_directory.join("state/server-hostname.txt"))
            .expect("rotated stored hostname"),
        original_hostname,
        "rotate-ca should replace the stored hostname",
    );
    assert_eq!(
        fs::read_to_string(cert_directory.join("state/server-hostname.txt"))
            .expect("rotated stored hostname"),
        "rotated.example.test",
        "rotate-ca should normalize the stored hostname",
    );
}

#[test]
fn server_cert_init_help_shows_the_new_dir_flag() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["server", "cert", "init", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("runewarp server cert init"));
    assert!(stdout.contains("--dir"));
    assert!(!stdout.contains("--directory"));
}

#[test]
fn server_cert_init_rejects_the_removed_directory_flag() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--directory",
            "server-cert",
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("unexpected argument '--directory'"));
    assert!(stderr.contains("--dir"));
}
