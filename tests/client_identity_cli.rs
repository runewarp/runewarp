use std::fs;
use std::io::Cursor;
use std::path::Path;

use assert_cmd::Command;
use runewarp::client_identity_from_certificate_der;
use rustls_pemfile::certs;
use tempfile::tempdir;

#[test]
fn client_identity_init_writes_identity_artifacts_to_the_requested_directory() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    assert_exists(tempdir.path().join("client-identity/client.key").as_path());
    assert_exists(tempdir.path().join("client-identity/client.crt").as_path());
    assert_exists(
        tempdir
            .path()
            .join("client-identity/client-identity.txt")
            .as_path(),
    );
}

#[test]
fn client_identity_init_uses_the_xdg_default_directory_when_dir_is_omitted() {
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

    assert_exists(
        xdg_data_home
            .join("runewarp/client/identity/client.key")
            .as_path(),
    );
    assert_exists(
        xdg_data_home
            .join("runewarp/client/identity/client.crt")
            .as_path(),
    );
    assert_exists(
        xdg_data_home
            .join("runewarp/client/identity/client-identity.txt")
            .as_path(),
    );
}

#[test]
fn client_identity_init_uses_the_configured_material_dir_when_config_is_provided() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/client-identity");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
identity-dir = "configured/client-identity"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--config", "client.toml"])
        .assert()
        .success();

    assert_exists(configured_dir.join("client.key").as_path());
    assert_exists(configured_dir.join("client.crt").as_path());
    assert_exists(configured_dir.join("client-identity.txt").as_path());
}

#[test]
fn client_identity_init_accepts_config_before_the_leaf_subcommand() {
    let tempdir = tempdir().unwrap();
    let configured_dir = tempdir.path().join("configured/client-identity");
    fs::create_dir_all(tempdir.path().join("configured")).unwrap();
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
identity-dir = "configured/client-identity"
"#,
    )
    .unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "--config", "client.toml", "init"])
        .assert()
        .success();

    assert_exists(configured_dir.join("client.key").as_path());
    assert_exists(configured_dir.join("client.crt").as_path());
    assert_exists(configured_dir.join("client-identity.txt").as_path());
}

#[test]
fn client_identity_init_rejects_the_legacy_identity_directory_key_in_config() {
    let tempdir = tempdir().unwrap();
    let xdg_data_home = tempdir.path().join("xdg-data");
    fs::write(
        tempdir.path().join("client.toml"),
        r#"
[client]
identity-directory = "legacy/client-identity"
"#,
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "identity", "init", "--config", "client.toml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("unknown field `identity-directory`"));
    assert!(
        !xdg_data_home
            .join("runewarp/client/identity/client.key")
            .exists()
    );
}

#[test]
fn client_identity_init_writes_pem_artifacts_and_a_client_identity() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let private_key =
        fs::read_to_string(tempdir.path().join("client-identity/client.key")).unwrap();
    let certificate =
        fs::read_to_string(tempdir.path().join("client-identity/client.crt")).unwrap();
    let client_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(certificate.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(client_identity.trim().len(), 64);
    assert!(
        client_identity
            .trim()
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    );
    assert!(stdout.contains("90 days"));
    assert!(stdout.contains("60 days"));
}

#[test]
fn client_identity_init_succeeds_when_identity_artifacts_already_exist() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();
}

#[test]
fn client_identity_init_matches_the_generated_certificate_subject_public_key_info() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let certificate_pem = fs::read(tempdir.path().join("client-identity/client.crt")).unwrap();
    let certificate = certs(&mut Cursor::new(certificate_pem))
        .next()
        .expect("generated certificate")
        .expect("parse generated certificate");
    let stored_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();

    let derived_identity = client_identity_from_certificate_der(certificate.as_ref())
        .expect("derive client identity from certificate");

    assert_eq!(stored_identity.trim(), derived_identity.to_string());
}

#[test]
fn client_identity_init_rejects_runtime_routing_flags() -> Result<(), Box<dyn std::error::Error>> {
    let tempdir = tempdir()?;

    let assert = Command::cargo_bin("runewarp")?
        .current_dir(tempdir.path())
        .args([
            "client",
            "--server-address",
            "tunnel.example.test",
            "--backend-address",
            "localhost:443",
            "identity",
            "init",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone())?;

    assert!(stderr.contains("runewarp client identity"));
    assert!(stderr.contains("--server-address"));
    assert!(stderr.contains("--backend-address"));
    Ok(())
}

#[test]
fn client_identity_renew_reuses_the_existing_key_and_identity() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let original_private_key = fs::read(tempdir.path().join("client-identity/client.key")).unwrap();
    let original_certificate = fs::read(tempdir.path().join("client-identity/client.crt")).unwrap();
    let original_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "renew", "--dir", "client-identity"])
        .assert()
        .success();

    let renewed_private_key = fs::read(tempdir.path().join("client-identity/client.key")).unwrap();
    let renewed_certificate = fs::read(tempdir.path().join("client-identity/client.crt")).unwrap();
    let renewed_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();
    let renewed_certificate_der = certs(&mut Cursor::new(renewed_certificate.clone()))
        .next()
        .expect("renewed certificate")
        .expect("parse renewed certificate");

    assert_eq!(renewed_private_key, original_private_key);
    assert_ne!(renewed_certificate, original_certificate);
    assert_eq!(renewed_identity, original_identity);
    assert_eq!(
        client_identity_from_certificate_der(renewed_certificate_der.as_ref())
            .unwrap()
            .to_string(),
        renewed_identity.trim(),
    );
}

#[test]
fn client_identity_rotate_replaces_the_key_and_client_identity() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let original_private_key = fs::read(tempdir.path().join("client-identity/client.key")).unwrap();
    let original_certificate = fs::read(tempdir.path().join("client-identity/client.crt")).unwrap();
    let original_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "rotate", "--dir", "client-identity"])
        .assert()
        .success();

    let rotated_private_key = fs::read(tempdir.path().join("client-identity/client.key")).unwrap();
    let rotated_certificate = fs::read(tempdir.path().join("client-identity/client.crt")).unwrap();
    let rotated_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();
    let rotated_certificate_der = certs(&mut Cursor::new(rotated_certificate.clone()))
        .next()
        .expect("rotated certificate")
        .expect("parse rotated certificate");

    assert_ne!(rotated_private_key, original_private_key);
    assert_ne!(rotated_certificate, original_certificate);
    assert_ne!(rotated_identity, original_identity);
    assert_eq!(
        client_identity_from_certificate_der(rotated_certificate_der.as_ref())
            .unwrap()
            .to_string(),
        rotated_identity.trim(),
    );
}

#[test]
fn client_identity_show_prints_only_the_fingerprint() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let expected_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "show", "--dir", "client-identity"])
        .assert()
        .success();

    assert_eq!(
        String::from_utf8(assert.get_output().stdout.clone()).unwrap(),
        format!("{}\n", expected_identity.trim())
    );
    assert!(assert.get_output().stderr.is_empty());
}

#[test]
fn client_identity_init_is_idempotent_when_material_already_exists() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let original_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let current_identity =
        fs::read_to_string(tempdir.path().join("client-identity/client-identity.txt")).unwrap();

    assert_eq!(current_identity, original_identity);
    assert!(stdout.contains("Client identity already exists"));
    assert!(!stdout.contains("os error"));
}

#[test]
fn client_identity_init_reports_repair_guidance_for_partial_material() {
    let tempdir = tempdir().unwrap();
    fs::create_dir_all(tempdir.path().join("client-identity")).unwrap();
    fs::write(
        tempdir.path().join("client-identity/client.crt"),
        "placeholder certificate",
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("incomplete or inconsistent"));
    assert!(stderr.contains("runewarp client identity init"));
    assert!(stderr.contains("client-identity/client.crt"));
    assert!(!stderr.contains("os error"));
}

#[test]
fn client_identity_init_reports_paths_and_utc_timestamps() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--dir", "client-identity"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Identity directory: client-identity"));
    assert!(stdout.contains("Issued at (UTC):"));
    assert!(stdout.contains("Renew after (UTC):"));
    assert!(stdout.contains("Expires at (UTC):"));
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist after `runewarp client identity init`",
        path.display()
    );
}

#[test]
fn client_identity_init_help_shows_the_new_dir_flag() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "identity", "init", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("runewarp client identity init"));
    assert!(stdout.contains("--dir"));
    assert!(!stdout.contains("--directory"));
}

#[test]
fn client_identity_help_shows_the_config_flag() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "identity", "--help"])
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("runewarp client identity"));
    assert!(stdout.contains("--config"));
}

#[test]
fn client_identity_init_rejects_the_removed_directory_flag() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "client",
            "identity",
            "init",
            "--directory",
            "client-identity",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("unexpected argument '--directory'"));
    assert!(stderr.contains("--dir"));
}
