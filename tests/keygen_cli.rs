use std::fs;
use std::path::Path;

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn keygen_writes_default_client_identity_artifacts() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .arg("keygen")
        .assert()
        .success();

    assert_exists(tempdir.path().join("certs/client.key").as_path());
    assert_exists(tempdir.path().join("certs/client.crt").as_path());
    assert_exists(
        tempdir
            .path()
            .join("certs/client-fingerprint.txt")
            .as_path(),
    );
}

#[test]
fn keygen_writes_pem_artifacts_and_a_client_identity_fingerprint() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .arg("keygen")
        .assert()
        .success();

    let private_key = fs::read_to_string(tempdir.path().join("certs/client.key")).unwrap();
    let certificate = fs::read_to_string(tempdir.path().join("certs/client.crt")).unwrap();
    let fingerprint =
        fs::read_to_string(tempdir.path().join("certs/client-fingerprint.txt")).unwrap();

    assert!(private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(certificate.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(fingerprint.trim().len(), 64);
    assert!(
        fingerprint
            .trim()
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    );
}

#[test]
fn keygen_writes_artifacts_to_a_custom_output_directory() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["keygen", "--out-dir", "operator-certs"])
        .assert()
        .success();

    assert_exists(tempdir.path().join("operator-certs/client.key").as_path());
    assert_exists(tempdir.path().join("operator-certs/client.crt").as_path());
    assert_exists(
        tempdir
            .path()
            .join("operator-certs/client-fingerprint.txt")
            .as_path(),
    );
}

#[test]
fn keygen_refuses_to_overwrite_existing_client_identity_artifacts() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .arg("keygen")
        .assert()
        .success();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .arg("keygen")
        .assert()
        .failure();
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist after `runewarp keygen`",
        path.display()
    );
}
