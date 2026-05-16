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
        .args(["client", "identity", "init", "--directory", "client-identity"])
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
fn client_identity_init_writes_pem_artifacts_and_a_client_identity() {
    let tempdir = tempdir().unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--directory", "client-identity"])
        .assert()
        .success();

    let private_key = fs::read_to_string(tempdir.path().join("client-identity/client.key")).unwrap();
    let certificate = fs::read_to_string(tempdir.path().join("client-identity/client.crt")).unwrap();
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
fn client_identity_init_refuses_to_overwrite_existing_identity_artifacts() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--directory", "client-identity"])
        .assert()
        .success();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--directory", "client-identity"])
        .assert()
        .failure();
}

#[test]
fn client_identity_init_matches_the_generated_certificate_subject_public_key_info() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args(["client", "identity", "init", "--directory", "client-identity"])
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

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "expected {} to exist after `runewarp client identity init`",
        path.display()
    );
}
