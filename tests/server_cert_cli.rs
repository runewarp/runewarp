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
            "--directory",
            "server-cert",
            "--hostname",
            "Tunnel.Example.Test.",
        ])
        .assert()
        .success();

    assert_exists(tempdir.path().join("server-cert/server.crt").as_path());
    assert_exists(tempdir.path().join("server-cert/server.key").as_path());
    assert_exists(tempdir.path().join("server-cert/server-ca.crt").as_path());
    assert_exists(tempdir.path().join("server-cert/state/manual/server-ca.key").as_path());
    assert_exists(
        tempdir
            .path()
            .join("server-cert/state/manual/server-hostname.txt")
            .as_path(),
    );

    let server_cert = fs::read_to_string(tempdir.path().join("server-cert/server.crt")).unwrap();
    let server_key = fs::read_to_string(tempdir.path().join("server-cert/server.key")).unwrap();
    let server_ca = fs::read_to_string(tempdir.path().join("server-cert/server-ca.crt")).unwrap();
    let server_hostname =
        fs::read_to_string(tempdir.path().join("server-cert/state/manual/server-hostname.txt"))
            .unwrap();

    assert!(server_cert.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(server_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(server_ca.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(server_hostname.trim(), "tunnel.example.test");
}

#[test]
fn server_cert_init_refuses_to_overwrite_existing_material() {
    let tempdir = tempdir().unwrap();

    Command::cargo_bin("runewarp")
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
        .success();

    Command::cargo_bin("runewarp")
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
            "--directory",
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
    let ca_key_mode = fs::metadata(tempdir.path().join("server-cert/state/manual/server-ca.key"))
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
            "--directory",
            cert_directory.to_str().expect("utf-8 certificate directory"),
            "--hostname",
            "Tunnel.EXAMPLE.test",
        ])
        .assert()
        .success();

    let original_server_certificate =
        fs::read(cert_directory.join("server.crt")).expect("original server certificate");
    let original_server_key = fs::read(cert_directory.join("server.key")).expect("original server key");
    let original_server_ca =
        fs::read(cert_directory.join("server-ca.crt")).expect("original server CA certificate");
    let original_server_ca_key = fs::read(cert_directory.join("state/manual/server-ca.key"))
        .expect("original server CA key");
    let original_hostname = fs::read_to_string(cert_directory.join("state/manual/server-hostname.txt"))
        .expect("original stored hostname");

    assert_cmd::Command::cargo_bin("runewarp")
        .expect("binary path")
        .args([
            "server",
            "cert",
            "renew",
            "--directory",
            cert_directory.to_str().expect("utf-8 certificate directory"),
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
        fs::read(cert_directory.join("state/manual/server-ca.key")).expect("renewed server CA key"),
        original_server_ca_key,
        "renew should preserve the existing server CA private key",
    );
    assert_eq!(
        fs::read_to_string(cert_directory.join("state/manual/server-hostname.txt"))
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
            "--directory",
            cert_directory.to_str().expect("utf-8 certificate directory"),
            "--hostname",
            "tunnel.example.test",
        ])
        .assert()
        .success();

    let original_server_certificate =
        fs::read(cert_directory.join("server.crt")).expect("original server certificate");
    let original_server_key = fs::read(cert_directory.join("server.key")).expect("original server key");
    let original_server_ca =
        fs::read(cert_directory.join("server-ca.crt")).expect("original server CA certificate");
    let original_server_ca_key = fs::read(cert_directory.join("state/manual/server-ca.key"))
        .expect("original server CA key");
    let original_hostname = fs::read_to_string(cert_directory.join("state/manual/server-hostname.txt"))
        .expect("original stored hostname");

    assert_cmd::Command::cargo_bin("runewarp")
        .expect("binary path")
        .args([
            "server",
            "cert",
            "rotate-ca",
            "--directory",
            cert_directory.to_str().expect("utf-8 certificate directory"),
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
        fs::read(cert_directory.join("state/manual/server-ca.key")).expect("rotated server CA key"),
        original_server_ca_key,
        "rotate-ca should replace the server CA private key",
    );
    assert_ne!(
        fs::read_to_string(cert_directory.join("state/manual/server-hostname.txt"))
            .expect("rotated stored hostname"),
        original_hostname,
        "rotate-ca should replace the stored hostname",
    );
    assert_eq!(
        fs::read_to_string(cert_directory.join("state/manual/server-hostname.txt"))
            .expect("rotated stored hostname"),
        "rotated.example.test",
        "rotate-ca should normalize the stored hostname",
    );
}
