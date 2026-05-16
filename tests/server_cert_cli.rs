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
