use std::fs;
use std::path::Path;
use std::process::Command as ProcessCommand;

use assert_cmd::Command;
use rcgen::{KeyPair, PKCS_ED25519};
use runewarp::IdentityKey;
use tempfile::tempdir;

fn runewarp(directory: &Path) -> Command {
    let mut command = Command::cargo_bin("runewarp").unwrap();
    command.current_dir(directory);
    command
}

fn stdout_of(command: &mut Command) -> String {
    let assert = command.assert().success();
    String::from_utf8(assert.get_output().stdout.clone()).unwrap()
}

fn stderr_of_failure(command: &mut Command) -> String {
    let assert = command.assert().failure();
    String::from_utf8(assert.get_output().stderr.clone()).unwrap()
}

fn fingerprint_of(path: &Path) -> String {
    IdentityKey::read(path)
        .unwrap()
        .client_identity()
        .to_string()
}

/// The documented operator recipe: SHA-256 over the DER SubjectPublicKeyInfo.
fn openssl_fingerprint(path: &Path) -> String {
    let public_key = ProcessCommand::new("openssl")
        .args(["pkey", "-in"])
        .arg(path)
        .args(["-pubout", "-outform", "DER"])
        .output()
        .expect("openssl must be installed to check the documented fingerprint recipe");
    assert!(public_key.status.success(), "openssl pkey failed");
    let mut digest = ProcessCommand::new("openssl")
        .args(["dgst", "-sha256", "-r"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(digest.stdin.as_mut().unwrap(), &public_key.stdout).unwrap();
    let output = digest.wait_with_output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_writes_only_an_owner_only_key_and_prints_its_fingerprint() {
    let tempdir = tempdir().unwrap();

    let stdout = stdout_of(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "init",
        "--key",
        "identity/client.key",
    ]));

    let key_path = tempdir.path().join("identity/client.key");
    let entries = fs::read_dir(tempdir.path().join("identity"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries, ["client.key"]);
    #[cfg(unix)]
    assert_eq!(mode_of(&key_path), 0o600);
    let fingerprint = fingerprint_of(&key_path);
    assert_eq!(
        stdout,
        format!("Client identity initialized: {fingerprint}\nIdentity key: identity/client.key\n")
    );
}

#[test]
fn init_uses_the_xdg_default_key_path_when_key_is_omitted() {
    let tempdir = tempdir().unwrap();
    let xdg_config_home = tempdir.path().join("xdg-config");
    let xdg_data_home = tempdir.path().join("xdg-data");
    fs::create_dir_all(xdg_config_home.join("runewarp")).unwrap();

    runewarp(tempdir.path())
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_DATA_HOME", &xdg_data_home)
        .args(["client", "identity", "init"])
        .assert()
        .success();

    assert!(xdg_data_home.join("runewarp/client/identity.key").is_file());
}

#[test]
fn init_uses_the_configured_identity_key_before_or_after_the_leaf_subcommand() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("custom.toml"),
        "[client]\nidentity-key = \"configured/client.key\"\n",
    )
    .unwrap();

    runewarp(tempdir.path())
        .args(["client", "identity", "init", "--config", "custom.toml"])
        .assert()
        .success();
    let first = fs::read(tempdir.path().join("configured/client.key")).unwrap();
    runewarp(tempdir.path())
        .args(["client", "--config", "custom.toml", "identity", "init"])
        .assert()
        .success();

    assert_eq!(
        fs::read(tempdir.path().join("configured/client.key")).unwrap(),
        first
    );
}

#[test]
fn init_leaves_an_existing_valid_key_unchanged() {
    let tempdir = tempdir().unwrap();
    let key_path = tempdir.path().join("client.key");
    // A released (v0.2.0) P-256 PKCS#8 key keeps its identity.
    let released = KeyPair::generate().unwrap().serialize_pem();
    fs::write(&key_path, &released).unwrap();

    let stdout = stdout_of(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "init",
        "--key",
        "client.key",
    ]));

    assert_eq!(fs::read_to_string(&key_path).unwrap(), released);
    assert!(stdout.starts_with(&format!(
        "Client identity already exists: {}",
        fingerprint_of(&key_path)
    )));
}

#[test]
fn init_refuses_to_overwrite_an_invalid_key() {
    let tempdir = tempdir().unwrap();
    let key_path = tempdir.path().join("client.key");
    fs::write(&key_path, "not a key").unwrap();

    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "init",
        "--key",
        "client.key",
    ]));

    assert!(
        stderr.contains("refusing to overwrite existing identity key"),
        "{stderr}"
    );
    assert_eq!(fs::read_to_string(&key_path).unwrap(), "not a key");
}

#[test]
fn legacy_certificate_and_fingerprint_files_are_ignored() {
    let tempdir = tempdir().unwrap();
    let identity = tempdir.path().join("identity");
    fs::create_dir(&identity).unwrap();
    fs::write(
        identity.join("client.key"),
        IdentityKey::generate().unwrap().to_pem(),
    )
    .unwrap();
    fs::write(identity.join("client.crt"), "stale certificate").unwrap();
    fs::write(identity.join("client-identity.txt"), "stale fingerprint").unwrap();

    let show = stdout_of(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "show",
        "--key",
        "identity/client.key",
    ]));
    runewarp(tempdir.path())
        .args(["client", "identity", "init", "--key", "identity/client.key"])
        .assert()
        .success();

    assert_eq!(show.trim(), fingerprint_of(&identity.join("client.key")));
    assert_eq!(
        fs::read_to_string(identity.join("client.crt")).unwrap(),
        "stale certificate"
    );
    assert_eq!(
        fs::read_to_string(identity.join("client-identity.txt")).unwrap(),
        "stale fingerprint"
    );
}

#[test]
fn show_prints_the_fingerprint_from_the_openssl_recipe() {
    let tempdir = tempdir().unwrap();
    runewarp(tempdir.path())
        .args(["client", "identity", "init", "--key", "client.key"])
        .assert()
        .success();

    let stdout = stdout_of(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "show",
        "--key",
        "client.key",
    ]));

    assert_eq!(
        stdout,
        format!(
            "{}\n",
            openssl_fingerprint(&tempdir.path().join("client.key"))
        )
    );
}

#[test]
fn show_explains_how_to_convert_a_sec1_key() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("client.key"),
        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIA==\n-----END EC PRIVATE KEY-----\n",
    )
    .unwrap();

    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "show",
        "--key",
        "client.key",
    ]));

    assert!(stderr.contains("openssl pkcs8 -topk8 -nocrypt"), "{stderr}");
}

#[test]
fn rotate_installs_a_new_owner_only_key_and_prints_its_fingerprint() {
    let tempdir = tempdir().unwrap();
    let key_path = tempdir.path().join("client.key");
    runewarp(tempdir.path())
        .args(["client", "identity", "init", "--key", "client.key"])
        .assert()
        .success();
    let before = fingerprint_of(&key_path);

    let stdout = stdout_of(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "rotate",
        "--key",
        "client.key",
    ]));

    let after = fingerprint_of(&key_path);
    assert_ne!(before, after);
    assert_eq!(
        stdout,
        format!("Client identity rotated: {after}\nIdentity key: client.key\n")
    );
    #[cfg(unix)]
    assert_eq!(mode_of(&key_path), 0o600);
    let leftovers = fs::read_dir(tempdir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(leftovers, ["client.key"]);
}

#[test]
fn rotate_replaces_an_unsupported_ed25519_key() {
    let tempdir = tempdir().unwrap();
    let key_path = tempdir.path().join("client.key");
    fs::write(
        &key_path,
        KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .serialize_pem(),
    )
    .unwrap();

    let show = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "show",
        "--key",
        "client.key",
    ]));
    assert!(show.contains("runewarp client identity rotate"), "{show}");

    runewarp(tempdir.path())
        .args(["client", "identity", "rotate", "--key", "client.key"])
        .assert()
        .success();

    IdentityKey::read(&key_path).unwrap();
}

#[test]
fn rotate_requires_an_existing_key() {
    let tempdir = tempdir().unwrap();

    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "rotate",
        "--key",
        "client.key",
    ]));

    assert!(stderr.contains("runewarp client identity init"), "{stderr}");
    assert!(!tempdir.path().join("client.key").exists());
}

#[test]
fn identity_commands_reject_runtime_routing_flags() {
    let tempdir = tempdir().unwrap();

    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "--server-address",
        "tunnel.example.test",
        "--backend-address",
        "localhost:443",
        "identity",
        "init",
    ]));

    assert!(stderr.contains("runewarp client identity"));
    assert!(stderr.contains("--server-address"));
    assert!(stderr.contains("--backend-address"));
}

#[test]
fn renew_is_rejected_as_an_unknown_subcommand() {
    let tempdir = tempdir().unwrap();

    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "renew",
        "--key",
        "client.key",
    ]));

    assert!(stderr.contains("unrecognized subcommand"));
    assert!(stderr.contains("renew"));
}

#[test]
fn init_help_shows_the_key_flag_and_dir_is_rejected() {
    let tempdir = tempdir().unwrap();

    let help = stdout_of(runewarp(tempdir.path()).args(["client", "identity", "init", "--help"]));
    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "identity",
        "init",
        "--dir",
        "client-identity",
    ]));

    assert!(help.contains("--key <PATH>"));
    assert!(help.contains("runewarp client identity init --key ./client.key"));
    assert!(stderr.contains("unexpected argument '--dir'"));
}

#[test]
fn identity_help_keeps_runewarp_branding_and_the_config_flag() {
    let tempdir = tempdir().unwrap();

    let group = stdout_of(runewarp(tempdir.path()).args(["client", "identity", "--help"]));
    let show = stdout_of(runewarp(tempdir.path()).args(["client", "identity", "show", "--help"]));

    assert!(group.contains("--config"));
    assert!(show.starts_with("Runewarp Client Identity"));
    assert!(show.contains("runewarp client identity show"));
    assert!(!show.contains("Config defaults:"));
}

#[test]
fn managed_configs_require_an_explicit_key_for_init_and_rotate() {
    let tempdir = tempdir().unwrap();
    fs::write(
        tempdir.path().join("managed-client.toml"),
        "[control]\naddress = \"control.example.test\"\n",
    )
    .unwrap();

    let stderr = stderr_of_failure(runewarp(tempdir.path()).args([
        "client",
        "--config",
        "managed-client.toml",
        "identity",
        "init",
    ]));
    runewarp(tempdir.path())
        .args([
            "client",
            "--config",
            "managed-client.toml",
            "identity",
            "init",
            "--key",
            "client.key",
        ])
        .assert()
        .success();

    assert!(stderr.contains("not supported for managed-mode configs without --key"));
    assert!(tempdir.path().join("client.key").is_file());
}

#[cfg(unix)]
#[test]
fn init_and_rotate_create_owner_only_keys_under_a_restrictive_umask() {
    let tempdir = tempdir().unwrap();
    let binary = assert_cmd::cargo::cargo_bin("runewarp");
    for subcommand in ["init", "rotate"] {
        let status = ProcessCommand::new("sh")
            .current_dir(tempdir.path())
            .arg("-c")
            .arg("umask 0777 && exec \"$0\" client identity \"$1\" --key client.key")
            .arg(&binary)
            .arg(subcommand)
            .status()
            .unwrap();

        assert!(
            status.success(),
            "`{subcommand}` must succeed under umask 0777"
        );
        assert_eq!(mode_of(&tempdir.path().join("client.key")), 0o600);
        IdentityKey::read(&tempdir.path().join("client.key")).unwrap();
    }
}
