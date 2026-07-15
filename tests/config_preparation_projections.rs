//! Characterization tests for Config preparation material projections.
//!
//! These assert operator-visible outcomes through the public preparation seam
//! used by material-management commands: explicit config keys, path resolution,
//! CLI/XDG precedence, terminating-hostname projection, and managed detection.

use std::error::Error;
use std::fs;

use runewarp::{
    is_managed_client_config, resolve_client_identity_material_dir,
    resolve_client_identity_material_dir_from_config, resolve_client_public_cert_material_dir,
    resolve_client_public_cert_material_dir_from_config, resolve_server_cert_hostname,
    resolve_server_cert_material_dir, resolve_server_cert_material_dir_from_config,
    resolve_server_hostname_from_config, resolve_terminating_hostnames_from_config,
};
use tempfile::tempdir;

#[test]
fn server_cert_material_dir_projects_relative_configured_path() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "configured/server-cert"
"#,
    )?;

    let projected = resolve_server_cert_material_dir_from_config(&config_path)?;
    assert_eq!(
        projected,
        Some(tempdir.path().join("configured/server-cert"))
    );

    let resolved = resolve_server_cert_material_dir(Some(config_path), None)?;
    assert_eq!(resolved, tempdir.path().join("configured/server-cert"));
    Ok(())
}

#[test]
fn server_cert_material_dir_prefers_cli_directory_over_config() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "configured/server-cert"
"#,
    )?;
    let cli_dir = tempdir.path().join("cli-dir");

    let resolved = resolve_server_cert_material_dir(Some(config_path), Some(cli_dir.clone()))?;
    assert_eq!(resolved, cli_dir);
    Ok(())
}

#[test]
fn server_hostname_projection_reads_configured_hostname() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[server]
hostname = "Tunnel.Example.Test."
"#,
    )?;

    let hostname = resolve_server_hostname_from_config(&config_path)?.expect("hostname");
    assert_eq!(hostname.as_str(), "tunnel.example.test");

    let resolved = resolve_server_cert_hostname(Some(config_path), None)?;
    assert_eq!(resolved, "tunnel.example.test");
    Ok(())
}

#[test]
fn server_cert_hostname_rejects_cli_mismatch_with_config() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[server]
hostname = "configured.example.test"
"#,
    )?;

    let error =
        resolve_server_cert_hostname(Some(config_path), Some("other.example.test".to_owned()))
            .expect_err("mismatch");
    assert!(
        error
            .to_string()
            .contains("does not match configured server.hostname")
    );
    Ok(())
}

#[test]
fn client_identity_and_public_cert_dirs_project_relative_paths() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[client]
server-address = "tunnel.example.test"
identity-dir = "configured/identity"
public-cert-dir = "configured/public-cert"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "localhost:8443"
tls-mode = "terminate"
"#,
    )?;

    assert_eq!(
        resolve_client_identity_material_dir_from_config(&config_path)?,
        Some(tempdir.path().join("configured/identity"))
    );
    assert_eq!(
        resolve_client_public_cert_material_dir_from_config(&config_path)?,
        Some(tempdir.path().join("configured/public-cert"))
    );
    assert_eq!(
        resolve_client_identity_material_dir(Some(config_path.clone()), None)?,
        tempdir.path().join("configured/identity")
    );
    assert_eq!(
        resolve_client_public_cert_material_dir(Some(config_path), None)?,
        tempdir.path().join("configured/public-cert")
    );
    Ok(())
}

#[test]
fn terminating_hostnames_are_normalized_sorted_and_deduplicated() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[client]
server-address = "tunnel.example.test"

[[client.services]]
public-hostnames = ["App.Example.Test.", "other.example.test"]
backend-address = "localhost:8443"
tls-mode = "terminate"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "localhost:9443"
tls-mode = "terminate"

[[client.services]]
public-hostnames = ["passthrough.example.test"]
backend-address = "localhost:10443"
tls-mode = "passthrough"
"#,
    )?;

    let hostnames = resolve_terminating_hostnames_from_config(&config_path)?.expect("hostnames");
    assert_eq!(
        hostnames
            .iter()
            .map(|hostname| hostname.as_str())
            .collect::<Vec<_>>(),
        vec!["app.example.test", "other.example.test"]
    );
    Ok(())
}

#[test]
fn managed_client_detection_follows_control_address_presence() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let static_path = tempdir.path().join("static.toml");
    fs::write(
        &static_path,
        r#"
[client]
server-address = "tunnel.example.test"
"#,
    )?;
    let managed_path = tempdir.path().join("managed.toml");
    fs::write(
        &managed_path,
        r#"
[control]
address = "https://control.example.test"

[client]
"#,
    )?;

    assert!(!is_managed_client_config(&static_path)?);
    assert!(is_managed_client_config(&managed_path)?);
    Ok(())
}

#[test]
fn omitted_material_keys_project_as_none_without_requiring_full_runtime_validity()
-> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let config_path = tempdir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
[server]
hostname = "tunnel.example.test"
"#,
    )?;

    assert_eq!(
        resolve_server_cert_material_dir_from_config(&config_path)?,
        None
    );
    Ok(())
}
