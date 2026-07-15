use std::error::Error;
use std::fs;

use runewarp::config::LogLevel;
use runewarp::config::client::{
    ClientConfigResolutionDefaults, ClientRuntimeArgs, SelectedClientConfig,
    resolve_selected_client_config,
};
use runewarp::config::server::{load_server_config, resolve_server_hostname_from_config};
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME,
    initialize_manual_server_certificate,
};
use tempfile::tempdir;

#[test]
fn client_config_can_be_resolved_through_the_deep_config_module() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    write_identity_material(&identity_directory)?;

    let settings = resolve_selected_client_config(
        SelectedClientConfig::None,
        &ClientRuntimeArgs {
            server_addresses: vec!["Tunnel.Example.Test.".to_owned()],
            backend_address: Some("localhost:8443".to_owned()),
            control_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory: identity_directory.clone(),
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;

    assert_eq!(settings.server_hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.server_port, 443);
    assert_eq!(settings.log_level, LogLevel::Info);
    assert_eq!(settings.identity_directory, identity_directory);
    assert_eq!(settings.services.len(), 1);
    assert_eq!(settings.services[0].backend_address, "localhost:8443");
    Ok(())
}

#[test]
fn server_config_can_be_loaded_through_the_deep_config_module() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let cert_dir = tempdir.path().join("server-cert");
    initialize_manual_server_certificate(&cert_dir, "tunnel.example.test")?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#,
    )?;

    let hostname = resolve_server_hostname_from_config(&tempdir.path().join("config.toml"))?
        .expect("hostname");
    assert_eq!(hostname.as_str(), "tunnel.example.test");

    let settings = load_server_config(&tempdir.path().join("config.toml"))?;
    assert_eq!(settings.hostname.as_str(), "tunnel.example.test");
    assert_eq!(settings.log_level, LogLevel::Info);
    assert_eq!(settings.tunnels.len(), 1);
    assert_eq!(
        settings.tunnels[0].public_hostnames[0].as_str(),
        "app.example.test"
    );
    Ok(())
}

fn write_identity_material(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(path)?;
    fs::write(path.join(CLIENT_CERT_FILENAME), "placeholder certificate")?;
    fs::write(path.join(CLIENT_KEY_FILENAME), "placeholder key")?;
    fs::write(
        path.join(CLIENT_IDENTITY_FILENAME),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )?;
    Ok(())
}
