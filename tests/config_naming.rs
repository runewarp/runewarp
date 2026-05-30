use std::error::Error;
use std::fs;

use runewarp::{
    ClientConfig, ClientConfigResolutionDefaults, LogLevel, SelectedClientConfig,
    ServerCertificateConfig, load_client_config, load_server_config,
    resolve_selected_client_config,
};
use tempfile::tempdir;

#[test]
fn client_config_api_uses_config_vocabulary() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    let identity_directory = tempdir.path().join("client-identity");
    fs::create_dir(&identity_directory)?;
    fs::write(identity_directory.join("client.crt"), "placeholder")?;
    fs::write(identity_directory.join("client.key"), "placeholder")?;
    fs::write(
        identity_directory.join("client-identity.txt"),
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    )?;
    fs::write(
        tempdir.path().join("config.toml"),
        r#"
[client]
server-address = "Tunnel.Example.Test."
identity-dir = "client-identity"

[[client.services]]
backend-address = "localhost:8443"
"#,
    )?;

    let config: ClientConfig = load_client_config(&tempdir.path().join("config.toml"))?;
    assert_eq!(config.server_hostname.as_str(), "tunnel.example.test");
    assert_eq!(config.log_level, LogLevel::Info);

    let resolved = resolve_selected_client_config(
        SelectedClientConfig::Explicit(tempdir.path().join("config.toml")),
        &runewarp::ClientRuntimeArgs {
            server_address: None,
            backend_address: None,
        },
        &ClientConfigResolutionDefaults {
            identity_directory,
            public_cert_directory: tempdir.path().join("unused-public-cert"),
        },
    )?;
    assert_eq!(resolved.server_port, 443);
    Ok(())
}

#[test]
fn server_config_api_uses_config_vocabulary() -> Result<(), Box<dyn Error>> {
    let tempdir = tempdir()?;
    runewarp::initialize_manual_server_certificate(
        tempdir.path().join("server-cert").as_path(),
        "tunnel.example.test",
    )?;
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

    let config = load_server_config(&tempdir.path().join("config.toml"))?;
    assert_eq!(config.log_level, LogLevel::Info);
    assert_eq!(
        config.certificate,
        ServerCertificateConfig::Manual {
            directory: tempdir.path().join("server-cert"),
        }
    );
    Ok(())
}
