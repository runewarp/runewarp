use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;

use runewarp::{
    PreparedClient, PreparedServer, generate_client_identity, load_client_settings,
    load_server_settings,
};

const CLIENT_KEY_FILENAME: &str = "client.key";
const CLIENT_CERT_FILENAME: &str = "client.crt";
const CLIENT_FINGERPRINT_FILENAME: &str = "client-fingerprint.txt";
const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        println!(
            "Runewarp currently ships a library-first Server and Client runtime; config-driven CLI commands land in phase 2."
        );
        return Ok(());
    };

    match command.as_str() {
        "keygen" => {
            let out_dir = parse_keygen_out_dir(args)?;
            write_keygen_artifacts(&out_dir)
        }
        "server" => {
            let config_path = parse_config_path(args)?;
            let settings = load_server_settings(&config_path)?;
            PreparedServer::bind(&settings, wildcard(443), wildcard(443))
                .await?
                .run()
                .await?;
            Ok(())
        }
        "client" => {
            let config_path = parse_config_path(args)?;
            let settings = load_client_settings(&config_path)?;
            PreparedClient::connect(&settings, wildcard(0))
                .await?
                .run()
                .await?;
            Ok(())
        }
        _ => {
            println!(
                "Runewarp currently ships a library-first Server and Client runtime; config-driven CLI commands land in phase 2."
            );
            Ok(())
        }
    }
}

fn parse_keygen_out_dir(
    mut args: impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let mut out_dir = std::path::PathBuf::from("certs");
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--out-dir" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --out-dir".into());
                };
                out_dir = value.into();
            }
            _ => {
                return Err(format!("unrecognized keygen argument: {argument}").into());
            }
        }
    }

    Ok(out_dir)
}

fn parse_config_path(
    mut args: impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let mut config_path = std::path::PathBuf::from(DEFAULT_CONFIG_PATH);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --config".into());
                };
                config_path = value.into();
            }
            _ => {
                return Err(format!("unrecognized command argument: {argument}").into());
            }
        }
    }

    Ok(config_path)
}

fn wildcard(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}

fn write_keygen_artifacts(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(out_dir)?;
    let generated = generate_client_identity()?;
    write_new_file(
        &out_dir.join(CLIENT_KEY_FILENAME),
        generated.private_key_pem.as_bytes(),
    )?;
    write_new_file(
        &out_dir.join(CLIENT_CERT_FILENAME),
        generated.certificate_pem.as_bytes(),
    )?;
    write_new_file(
        &out_dir.join(CLIENT_FINGERPRINT_FILENAME),
        generated.client_identity.to_string().as_bytes(),
    )?;
    println!("{}", generated.client_identity);
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    Ok(())
}
