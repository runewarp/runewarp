use std::path::{Path, PathBuf};

use runewarp::{
    CLIENT_PUBLIC_CA_FILENAME, CLIENT_PUBLIC_CERT_FILENAME, CLIENT_PUBLIC_CERT_LIFETIME_DAYS,
    CLIENT_PUBLIC_KEY_FILENAME, default_client_public_cert_material_dir, default_config_path,
    initialize_manual_client_public_cert, renew_manual_client_public_cert,
    resolve_client_public_cert_material_dir_from_config, resolve_terminating_hostnames_from_config,
    rotate_manual_client_public_cert_authority, select_client_config,
};

use crate::cli;
use crate::commands::{CommandResult, certs};

pub(crate) fn run(config: Option<PathBuf>, command: cli::ClientPublicCertArgs) -> CommandResult {
    match command.command {
        cli::ClientPublicCertSubcommand::Init(args) => {
            let directory_config = config.clone();
            let hostnames = resolve_client_public_cert_hostnames(config, args.hostname)?;
            let directory = resolve_client_public_cert_dir(directory_config, args.dir)?;
            let mut initialized_hostnames = Vec::new();
            let mut existing_hostnames = Vec::new();
            for hostname in &hostnames {
                match inspect_client_public_cert_init_state(&directory, hostname) {
                    ClientPublicCertInitState::ReadyToInitialize => {
                        initialize_manual_client_public_cert(&directory, hostname)?;
                        initialized_hostnames.push(hostname.clone());
                    }
                    ClientPublicCertInitState::AlreadyExists => {
                        existing_hostnames.push(hostname.clone());
                    }
                    ClientPublicCertInitState::Partial(existing_paths) => {
                        return Err(format!(
                            "Public hostname certificate material in {} is incomplete or \
                             inconsistent. Repair or remove the existing files and rerun \
                             `runewarp client public-cert init`.\nExisting files: {}",
                            directory.display(),
                            existing_paths
                                .iter()
                                .map(|path| path.display().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                        .into());
                    }
                }
            }
            if !existing_hostnames.is_empty() {
                println!(
                    "Public hostname certificate material already exists for: {}",
                    existing_hostnames.join(", ")
                );
            }
            println!(
                "Public hostname CA: {}",
                directory.join(CLIENT_PUBLIC_CA_FILENAME).display()
            );
            if !initialized_hostnames.is_empty() {
                println!(
                    "Initialized leaf certificate(s) for: {}",
                    initialized_hostnames.join(", ")
                );
            }
            print_public_cert_timestamps(
                &directory,
                initialized_hostnames.first().unwrap_or(&hostnames[0]),
            )?;
            Ok(())
        }
        cli::ClientPublicCertSubcommand::Renew(args) => {
            let directory_config = config.clone();
            let hostnames = resolve_client_public_cert_hostnames(config, args.hostname)?;
            let directory = resolve_client_public_cert_dir(directory_config, args.dir)?;
            for hostname in &hostnames {
                renew_manual_client_public_cert(&directory, hostname)?;
            }
            println!("Renewed leaf certificate(s) for: {}", hostnames.join(", "));
            print_public_cert_timestamps(&directory, &hostnames[0])?;
            Ok(())
        }
        cli::ClientPublicCertSubcommand::RotateCa(args) => {
            let directory_config = config.clone();
            let hostnames = resolve_client_public_cert_hostnames_from_config_required(config)?;
            let directory = resolve_client_public_cert_dir(directory_config, args.dir)?;
            rotate_manual_client_public_cert_authority(&directory, &hostnames)?;
            println!(
                "Public hostname CA rotated: {}",
                directory.join(CLIENT_PUBLIC_CA_FILENAME).display()
            );
            println!("Reissued leaf certificate(s) for: {}", hostnames.join(", "));
            print_public_cert_timestamps(&directory, &hostnames[0])?;
            Ok(())
        }
    }
}

fn resolve_client_public_cert_hostnames(
    config: Option<PathBuf>,
    hostname: Option<String>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if let Some(hostname) = hostname {
        return Ok(vec![hostname]);
    }
    let Some(config_path) = resolve_selected_client_config_path(config)? else {
        return Err(
            "--hostname is required, or supply --config or a default client config to derive \
             targets from client.services[].public-hostnames (tls-mode = \"terminate\")"
                .into(),
        );
    };
    let Some(hostnames) = resolve_terminating_hostnames_from_config(&config_path)? else {
        return Err(format!(
            "config file {} has no [client] section; cannot derive terminating hostnames",
            config_path.display()
        )
        .into());
    };
    if hostnames.is_empty() {
        return Err(format!(
            "config file {} has no tls-mode = \"terminate\" services with explicit \
             public-hostnames; use --hostname to specify the target explicitly",
            config_path.display()
        )
        .into());
    }
    Ok(hostnames.into_iter().map(String::from).collect())
}

fn resolve_client_public_cert_hostnames_from_config_required(
    config: Option<PathBuf>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let config_path = match resolve_selected_client_config_path(config.clone())? {
        Some(config_path) => config_path,
        None => {
            let default_path = default_config_path()?;
            return Err(format!(
                "no selected config file for `client public-cert rotate-ca`; use -c, --config \
                 or create the default config at {}",
                default_path.display()
            )
            .into());
        }
    };
    let Some(hostnames) = resolve_terminating_hostnames_from_config(&config_path)? else {
        return Err(format!(
            "config file {} has no [client] section; cannot derive terminating hostnames",
            config_path.display()
        )
        .into());
    };
    if hostnames.is_empty() {
        return Err(format!(
            "config file {} has no tls-mode = \"terminate\" services with explicit \
             public-hostnames",
            config_path.display()
        )
        .into());
    }
    Ok(hostnames.into_iter().map(String::from).collect())
}

fn resolve_selected_client_config_path(
    config: Option<PathBuf>,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    match select_client_config(config)? {
        runewarp::SelectedClientConfig::Explicit(path)
        | runewarp::SelectedClientConfig::Discovered(path) => Ok(Some(path)),
        runewarp::SelectedClientConfig::None => Ok(None),
    }
}

fn resolve_client_public_cert_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    certs::resolve_material_dir(
        config,
        directory,
        resolve_client_public_cert_material_dir_from_config,
        default_client_public_cert_material_dir,
    )
}

fn print_public_cert_timestamps(
    directory: &Path,
    hostname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let certificate_path = runewarp::client_public_cert_leaf_dir(directory, hostname)
        .join(CLIENT_PUBLIC_CERT_FILENAME);
    let certificate_window = certs::read_certificate_window(&certificate_path)?;

    println!("Leaf certificate lifetime: {CLIENT_PUBLIC_CERT_LIFETIME_DAYS} days");
    println!(
        "Issued at (UTC): {}",
        certs::format_utc(certificate_window.issued_at)
    );
    println!(
        "Renew after (UTC): {}",
        certs::format_utc(
            certificate_window.issued_at
                + time::Duration::days(certs::MANUAL_CERT_RENEW_AFTER_DAYS),
        )
    );
    println!(
        "Expires at (UTC): {}",
        certs::format_utc(certificate_window.expires_at)
    );
    Ok(())
}

enum ClientPublicCertInitState {
    ReadyToInitialize,
    AlreadyExists,
    Partial(Vec<PathBuf>),
}

fn inspect_client_public_cert_init_state(
    directory: &Path,
    hostname: &str,
) -> ClientPublicCertInitState {
    let ca_cert = directory.join(CLIENT_PUBLIC_CA_FILENAME);
    let ca_key = directory.join("state/public-ca.key");
    let leaf_dir = runewarp::client_public_cert_leaf_dir(directory, hostname);
    let leaf_cert = leaf_dir.join(CLIENT_PUBLIC_CERT_FILENAME);
    let leaf_key = leaf_dir.join(CLIENT_PUBLIC_KEY_FILENAME);

    let ca_complete = ca_cert.exists() && ca_key.exists();
    let ca_partial = ca_cert.exists() ^ ca_key.exists();
    let leaf_complete = leaf_cert.exists() && leaf_key.exists();
    let leaf_partial = leaf_cert.exists() ^ leaf_key.exists();

    if !ca_complete && !leaf_complete && !ca_partial && !leaf_partial {
        return ClientPublicCertInitState::ReadyToInitialize;
    }
    if ca_complete && !leaf_complete && !leaf_partial {
        return ClientPublicCertInitState::ReadyToInitialize;
    }
    if ca_complete && leaf_complete {
        return ClientPublicCertInitState::AlreadyExists;
    }

    ClientPublicCertInitState::Partial(
        [ca_cert, ca_key, leaf_cert, leaf_key]
            .into_iter()
            .filter(|path| path.exists())
            .collect(),
    )
}
