use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rustls_pemfile::certs;
use time::OffsetDateTime;
use x509_parser::parse_x509_certificate;

use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, SettingsError, XdgPathError,
    default_client_identity_material_dir, default_client_public_cert_material_dir,
    default_config_path, default_server_cert_material_dir, generate_client_identity,
    initialize_manual_client_public_cert, initialize_manual_server_certificate,
    inspect_manual_server_certificate, read_client_identity, renew_client_identity_certificate,
    renew_manual_client_public_cert, renew_manual_server_certificate,
    resolve_client_identity_material_dir_from_config,
    resolve_client_public_cert_material_dir_from_config,
    resolve_server_cert_material_dir_from_config, resolve_server_hostname_from_config,
    resolve_terminating_hostnames_from_config, rotate_client_identity,
    rotate_manual_client_public_cert_authority, rotate_manual_server_certificate_authority,
    select_client_config,
};

use crate::cli;

const MANUAL_CERT_RENEW_AFTER_DAYS: i64 = 60;

pub(crate) fn run_server_cert_command(
    config: Option<PathBuf>,
    command: cli::ServerCertArgs,
) -> Result<(), Box<dyn Error>> {
    match command.command {
        cli::ServerCertSubcommand::Init(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_dir(config, args.dir)?;
            if let Ok(existing_state) = inspect_manual_server_certificate(&directory) {
                if existing_state.hostname == hostname {
                    print_server_certificate_summary(
                        "Server certificate material already exists",
                        &directory,
                        &existing_state.hostname,
                    )?;
                    return Ok(());
                }

                return Err(format!(
                    "Server certificate material in {} already belongs to Server hostname {}. \
                     Use a different directory or rotate the existing material.",
                    directory.display(),
                    existing_state.hostname
                )
                .into());
            }
            let existing_paths = existing_server_cert_paths(&directory);
            if !existing_paths.is_empty() {
                return Err(format!(
                    "Server certificate material in {} is incomplete or inconsistent. Repair or \
                     remove the existing files and rerun `runewarp server cert init`.\nExisting \
                     files: {}",
                    directory.display(),
                    existing_paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }
            initialize_manual_server_certificate(&directory, &hostname)?;
            print_server_certificate_summary(
                "Server certificate initialized",
                &directory,
                &hostname,
            )?;
            Ok(())
        }
        cli::ServerCertSubcommand::Renew(args) => {
            let directory = resolve_server_cert_dir(config, args.dir)?;
            renew_manual_server_certificate(&directory)?;
            let hostname = inspect_manual_server_certificate(&directory)?.hostname;
            print_server_certificate_summary("Server certificate renewed", &directory, &hostname)?;
            Ok(())
        }
        cli::ServerCertSubcommand::RotateCa(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_dir(config, args.dir)?;
            rotate_manual_server_certificate_authority(&directory, &hostname)?;
            print_server_certificate_summary(
                "Server certificate authority rotated",
                &directory,
                &hostname,
            )?;
            Ok(())
        }
    }
}

pub(crate) fn run_client_identity_command(
    config: Option<PathBuf>,
    command: cli::ClientIdentityArgs,
) -> Result<(), Box<dyn Error>> {
    match command.command {
        cli::ClientIdentitySubcommand::Init(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            write_client_identity_artifacts(&directory)
        }
        cli::ClientIdentitySubcommand::Renew(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            let renewed = renew_client_identity_certificate(&directory)?;
            print_client_identity_summary(
                "Client identity renewed",
                &directory,
                renewed.client_identity,
            )?;
            Ok(())
        }
        cli::ClientIdentitySubcommand::Rotate(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            let rotated = rotate_client_identity(&directory)?;
            print_client_identity_summary(
                "Client identity rotated",
                &directory,
                rotated.client_identity,
            )?;
            Ok(())
        }
        cli::ClientIdentitySubcommand::Show(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            println!("{}", read_client_identity(&directory)?);
            Ok(())
        }
    }
}

pub(crate) fn run_client_public_cert_command(
    config: Option<PathBuf>,
    command: cli::ClientPublicCertArgs,
) -> Result<(), Box<dyn Error>> {
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
                directory
                    .join(runewarp::CLIENT_PUBLIC_CA_FILENAME)
                    .display()
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
                directory
                    .join(runewarp::CLIENT_PUBLIC_CA_FILENAME)
                    .display()
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
) -> Result<Vec<String>, Box<dyn Error>> {
    if let Some(h) = hostname {
        return Ok(vec![h]);
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
    Ok(hostnames)
}

fn resolve_client_public_cert_hostnames_from_config_required(
    config: Option<PathBuf>,
) -> Result<Vec<String>, Box<dyn Error>> {
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
    Ok(hostnames)
}

fn resolve_selected_client_config_path(
    config: Option<PathBuf>,
) -> Result<Option<PathBuf>, Box<dyn Error>> {
    match select_client_config(config)? {
        runewarp::SelectedClientConfig::Explicit(path)
        | runewarp::SelectedClientConfig::Discovered(path) => Ok(Some(path)),
        runewarp::SelectedClientConfig::None => Ok(None),
    }
}

fn resolve_client_public_cert_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn Error>> {
    resolve_material_dir(
        config,
        directory,
        resolve_client_public_cert_material_dir_from_config,
        default_client_public_cert_material_dir,
    )
}

fn resolve_server_cert_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn Error>> {
    resolve_material_dir(
        config,
        directory,
        resolve_server_cert_material_dir_from_config,
        default_server_cert_material_dir,
    )
}

fn resolve_client_identity_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn Error>> {
    resolve_material_dir(
        config,
        directory,
        resolve_client_identity_material_dir_from_config,
        default_client_identity_material_dir,
    )
}

fn resolve_server_cert_hostname(
    config: Option<PathBuf>,
    hostname: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let configured_hostname = if let Some(config_path) = candidate_config_path(config.clone()) {
        resolve_server_hostname_from_config(&config_path)
            .map_err(|error| -> Box<dyn Error> { Box::new(error) })?
    } else {
        None
    };

    match (hostname, configured_hostname) {
        (Some(hostname), Some(configured_hostname)) => {
            if normalized_hostname_for_match(&hostname)
                != normalized_hostname_for_match(&configured_hostname)
            {
                return Err(format!(
                    "--hostname `{hostname}` does not match configured server.hostname `{configured_hostname}`"
                )
                .into());
            }
            Ok(hostname)
        }
        (Some(hostname), None) => Ok(hostname),
        (None, Some(configured_hostname)) => Ok(configured_hostname),
        (None, None) => {
            Err("server hostname is required via --hostname or server.hostname in config".into())
        }
    }
}

fn resolve_material_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
    configured_dir: impl Fn(&Path) -> Result<Option<PathBuf>, SettingsError>,
    default_dir: impl Fn() -> Result<PathBuf, XdgPathError>,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(directory) = directory {
        return Ok(directory);
    }

    if let Some(config_path) = candidate_config_path(config)
        && let Some(configured_dir) =
            configured_dir(&config_path).map_err(|error| -> Box<dyn Error> { Box::new(error) })?
    {
        return Ok(configured_dir);
    }

    default_dir().map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

fn candidate_config_path(config: Option<PathBuf>) -> Option<PathBuf> {
    match config {
        Some(config) => Some(config),
        None => default_config_path()
            .ok()
            .filter(|default_config_path| default_config_path.is_file()),
    }
}

fn normalized_hostname_for_match(hostname: &str) -> String {
    hostname
        .strip_suffix('.')
        .unwrap_or(hostname)
        .to_ascii_lowercase()
}

fn write_client_identity_artifacts(directory: &Path) -> Result<(), Box<dyn Error>> {
    if let Ok(existing_identity) = read_client_identity(directory) {
        print_client_identity_summary(
            "Client identity already exists",
            directory,
            existing_identity,
        )?;
        return Ok(());
    }

    let existing_paths = existing_client_identity_paths(directory);
    if !existing_paths.is_empty() {
        return Err(format!(
            "Client identity material in {} is incomplete or inconsistent. Repair or remove the \
             existing files and rerun `runewarp client identity init`.\nExisting files: {}",
            directory.display(),
            existing_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into());
    }

    fs::create_dir_all(directory)?;
    let generated = generate_client_identity()?;
    write_new_file(
        &directory.join(CLIENT_KEY_FILENAME),
        generated.private_key_pem.as_bytes(),
    )?;
    write_new_file(
        &directory.join(CLIENT_CERT_FILENAME),
        generated.certificate_pem.as_bytes(),
    )?;
    write_new_file(
        &directory.join(CLIENT_IDENTITY_FILENAME),
        generated.client_identity.to_string().as_bytes(),
    )?;
    print_client_identity_summary(
        "Client identity initialized",
        directory,
        generated.client_identity,
    )?;
    Ok(())
}

fn print_client_identity_summary(
    headline: &str,
    directory: &Path,
    client_identity: runewarp::ClientIdentity,
) -> Result<(), Box<dyn Error>> {
    let certificate_window = read_certificate_window(&directory.join(CLIENT_CERT_FILENAME))?;

    println!("{headline}: {client_identity}");
    println!("Identity directory: {}", directory.display());
    println!("Certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
    println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
    println!(
        "Issued at (UTC): {}",
        format_utc(certificate_window.issued_at)
    );
    println!(
        "Renew after (UTC): {}",
        format_utc(
            certificate_window.issued_at
                + time::Duration::days(CLIENT_CERT_RENEW_AFTER_DAYS as i64),
        )
    );
    println!(
        "Expires at (UTC): {}",
        format_utc(certificate_window.expires_at)
    );
    Ok(())
}

fn print_server_certificate_summary(
    headline: &str,
    directory: &Path,
    hostname: &str,
) -> Result<(), Box<dyn Error>> {
    let certificate_window = read_certificate_window(&directory.join("server.crt"))?;

    println!("{headline}");
    println!("Server hostname: {hostname}");
    println!("Certificate directory: {}", directory.display());
    println!(
        "Server certificate: {}",
        directory.join("server.crt").display()
    );
    println!(
        "Server certificate authority: {}",
        directory.join(runewarp::SERVER_CA_FILENAME).display()
    );
    println!("Certificate lifetime: 90 days");
    println!(
        "Renew after (UTC): {}",
        format_utc(
            certificate_window.issued_at + time::Duration::days(MANUAL_CERT_RENEW_AFTER_DAYS)
        )
    );
    println!(
        "Issued at (UTC): {}",
        format_utc(certificate_window.issued_at)
    );
    println!(
        "Expires at (UTC): {}",
        format_utc(certificate_window.expires_at)
    );
    Ok(())
}

fn print_public_cert_timestamps(directory: &Path, hostname: &str) -> Result<(), Box<dyn Error>> {
    let certificate_path = runewarp::client_public_cert_leaf_dir(directory, hostname)
        .join(runewarp::CLIENT_PUBLIC_CERT_FILENAME);
    let certificate_window = read_certificate_window(&certificate_path)?;

    println!(
        "Leaf certificate lifetime: {} days",
        runewarp::CLIENT_PUBLIC_CERT_LIFETIME_DAYS
    );
    println!(
        "Issued at (UTC): {}",
        format_utc(certificate_window.issued_at)
    );
    println!(
        "Renew after (UTC): {}",
        format_utc(
            certificate_window.issued_at + time::Duration::days(MANUAL_CERT_RENEW_AFTER_DAYS)
        )
    );
    println!(
        "Expires at (UTC): {}",
        format_utc(certificate_window.expires_at)
    );
    Ok(())
}

struct CertificateWindow {
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

fn read_certificate_window(path: &Path) -> Result<CertificateWindow, Box<dyn Error>> {
    let certificate_pem = fs::read(path)?;
    let certificate_der = certs(&mut std::io::Cursor::new(certificate_pem))
        .next()
        .transpose()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing certificate"))?;
    let (_, certificate) = parse_x509_certificate(certificate_der.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid X.509 certificate"))?;

    Ok(CertificateWindow {
        issued_at: certificate.validity().not_before.to_datetime(),
        expires_at: certificate.validity().not_after.to_datetime(),
    })
}

fn format_utc(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting should succeed")
}

fn existing_client_identity_paths(directory: &Path) -> Vec<PathBuf> {
    [
        directory.join(CLIENT_KEY_FILENAME),
        directory.join(CLIENT_CERT_FILENAME),
        directory.join(CLIENT_IDENTITY_FILENAME),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect()
}

fn existing_server_cert_paths(directory: &Path) -> Vec<PathBuf> {
    [
        directory.join("server.crt"),
        directory.join("server.key"),
        directory.join(runewarp::SERVER_CA_FILENAME),
        directory.join("state/server-ca.key"),
        directory.join("state/server-hostname.txt"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect()
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
    let ca_cert = directory.join(runewarp::CLIENT_PUBLIC_CA_FILENAME);
    let ca_key = directory.join("state/public-ca.key");
    let leaf_dir = runewarp::client_public_cert_leaf_dir(directory, hostname);
    let leaf_cert = leaf_dir.join(runewarp::CLIENT_PUBLIC_CERT_FILENAME);
    let leaf_key = leaf_dir.join(runewarp::CLIENT_PUBLIC_KEY_FILENAME);

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

fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    Ok(())
}
