use std::path::{Path, PathBuf};

use runewarp::{
    SERVER_CA_FILENAME, default_server_cert_material_dir, initialize_manual_server_certificate,
    inspect_manual_server_certificate, renew_manual_server_certificate,
    resolve_server_cert_material_dir_from_config, resolve_server_hostname_from_config,
    rotate_manual_server_certificate_authority,
};

use crate::cli;
use crate::commands::{CommandResult, certs};

pub(crate) fn run(config: Option<PathBuf>, command: cli::ServerCertArgs) -> CommandResult {
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

fn resolve_server_cert_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    certs::resolve_material_dir(
        config,
        directory,
        resolve_server_cert_material_dir_from_config,
        default_server_cert_material_dir,
    )
}

fn resolve_server_cert_hostname(
    config: Option<PathBuf>,
    hostname: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let configured_hostname =
        if let Some(config_path) = certs::candidate_config_path(config.clone()) {
            resolve_server_hostname_from_config(&config_path)
                .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })?
        } else {
            None
        };

    match (hostname, configured_hostname) {
        (Some(hostname), Some(configured_hostname)) => {
            if normalized_hostname_for_match(&hostname)
                != normalized_hostname_for_match(configured_hostname.as_str())
            {
                return Err(format!(
                    "--hostname `{hostname}` does not match configured server.hostname `{configured_hostname}`"
                )
                .into());
            }
            Ok(hostname)
        }
        (Some(hostname), None) => Ok(hostname),
        (None, Some(configured_hostname)) => Ok(configured_hostname.to_string()),
        (None, None) => {
            Err("server hostname is required via --hostname or server.hostname in config".into())
        }
    }
}

fn normalized_hostname_for_match(hostname: &str) -> String {
    hostname
        .strip_suffix('.')
        .unwrap_or(hostname)
        .to_ascii_lowercase()
}

fn print_server_certificate_summary(
    headline: &str,
    directory: &Path,
    hostname: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let certificate_window = certs::read_certificate_window(&directory.join("server.crt"))?;

    println!("{headline}");
    println!("Server hostname: {hostname}");
    println!("Certificate directory: {}", directory.display());
    println!(
        "Server certificate: {}",
        directory.join("server.crt").display()
    );
    println!(
        "Server certificate authority: {}",
        directory.join(SERVER_CA_FILENAME).display()
    );
    println!("Certificate lifetime: 90 days");
    println!(
        "Renew after (UTC): {}",
        certs::format_utc(
            certificate_window.issued_at
                + time::Duration::days(certs::MANUAL_CERT_RENEW_AFTER_DAYS),
        )
    );
    println!(
        "Issued at (UTC): {}",
        certs::format_utc(certificate_window.issued_at)
    );
    println!(
        "Expires at (UTC): {}",
        certs::format_utc(certificate_window.expires_at)
    );
    Ok(())
}

fn existing_server_cert_paths(directory: &Path) -> Vec<PathBuf> {
    [
        directory.join("server.crt"),
        directory.join("server.key"),
        directory.join(SERVER_CA_FILENAME),
        directory.join("state/server-ca.key"),
        directory.join("state/server-hostname.txt"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect()
}
