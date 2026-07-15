use std::path::{Path, PathBuf};

use runewarp::{
    SERVER_CA_FILENAME, initialize_manual_server_certificate, inspect_manual_server_certificate,
    renew_manual_server_certificate, resolve_server_cert_hostname,
    resolve_server_cert_material_dir, rotate_manual_server_certificate_authority,
};

use crate::cli;
use crate::commands::{CommandResult, certs};

pub(crate) fn run(config: Option<PathBuf>, command: cli::ServerCertArgs) -> CommandResult {
    match command.command {
        cli::ServerCertSubcommand::Init(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_material_dir(config, args.dir)?;
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
            let directory = resolve_server_cert_material_dir(config, args.dir)?;
            renew_manual_server_certificate(&directory)?;
            let hostname = inspect_manual_server_certificate(&directory)?.hostname;
            print_server_certificate_summary("Server certificate renewed", &directory, &hostname)?;
            Ok(())
        }
        cli::ServerCertSubcommand::RotateCa(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_material_dir(config, args.dir)?;
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
