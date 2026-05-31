use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, default_client_identity_material_dir,
    generate_client_identity, read_client_identity, renew_client_identity_certificate,
    resolve_client_identity_material_dir_from_config, rotate_client_identity,
};

use crate::cli;
use crate::commands::{CommandResult, certs};

pub(crate) fn run(config: Option<PathBuf>, command: cli::ClientIdentityArgs) -> CommandResult {
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

fn resolve_client_identity_dir(
    config: Option<PathBuf>,
    directory: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    certs::resolve_material_dir(
        config,
        directory,
        resolve_client_identity_material_dir_from_config,
        default_client_identity_material_dir,
    )
}

fn write_client_identity_artifacts(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
) -> Result<(), Box<dyn std::error::Error>> {
    let certificate_window = certs::read_certificate_window(&directory.join(CLIENT_CERT_FILENAME))?;

    println!("{headline}: {client_identity}");
    println!("Identity directory: {}", directory.display());
    println!("Certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
    println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
    println!(
        "Issued at (UTC): {}",
        certs::format_utc(certificate_window.issued_at)
    );
    println!(
        "Renew after (UTC): {}",
        certs::format_utc(
            certificate_window.issued_at
                + time::Duration::days(CLIENT_CERT_RENEW_AFTER_DAYS as i64),
        )
    );
    println!(
        "Expires at (UTC): {}",
        certs::format_utc(certificate_window.expires_at)
    );
    Ok(())
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

fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    Ok(())
}
