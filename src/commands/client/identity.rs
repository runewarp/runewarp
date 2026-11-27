use std::path::{Path, PathBuf};

use runewarp::{
    IdentityKey, IdentityKeyInit, init_identity_key, is_managed_selected_client_config,
    resolve_client_identity_key_path, rotate_identity_key,
};

use crate::cli;
use crate::commands::CommandResult;

pub(crate) fn run(config: Option<PathBuf>, command: cli::ClientIdentityArgs) -> CommandResult {
    match command.command {
        cli::ClientIdentitySubcommand::Init(args) => {
            reject_managed_config_derived_identity_command(config.clone(), args.key.is_some())?;
            let key_path = resolve_client_identity_key_path(config, args.key)?;
            match init_identity_key(&key_path)? {
                IdentityKeyInit::Created(identity) => print_client_identity_summary(
                    "Client identity initialized",
                    &key_path,
                    identity,
                ),
                IdentityKeyInit::Existing(identity) => print_client_identity_summary(
                    "Client identity already exists",
                    &key_path,
                    identity,
                ),
            }
            Ok(())
        }
        cli::ClientIdentitySubcommand::Rotate(args) => {
            reject_managed_config_derived_identity_command(config.clone(), args.key.is_some())?;
            let key_path = resolve_client_identity_key_path(config, args.key)?;
            let rotated = rotate_identity_key(&key_path)?;
            print_client_identity_summary("Client identity rotated", &key_path, rotated);
            Ok(())
        }
        cli::ClientIdentitySubcommand::Show(args) => {
            let key_path = resolve_client_identity_key_path(config, args.key)?;
            println!("{}", IdentityKey::read(&key_path)?.client_identity());
            Ok(())
        }
    }
}

fn reject_managed_config_derived_identity_command(
    config: Option<PathBuf>,
    explicit_key: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if explicit_key {
        return Ok(());
    }
    if is_managed_selected_client_config(config)? {
        return Err(
            "client identity init and rotate are not supported for managed-mode configs without --key"
                .into(),
        );
    }
    Ok(())
}

fn print_client_identity_summary(
    headline: &str,
    key_path: &Path,
    client_identity: runewarp::ClientIdentity,
) {
    println!("{headline}: {client_identity}");
    println!("Identity key: {}", key_path.display());
}
