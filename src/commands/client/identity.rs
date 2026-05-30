use std::path::PathBuf;

use crate::cli;
use crate::commands::CommandResult;

pub(crate) fn run(config: Option<PathBuf>, command: cli::ClientIdentityArgs) -> CommandResult {
    crate::cert_commands::run_client_identity_command(config, command)
}
