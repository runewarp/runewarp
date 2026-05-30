use std::path::PathBuf;

use crate::cli;
use crate::commands::CommandResult;

pub(crate) fn run(config: Option<PathBuf>, command: cli::ClientPublicCertArgs) -> CommandResult {
    crate::cert_commands::run_client_public_cert_command(config, command)
}
