use std::path::PathBuf;

use crate::cli;
use crate::commands::CommandResult;

pub(crate) fn run(config: Option<PathBuf>, command: cli::ServerCertArgs) -> CommandResult {
    crate::cert_commands::run_server_cert_command(config, command)
}
