use std::error::Error;
use std::io;

use clap::{CommandFactory, Parser};

use crate::cli;
use crate::error_handling::{RunError, classify_runtime_error};

mod client;
mod server;

pub(crate) async fn run(args: impl Iterator<Item = String>) -> Result<(), RunError> {
    let argv = std::iter::once(env!("CARGO_PKG_NAME").to_owned())
        .chain(args)
        .collect::<Vec<_>>();
    if argv.len() == 1 {
        let mut command = cli::Cli::command();
        command
            .print_help()
            .map_err(|error| RunError::Other(Box::new(error)))?;
        println!();
        return Ok(());
    }

    let cli = cli::Cli::try_parse_from(argv).map_err(RunError::Cli)?;
    match cli.command {
        Some(cli::TopLevelCommand::Server(command)) => {
            server::run(command).await.map_err(classify_runtime_error)
        }
        Some(cli::TopLevelCommand::Client(command)) => {
            client::run(command).await.map_err(classify_runtime_error)
        }
        None => Ok(()),
    }
}

async fn wait_for_orderly_shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).map_err(|error| io::Error::other(error.to_string()))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| io::Error::other(error.to_string()))?;
            }
            _ = terminate.recv() => {}
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    }
}

type CommandResult = Result<(), Box<dyn Error>>;
