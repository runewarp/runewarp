use std::error::Error;
use std::io;

use clap::{CommandFactory, Parser};

use crate::cli;
use crate::error_handling::{RunError, classify_runtime_error};
use runewarp::ShutdownMode;

mod certs;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownSignalEvent {
    CtrlC,
    Sigterm,
    Sigquit,
}

fn shutdown_mode_for_first_signal(event: ShutdownSignalEvent) -> ShutdownMode {
    match event {
        ShutdownSignalEvent::Sigquit => ShutdownMode::Fast,
        ShutdownSignalEvent::CtrlC | ShutdownSignalEvent::Sigterm => ShutdownMode::Graceful,
    }
}

fn should_escalate_to_fast(event: ShutdownSignalEvent) -> bool {
    matches!(
        event,
        ShutdownSignalEvent::CtrlC | ShutdownSignalEvent::Sigquit
    )
}

async fn wait_for_initial_shutdown_signal() -> io::Result<ShutdownSignalEvent> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).map_err(|error| io::Error::other(error.to_string()))?;
        let mut quit =
            signal(SignalKind::quit()).map_err(|error| io::Error::other(error.to_string()))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| io::Error::other(error.to_string()))?;
                Ok(ShutdownSignalEvent::CtrlC)
            }
            _ = terminate.recv() => Ok(ShutdownSignalEvent::Sigterm),
            _ = quit.recv() => Ok(ShutdownSignalEvent::Sigquit),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(ShutdownSignalEvent::CtrlC)
    }
}

async fn wait_for_fast_shutdown_signal() -> io::Result<ShutdownSignalEvent> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut quit =
            signal(SignalKind::quit()).map_err(|error| io::Error::other(error.to_string()))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| io::Error::other(error.to_string()))?;
                Ok(ShutdownSignalEvent::CtrlC)
            }
            _ = quit.recv() => Ok(ShutdownSignalEvent::Sigquit),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(ShutdownSignalEvent::CtrlC)
    }
}

type CommandResult = Result<(), Box<dyn Error>>;

#[cfg(test)]
mod tests {
    use super::{ShutdownSignalEvent, should_escalate_to_fast, shutdown_mode_for_first_signal};
    use runewarp::ShutdownMode;

    #[test]
    fn first_signal_maps_to_expected_shutdown_mode() {
        assert_eq!(
            shutdown_mode_for_first_signal(ShutdownSignalEvent::CtrlC),
            ShutdownMode::Graceful
        );
        assert_eq!(
            shutdown_mode_for_first_signal(ShutdownSignalEvent::Sigterm),
            ShutdownMode::Graceful
        );
        assert_eq!(
            shutdown_mode_for_first_signal(ShutdownSignalEvent::Sigquit),
            ShutdownMode::Fast
        );
    }

    #[test]
    fn only_ctrl_c_and_sigquit_escalate_to_fast() {
        assert!(should_escalate_to_fast(ShutdownSignalEvent::CtrlC));
        assert!(should_escalate_to_fast(ShutdownSignalEvent::Sigquit));
        assert!(!should_escalate_to_fast(ShutdownSignalEvent::Sigterm));
    }
}
