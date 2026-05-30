mod cert_commands;
mod client_runtime;
mod error_handling;
mod reconnect_policy;

use std::env;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;

use cert_commands::{
    run_client_identity_command, run_client_public_cert_command, run_server_cert_command,
};
use clap::{CommandFactory, Parser};
use error_handling::{
    RunError, RunTermination, classify_runtime_error, finish_run, logged_runtime_failure,
};
use runewarp::{
    ClientRuntimeArgs, ClientSettingsResolutionError, PreparedServer,
    ServerSettingsResolutionError, SettingsError, default_config_path,
    resolve_client_settings_from_cli, resolve_server_settings_from_cli,
};

mod cli;

#[tokio::main]
async fn main() -> ExitCode {
    let mut stderr = io::stderr().lock();
    match finish_run(run(env::args().skip(1)).await, &mut stderr) {
        RunTermination::Exit(code) => code,
        RunTermination::Clap(error) => error.exit(),
    }
}

async fn run(args: impl Iterator<Item = String>) -> Result<(), RunError> {
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
        Some(cli::TopLevelCommand::Server(command)) => run_server_command(command)
            .await
            .map_err(classify_runtime_error),
        Some(cli::TopLevelCommand::Client(command)) => run_client_command_from_cli(command)
            .await
            .map_err(classify_runtime_error),
        None => Ok(()),
    }
}

async fn run_server_command(command: cli::ServerArgs) -> Result<(), Box<dyn Error>> {
    let config = command.config;
    if let Some(cli::ServerSubcommand::Cert(command)) = command.command {
        return run_server_cert_command(config, command);
    }

    let settings =
        resolve_server_settings_from_cli(config).map_err(wrap_server_settings_resolution_error)?;
    runewarp::runtime_log::install(settings.log_level)?;
    let server = match PreparedServer::bind(
        &settings,
        settings.public_bind_address,
        settings.tunnel_connection_bind_address,
    )
    .await
    {
        Ok(server) => server,
        Err(error) => return Err(logged_runtime_failure(Box::new(error))),
    };
    runewarp::runtime_log::server_public_listener_ready(server.public_addr()?);
    runewarp::runtime_log::server_tunnel_listener_ready(server.tunnel_addr()?);
    let server_result = server
        .run_until_shutdown(async {
            let _ = wait_for_orderly_shutdown_signal().await;
            runewarp::runtime_log::server_graceful_shutdown_started();
        })
        .await;
    if let Err(error) = server_result {
        return Err(logged_runtime_failure(Box::new(error)));
    }
    Ok(())
}

async fn run_client_command_from_cli(command: cli::ClientArgs) -> Result<(), Box<dyn Error>> {
    let cli::ClientArgs {
        config,
        server_address,
        backend_address,
        command,
    } = command;

    if let Some(cli::ClientSubcommand::Identity(command)) = command {
        let forbidden_flags = client_identity_forbidden_runtime_flags(
            server_address.as_deref(),
            backend_address.as_deref(),
        );
        if !forbidden_flags.is_empty() {
            return Err(format!(
                "{} may be used only with `runewarp client`, not `runewarp client identity ...`",
                forbidden_flags.join(" and ")
            )
            .into());
        }
        return run_client_identity_command(config, command);
    }

    if let Some(cli::ClientSubcommand::PublicCert(command)) = command {
        return run_client_public_cert_command(config, command);
    }

    let runtime = ClientRuntimeArgs {
        server_address,
        backend_address,
    };
    let settings = resolve_client_settings_from_cli(config.clone(), runtime)
        .map_err(wrap_client_settings_resolution_error)?;
    runewarp::runtime_log::install(settings.log_level)?;
    client_runtime::run_until_orderly_shutdown(
        &settings,
        wildcard(0),
        wait_for_orderly_shutdown_signal(),
    )
    .await
    .map_err(logged_runtime_failure)
}

fn client_identity_forbidden_runtime_flags(
    server_address: Option<&str>,
    backend_address: Option<&str>,
) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if server_address.is_some() {
        flags.push("--server-address");
    }
    if backend_address.is_some() {
        flags.push("--backend-address");
    }
    flags
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

fn wrap_server_settings_resolution_error(error: ServerSettingsResolutionError) -> Box<dyn Error> {
    if error.settings_error().is_some_and(server_material_missing) {
        return Box::new(io::Error::other(format!(
            "{error}\nHint: {}",
            error.selected_config_path().map_or_else(
                || "runewarp server cert init".to_owned(),
                server_cert_init_hint
            )
        )));
    }
    Box::new(error)
}

fn wrap_client_settings_resolution_error(error: ClientSettingsResolutionError) -> Box<dyn Error> {
    if error
        .validation_messages()
        .is_some_and(client_identity_messages_missing)
    {
        return Box::new(io::Error::other(format!(
            "{error}\nHint: {}",
            client_identity_init_hint_from_optional_path(error.selected_config_path())
        )));
    }
    Box::new(error)
}

fn server_material_missing(error: &SettingsError) -> bool {
    settings_messages(error).iter().any(|message| {
        message.starts_with("server.cert-dir directory not found:")
            || message.starts_with("server.cert-dir file not found:")
    })
}

fn settings_messages(error: &SettingsError) -> &[String] {
    match error {
        SettingsError::Validation { messages, .. } => messages,
        SettingsError::Read { .. } | SettingsError::Parse { .. } => &[],
    }
}

fn server_cert_init_hint(config_path: &Path) -> String {
    hint_command("runewarp server cert init", config_path)
}

fn client_identity_init_hint(config_path: &Path) -> String {
    hint_command("runewarp client identity init", config_path)
}

fn client_identity_init_hint_from_optional_path(config_path: Option<&Path>) -> String {
    config_path.map_or_else(
        || "runewarp client identity init".to_owned(),
        client_identity_init_hint,
    )
}

fn client_identity_messages_missing(messages: &[String]) -> bool {
    messages.iter().any(|message| {
        message.starts_with("client.identity-dir directory not found:")
            || message.starts_with("client.identity-dir file not found:")
    })
}

fn hint_command(base: &str, config_path: &Path) -> String {
    if uses_nondefault_config_path(config_path) {
        format!("{base} --config {}", config_path.display())
    } else {
        base.to_owned()
    }
}

fn uses_nondefault_config_path(config_path: &Path) -> bool {
    match default_config_path() {
        Ok(default_path) => default_path != config_path,
        Err(_) => true,
    }
}

fn wildcard(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}
