use runewarp::{
    OrderlyShutdown, PreparedServer, QUIC_CLOSE_FLUSH_DURATION, ServerRuntimeArgs, ShutdownMode,
    resolve_server_config_from_cli,
};

use crate::cli;
use crate::commands::CommandResult;
use crate::config_hints::wrap_server_config_resolution_error;
use crate::error_handling::logged_runtime_failure;

mod cert;

pub(crate) async fn run(command: cli::ServerArgs) -> CommandResult {
    let runtime = ServerRuntimeArgs {
        hostname: command.hostname,
    };
    let config = command.config;
    if let Some(cli::ServerSubcommand::Cert(command)) = command.command {
        if let Some(hostname) = runtime.hostname {
            return Err(format!(
                "--hostname is only supported for `runewarp server`, not `runewarp server cert ...` \
                 (got `{hostname}`). Use `runewarp server cert init --hostname ...` or \
                 `runewarp server cert rotate-ca --hostname ...` for certificate commands."
            )
            .into());
        }
        return cert::run(config, command);
    }

    let config = resolve_server_config_from_cli(config, runtime)
        .map_err(wrap_server_config_resolution_error)?;
    runewarp::runtime_log::install(config.log_level)?;
    let server = match PreparedServer::bind(
        &config,
        config.public_bind_address,
        config.tunnel_connection_bind_address,
    )
    .await
    {
        Ok(server) => server,
        Err(error) => return Err(logged_runtime_failure(Box::new(error))),
    };
    runewarp::runtime_log::server_public_listener_ready(server.public_addr()?);
    runewarp::runtime_log::server_tunnel_listener_ready(server.tunnel_addr()?);
    let shutdown =
        OrderlyShutdown::new(config.graceful_shutdown_duration, QUIC_CLOSE_FLUSH_DURATION);
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let first_signal = match super::wait_for_initial_shutdown_signal().await {
            Ok(signal) => signal,
            Err(error) => {
                runewarp::runtime_log::emit(
                    runewarp::runtime_log::EventLevel::Error,
                    &format!(
                        "server shutdown signal handling unavailable; forcing fast shutdown: {error}"
                    ),
                );
                let _ = shutdown_signal.begin_fast();
                return;
            }
        };
        let mode = super::shutdown_mode_for_first_signal(first_signal);
        let effective_graceful_duration = match mode {
            ShutdownMode::Graceful => config.graceful_shutdown_duration,
            ShutdownMode::Fast => std::time::Duration::ZERO,
        };
        runewarp::runtime_log::server_orderly_shutdown_started(mode, effective_graceful_duration);
        match mode {
            ShutdownMode::Graceful => {
                let _ = shutdown_signal.begin_graceful();
                if super::should_escalate_to_fast(first_signal) {
                    match super::wait_for_fast_shutdown_signal().await {
                        Ok(signal) => {
                            if super::should_escalate_to_fast(signal)
                                && shutdown_signal.begin_fast()
                                    == runewarp::ShutdownTransition::EscalatedToFast
                            {
                                runewarp::runtime_log::server_orderly_shutdown_escalated();
                            }
                        }
                        Err(error) => {
                            runewarp::runtime_log::warning(
                                "server",
                                &format!(
                                    "fast shutdown escalation signal handling unavailable; continuing graceful shutdown: {error}"
                                ),
                            );
                        }
                    }
                }
            }
            ShutdownMode::Fast => {
                let _ = shutdown_signal.begin_fast();
            }
        }
    });
    let server_result = server.run_with_shutdown(&shutdown).await;
    if let Err(error) = server_result {
        return Err(logged_runtime_failure(Box::new(error)));
    }
    Ok(())
}
