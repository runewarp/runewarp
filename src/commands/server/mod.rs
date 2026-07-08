use runewarp::{PreparedServer, ServerRuntimeArgs, resolve_server_config_from_cli};

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
    let server_result = server
        .run_until_shutdown(async {
            let _ = super::wait_for_orderly_shutdown_signal().await;
            runewarp::runtime_log::server_graceful_shutdown_started();
        })
        .await;
    if let Err(error) = server_result {
        return Err(logged_runtime_failure(Box::new(error)));
    }
    Ok(())
}
