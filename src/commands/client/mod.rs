use std::net::{Ipv4Addr, SocketAddr};

use runewarp::{ClientRuntime, ClientRuntimeArgs, resolve_client_config_from_cli};

use crate::cli;
use crate::commands::CommandResult;
use crate::config_hints::wrap_client_config_resolution_error;
use crate::error_handling::logged_runtime_failure;

mod identity;
mod public_cert;

pub(crate) async fn run(command: cli::ClientArgs) -> CommandResult {
    let cli::ClientArgs {
        config,
        server_address,
        backend_address,
        control_address,
        log_format,
        command,
    } = command;

    if let Some(cli::ClientSubcommand::Identity(command)) = command {
        let forbidden_flags = client_identity_forbidden_runtime_flags(
            &server_address,
            backend_address.as_deref(),
            control_address.as_deref(),
            log_format.is_some(),
        );
        if !forbidden_flags.is_empty() {
            return Err(format!(
                "{} may be used only with `runewarp client`, not `runewarp client identity ...`",
                forbidden_flags.join(" and ")
            )
            .into());
        }
        return identity::run(config, command);
    }

    if let Some(cli::ClientSubcommand::PublicCert(command)) = command {
        let forbidden_flags = client_public_cert_forbidden_runtime_flags(
            &server_address,
            backend_address.as_deref(),
            control_address.as_deref(),
            log_format.is_some(),
        );
        if !forbidden_flags.is_empty() {
            return Err(format!(
                "{} may be used only with `runewarp client`, not `runewarp client public-cert ...`",
                forbidden_flags.join(" and ")
            )
            .into());
        }
        return public_cert::run(config, command);
    }

    let runtime = ClientRuntimeArgs {
        server_addresses: server_address,
        backend_address,
        control_address,
        log_format: log_format.map(Into::into),
    };
    let config = resolve_client_config_from_cli(config.clone(), runtime)
        .map_err(wrap_client_config_resolution_error)?;
    runewarp::runtime_log::install_with_trace_export(
        config.log_level,
        config.log_format,
        config.trace_export.as_ref(),
        runewarp::TraceRole::Client,
    )?;
    let result = serve(config).await;
    runewarp::runtime_log::shutdown_trace_export().await;
    result
}

async fn serve(config: runewarp::ClientConfig) -> CommandResult {
    // Like the Server, only a first Ctrl-C or SIGQUIT arms graceful-to-fast escalation.
    let escalates = std::sync::atomic::AtomicBool::new(false);
    ClientRuntime::prepare(&config, wildcard(0))
        .await
        .map_err(|error| logged_runtime_failure(Box::new(error)))?
        .run_with_escalation(
            async {
                let signal = super::wait_for_initial_shutdown_signal().await?;
                escalates.store(
                    super::should_escalate_to_fast(signal),
                    std::sync::atomic::Ordering::SeqCst,
                );
                Ok::<runewarp::ShutdownMode, std::io::Error>(
                    super::shutdown_mode_for_first_signal(signal),
                )
            },
            async {
                if !escalates.load(std::sync::atomic::Ordering::SeqCst) {
                    return std::future::pending().await;
                }
                loop {
                    match super::wait_for_fast_shutdown_signal().await {
                        Ok(signal) if super::should_escalate_to_fast(signal) => return,
                        Ok(_) => {}
                        Err(error) => {
                            runewarp::runtime_log::warning(
                                "client",
                                &format!(
                                    "fast shutdown escalation signal handling unavailable; continuing graceful shutdown: {error}"
                                ),
                            );
                            return std::future::pending().await;
                        }
                    }
                }
            },
        )
        .await
        .map_err(logged_runtime_failure)
}

fn client_identity_forbidden_runtime_flags(
    server_addresses: &[String],
    backend_address: Option<&str>,
    control_address: Option<&str>,
    log_format: bool,
) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if !server_addresses.is_empty() {
        flags.push("--server-address");
    }
    if backend_address.is_some() {
        flags.push("--backend-address");
    }
    if control_address.is_some() {
        flags.push("--control-address");
    }
    if log_format {
        flags.push("--log-format");
    }
    flags
}

fn client_public_cert_forbidden_runtime_flags(
    server_addresses: &[String],
    backend_address: Option<&str>,
    control_address: Option<&str>,
    log_format: bool,
) -> Vec<&'static str> {
    client_identity_forbidden_runtime_flags(
        server_addresses,
        backend_address,
        control_address,
        log_format,
    )
}

fn wildcard(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}
