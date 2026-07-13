use std::net::{Ipv4Addr, SocketAddr};

use runewarp::{ClientRuntimeArgs, resolve_client_config_from_cli};

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
        command,
    } = command;

    if let Some(cli::ClientSubcommand::Identity(command)) = command {
        let forbidden_flags = client_identity_forbidden_runtime_flags(
            &server_address,
            backend_address.as_deref(),
            control_address.as_deref(),
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
    };
    let config = resolve_client_config_from_cli(config.clone(), runtime)
        .map_err(wrap_client_config_resolution_error)?;
    runewarp::runtime_log::install(config.log_level)?;
    crate::client_runtime::run_until_orderly_shutdown(&config, wildcard(0), async {
        let signal = super::wait_for_initial_shutdown_signal().await?;
        Ok::<runewarp::ShutdownMode, std::io::Error>(super::shutdown_mode_for_first_signal(signal))
    })
    .await
    .map_err(logged_runtime_failure)
}

fn client_identity_forbidden_runtime_flags(
    server_addresses: &[String],
    backend_address: Option<&str>,
    control_address: Option<&str>,
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
    flags
}

fn client_public_cert_forbidden_runtime_flags(
    server_addresses: &[String],
    backend_address: Option<&str>,
    control_address: Option<&str>,
) -> Vec<&'static str> {
    client_identity_forbidden_runtime_flags(server_addresses, backend_address, control_address)
}

fn wildcard(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}
