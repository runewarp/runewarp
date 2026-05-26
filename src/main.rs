use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use clap::{CommandFactory, Parser};
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientRuntimeArgs,
    ClientSettingsResolutionError, PreparedClient, PreparedServer, ServerSettingsResolutionError,
    SettingsError, XdgPathError, default_client_identity_material_dir,
    default_client_public_cert_material_dir, default_config_path, default_server_cert_material_dir,
    generate_client_identity, initialize_manual_client_public_cert,
    initialize_manual_server_certificate, renew_client_identity_certificate,
    renew_manual_client_public_cert, renew_manual_server_certificate,
    resolve_client_identity_material_dir_from_config,
    resolve_client_public_cert_material_dir_from_config, resolve_client_settings_from_cli,
    resolve_server_cert_material_dir_from_config, resolve_server_hostname_from_config,
    resolve_server_settings_from_cli, resolve_terminating_hostnames_from_config,
    rotate_client_identity, rotate_manual_client_public_cert_authority,
    rotate_manual_server_certificate_authority,
};
use time::OffsetDateTime;
use tokio::net::lookup_host;

mod cli;

enum RunError {
    Cli(clap::Error),
    Other(Box<dyn Error>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryAttemptKind {
    Initial,
    ImmediateRetry,
    IntervalRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryDisposition {
    Immediate,
    Interval,
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientTunnelDialTarget {
    configured_server_addr: String,
    resolved_server_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::Cli(error)) => error.exit(),
        Err(RunError::Other(error)) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
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
        Some(cli::TopLevelCommand::Server(command)) => {
            run_server_command(command).await.map_err(RunError::Other)
        }
        Some(cli::TopLevelCommand::Client(command)) => run_client_command_from_cli(command)
            .await
            .map_err(RunError::Other),
        None => Ok(()),
    }
}

async fn run_client_command(
    settings: &runewarp::ClientSettings,
    local_bind_addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let mut connected_once = false;
    loop {
        ensure_client_identity_fresh(&settings.identity_directory)?;
        let phase = client_tunnel_phase(connected_once);
        let (client, connected_dial_target) = retry_with_immediate_retry(
            settings.reconnect_interval,
            retry_disposition_for_client_connect_error,
            |attempt_kind| async move {
                let log_attempt_kind = client_tunnel_attempt_kind(attempt_kind);
                let dial_target = match resolve_client_tunnel_dial_target(settings).await {
                    Ok(dial_target) => dial_target,
                    Err(error) => {
                        runewarp::runtime_log::client_tunnel_resolution_failed(
                            phase,
                            log_attempt_kind,
                            &configured_server_addr(
                                &settings.server_hostname,
                                settings.server_port,
                            ),
                            settings.reconnect_interval,
                            &error.to_string(),
                        );
                        return Err(error);
                    }
                };
                runewarp::runtime_log::client_tunnel_connecting(
                    phase,
                    log_attempt_kind,
                    &dial_target.configured_server_addr,
                    dial_target.resolved_server_addr,
                    settings.reconnect_interval,
                );
                match PreparedClient::connect_to(
                    settings,
                    local_bind_addr,
                    dial_target.resolved_server_addr,
                )
                .await
                {
                    Ok(client) => {
                        runewarp::runtime_log::client_tunnel_connected(
                            phase,
                            &dial_target.configured_server_addr,
                            dial_target.resolved_server_addr,
                        );
                        Ok((client, dial_target))
                    }
                    Err(error) => {
                        if error
                            .source()
                            .and_then(|source| {
                                source.downcast_ref::<runewarp::ClientConnectError>()
                            })
                            .is_some_and(
                                runewarp::ClientConnectError::is_unauthorized_client_identity,
                            )
                        {
                            runewarp::runtime_log::client_tunnel_unauthorized(
                                log_attempt_kind,
                                &dial_target.configured_server_addr,
                                &error.to_string(),
                            );
                        } else {
                            runewarp::runtime_log::client_tunnel_connect_failed(
                                phase,
                                log_attempt_kind,
                                &dial_target.configured_server_addr,
                                dial_target.resolved_server_addr,
                                settings.reconnect_interval,
                                &error.to_string(),
                            );
                        }
                        Err(error)
                    }
                }
            },
            |delay| tokio::time::sleep(delay),
        )
        .await
        .map_err(|error| -> Box<dyn Error> { Box::new(error) })?;
        connected_once = true;

        if let Err(error) = client.run().await {
            if is_unauthorized_client_connection_error(&error) {
                runewarp::runtime_log::client_tunnel_unauthorized(
                    client_tunnel_unauthorized_attempt_kind(connected_once),
                    &connected_dial_target.configured_server_addr,
                    &error.to_string(),
                );
                tokio::time::sleep(settings.reconnect_interval).await;
            } else {
                runewarp::runtime_log::client_tunnel_disconnected(
                    &connected_dial_target.configured_server_addr,
                    connected_dial_target.resolved_server_addr,
                    &error.to_string(),
                );
            }
            continue;
        }

        return Ok(());
    }
}

fn ensure_client_identity_fresh(
    directory: &Path,
) -> Result<(), runewarp::ClientIdentityMaterialError> {
    match runewarp::inspect_client_certificate_renewal(directory, OffsetDateTime::now_utc())? {
        runewarp::ClientCertificateRenewalDecision::NotDue { .. } => Ok(()),
        runewarp::ClientCertificateRenewalDecision::Due { .. }
        | runewarp::ClientCertificateRenewalDecision::Expired { .. } => {
            runewarp::renew_client_identity_certificate(directory)?;
            Ok(())
        }
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
    PreparedServer::bind(
        &settings,
        settings.public_bind_address,
        settings.tunnel_connection_bind_address,
    )
    .await?
    .run()
    .await?;
    Ok(())
}

fn run_server_cert_command(
    config: Option<std::path::PathBuf>,
    command: cli::ServerCertArgs,
) -> Result<(), Box<dyn Error>> {
    match command.command {
        cli::ServerCertSubcommand::Init(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_dir(config, args.dir)?;
            initialize_manual_server_certificate(&directory, &hostname)?;
            Ok(())
        }
        cli::ServerCertSubcommand::Renew(args) => {
            let directory = resolve_server_cert_dir(config, args.dir)?;
            renew_manual_server_certificate(&directory)?;
            Ok(())
        }
        cli::ServerCertSubcommand::RotateCa(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_dir(config, args.dir)?;
            rotate_manual_server_certificate_authority(&directory, &hostname)?;
            Ok(())
        }
    }
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
    run_client_command(&settings, wildcard(0)).await
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

fn run_client_identity_command(
    config: Option<std::path::PathBuf>,
    command: cli::ClientIdentityArgs,
) -> Result<(), Box<dyn Error>> {
    match command.command {
        cli::ClientIdentitySubcommand::Init(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            write_client_identity_artifacts(&directory)
        }
        cli::ClientIdentitySubcommand::Renew(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            let renewed = renew_client_identity_certificate(&directory)?;
            println!("Client identity: {}", renewed.client_identity);
            println!("Renewed certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
            println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
            Ok(())
        }
        cli::ClientIdentitySubcommand::Rotate(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            let rotated = rotate_client_identity(&directory)?;
            println!("Client identity: {}", rotated.client_identity);
            println!("Rotated certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
            println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
            Ok(())
        }
    }
}

fn run_client_public_cert_command(
    config: Option<std::path::PathBuf>,
    command: cli::ClientPublicCertArgs,
) -> Result<(), Box<dyn Error>> {
    match command.command {
        cli::ClientPublicCertSubcommand::Init(args) => {
            let directory = resolve_client_public_cert_dir(config.clone(), args.dir)?;
            let hostnames = resolve_client_public_cert_hostnames(config, args.hostname)?;
            for hostname in &hostnames {
                initialize_manual_client_public_cert(&directory, hostname)?;
            }
            println!(
                "Public hostname CA: {}",
                directory
                    .join(runewarp::CLIENT_PUBLIC_CA_FILENAME)
                    .display()
            );
            println!(
                "Initialized leaf certificate(s) for: {}",
                hostnames.join(", ")
            );
            println!(
                "Leaf certificate lifetime: {} days",
                runewarp::CLIENT_PUBLIC_CERT_LIFETIME_DAYS
            );
            Ok(())
        }
        cli::ClientPublicCertSubcommand::Renew(args) => {
            let directory = resolve_client_public_cert_dir(config.clone(), args.dir)?;
            let hostnames = resolve_client_public_cert_hostnames(config, args.hostname)?;
            for hostname in &hostnames {
                renew_manual_client_public_cert(&directory, hostname)?;
            }
            println!("Renewed leaf certificate(s) for: {}", hostnames.join(", "));
            println!(
                "Leaf certificate lifetime: {} days",
                runewarp::CLIENT_PUBLIC_CERT_LIFETIME_DAYS
            );
            Ok(())
        }
        cli::ClientPublicCertSubcommand::RotateCa(args) => {
            let directory = resolve_client_public_cert_dir(config.clone(), args.dir)?;
            let hostnames = resolve_client_public_cert_hostnames_from_config_required(config)?;
            rotate_manual_client_public_cert_authority(&directory, &hostnames)?;
            println!(
                "Public hostname CA rotated: {}",
                directory
                    .join(runewarp::CLIENT_PUBLIC_CA_FILENAME)
                    .display()
            );
            println!("Reissued leaf certificate(s) for: {}", hostnames.join(", "));
            println!(
                "Leaf certificate lifetime: {} days",
                runewarp::CLIENT_PUBLIC_CERT_LIFETIME_DAYS
            );
            Ok(())
        }
    }
}

/// Resolves the set of hostnames to target for `client public-cert init` or
/// `client public-cert renew`.
///
/// - If `--hostname H` was supplied explicitly, returns `[H]`.
/// - If `--hostname` was omitted and a config path is available, derives the
///   set from `public-hostnames` on terminating services in the config.
/// - If neither source is available, returns an error prompting the operator
///   to supply one.
fn resolve_client_public_cert_hostnames(
    config: Option<std::path::PathBuf>,
    hostname: Option<String>,
) -> Result<Vec<String>, Box<dyn Error>> {
    if let Some(h) = hostname {
        return Ok(vec![h]);
    }
    let Some(config_path) = config else {
        return Err(
            "--hostname is required, or supply --config to derive targets from \
             client.services[].public-hostnames (tls-mode = \"terminate\")"
                .into(),
        );
    };
    let Some(hostnames) = resolve_terminating_hostnames_from_config(&config_path)? else {
        return Err(format!(
            "config file {} has no [client] section; cannot derive terminating hostnames",
            config_path.display()
        )
        .into());
    };
    if hostnames.is_empty() {
        return Err(format!(
            "config file {} has no tls-mode = \"terminate\" services with explicit \
             public-hostnames; use --hostname to specify the target explicitly",
            config_path.display()
        )
        .into());
    }
    Ok(hostnames)
}

/// Like `resolve_client_public_cert_hostnames` but always requires config
/// (used by `rotate-ca` which has no `--hostname` flag).
fn resolve_client_public_cert_hostnames_from_config_required(
    config: Option<std::path::PathBuf>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let Some(config_path) = config else {
        return Err(
            "--config is required for `client public-cert rotate-ca`; the managed hostname \
             set is derived from client.services[].public-hostnames \
             (tls-mode = \"terminate\")"
                .into(),
        );
    };
    let Some(hostnames) = resolve_terminating_hostnames_from_config(&config_path)? else {
        return Err(format!(
            "config file {} has no [client] section; cannot derive terminating hostnames",
            config_path.display()
        )
        .into());
    };
    if hostnames.is_empty() {
        return Err(format!(
            "config file {} has no tls-mode = \"terminate\" services with explicit \
             public-hostnames",
            config_path.display()
        )
        .into());
    }
    Ok(hostnames)
}

fn resolve_client_public_cert_dir(
    config: Option<std::path::PathBuf>,
    directory: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    resolve_material_dir(
        config,
        directory,
        resolve_client_public_cert_material_dir_from_config,
        default_client_public_cert_material_dir,
    )
}

fn retry_disposition_for_client_connect_error(
    error: &runewarp::ClientStartupError,
) -> RetryDisposition {
    match error {
        runewarp::ClientStartupError::Resolve(_)
        | runewarp::ClientStartupError::MissingServerAddress { .. } => RetryDisposition::Immediate,
        runewarp::ClientStartupError::Connect(source)
            if source.is_unauthorized_client_identity() =>
        {
            RetryDisposition::Interval
        }
        runewarp::ClientStartupError::Connect(_) => RetryDisposition::Immediate,
        _ => RetryDisposition::Stop,
    }
}

fn client_tunnel_phase(connected_once: bool) -> runewarp::runtime_log::ClientTunnelPhase {
    if connected_once {
        runewarp::runtime_log::ClientTunnelPhase::Reconnecting
    } else {
        runewarp::runtime_log::ClientTunnelPhase::Establishing
    }
}

fn client_tunnel_attempt_kind(
    attempt_kind: RetryAttemptKind,
) -> runewarp::runtime_log::ClientTunnelAttemptKind {
    match attempt_kind {
        RetryAttemptKind::Initial => runewarp::runtime_log::ClientTunnelAttemptKind::Initial,
        RetryAttemptKind::ImmediateRetry => {
            runewarp::runtime_log::ClientTunnelAttemptKind::ImmediateRetry
        }
        RetryAttemptKind::IntervalRetry => {
            runewarp::runtime_log::ClientTunnelAttemptKind::IntervalRetry
        }
    }
}

fn client_tunnel_unauthorized_attempt_kind(
    connected_once: bool,
) -> runewarp::runtime_log::ClientTunnelAttemptKind {
    if connected_once {
        runewarp::runtime_log::ClientTunnelAttemptKind::IntervalRetry
    } else {
        runewarp::runtime_log::ClientTunnelAttemptKind::Initial
    }
}

async fn resolve_client_tunnel_dial_target(
    settings: &runewarp::ClientSettings,
) -> Result<ClientTunnelDialTarget, runewarp::ClientStartupError> {
    let mut server_addrs = lookup_host((settings.server_hostname.as_str(), settings.server_port))
        .await
        .map_err(runewarp::ClientStartupError::Resolve)?;
    let Some(resolved_server_addr) = server_addrs.next() else {
        return Err(runewarp::ClientStartupError::MissingServerAddress {
            server_hostname: settings.server_hostname.clone(),
        });
    };
    Ok(ClientTunnelDialTarget {
        configured_server_addr: configured_server_addr(
            &settings.server_hostname,
            settings.server_port,
        ),
        resolved_server_addr,
    })
}

fn configured_server_addr(server_hostname: &str, server_port: u16) -> String {
    if server_hostname.contains(':') && !server_hostname.starts_with('[') {
        format!("[{server_hostname}]:{server_port}")
    } else {
        format!("{server_hostname}:{server_port}")
    }
}

fn is_unauthorized_client_connection_error(error: &quinn::ConnectionError) -> bool {
    error.to_string().contains("ApplicationVerificationFailure")
}

async fn retry_with_immediate_retry<T, E, Attempt, AttemptFuture, Sleep, SleepFuture>(
    retry_interval: Duration,
    retry_disposition: impl Fn(&E) -> RetryDisposition,
    mut attempt: Attempt,
    mut sleep: Sleep,
) -> Result<T, E>
where
    Attempt: FnMut(RetryAttemptKind) -> AttemptFuture,
    AttemptFuture: Future<Output = Result<T, E>>,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    let mut used_immediate_retry = false;
    let mut attempt_kind = RetryAttemptKind::Initial;
    loop {
        match attempt(attempt_kind).await {
            Ok(result) => return Ok(result),
            Err(error) => match retry_disposition(&error) {
                RetryDisposition::Immediate if used_immediate_retry => {
                    sleep(retry_interval).await;
                    attempt_kind = RetryAttemptKind::IntervalRetry;
                }
                RetryDisposition::Immediate => {
                    used_immediate_retry = true;
                    attempt_kind = RetryAttemptKind::ImmediateRetry;
                }
                RetryDisposition::Interval => {
                    used_immediate_retry = true;
                    sleep(retry_interval).await;
                    attempt_kind = RetryAttemptKind::IntervalRetry;
                }
                RetryDisposition::Stop => return Err(error),
            },
        }
    }
}

fn resolve_server_cert_dir(
    config: Option<std::path::PathBuf>,
    directory: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    resolve_material_dir(
        config,
        directory,
        resolve_server_cert_material_dir_from_config,
        default_server_cert_material_dir,
    )
}

fn resolve_client_identity_dir(
    config: Option<std::path::PathBuf>,
    directory: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    resolve_material_dir(
        config,
        directory,
        resolve_client_identity_material_dir_from_config,
        default_client_identity_material_dir,
    )
}

fn resolve_server_cert_hostname(
    config: Option<std::path::PathBuf>,
    hostname: Option<String>,
) -> Result<String, Box<dyn Error>> {
    let configured_hostname = if let Some(config_path) = candidate_config_path(config.clone()) {
        resolve_server_hostname_from_config(&config_path)
            .map_err(|error| -> Box<dyn Error> { Box::new(error) })?
    } else {
        None
    };

    match (hostname, configured_hostname) {
        (Some(hostname), Some(configured_hostname)) => {
            if normalized_hostname_for_match(&hostname)
                != normalized_hostname_for_match(&configured_hostname)
            {
                return Err(format!(
                    "--hostname `{hostname}` does not match configured server.hostname `{configured_hostname}`"
                )
                .into());
            }
            Ok(hostname)
        }
        (Some(hostname), None) => Ok(hostname),
        (None, Some(configured_hostname)) => Ok(configured_hostname),
        (None, None) => {
            Err("server hostname is required via --hostname or server.hostname in config".into())
        }
    }
}

fn resolve_material_dir(
    config: Option<std::path::PathBuf>,
    directory: Option<std::path::PathBuf>,
    configured_dir: impl Fn(&Path) -> Result<Option<std::path::PathBuf>, SettingsError>,
    default_dir: impl Fn() -> Result<std::path::PathBuf, XdgPathError>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    if let Some(directory) = directory {
        return Ok(directory);
    }

    if let Some(config_path) = candidate_config_path(config)
        && let Some(configured_dir) =
            configured_dir(&config_path).map_err(|error| -> Box<dyn Error> { Box::new(error) })?
    {
        return Ok(configured_dir);
    }

    default_dir().map_err(|error| -> Box<dyn Error> { Box::new(error) })
}

fn candidate_config_path(config: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    match config {
        Some(config) => Some(config),
        None => default_config_path()
            .ok()
            .filter(|default_config_path| default_config_path.is_file()),
    }
}

fn normalized_hostname_for_match(hostname: &str) -> String {
    hostname
        .strip_suffix('.')
        .unwrap_or(hostname)
        .to_ascii_lowercase()
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
fn write_client_identity_artifacts(directory: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory)?;
    let generated = generate_client_identity()?;
    write_new_file(
        &directory.join(CLIENT_KEY_FILENAME),
        generated.private_key_pem.as_bytes(),
    )?;
    write_new_file(
        &directory.join(CLIENT_CERT_FILENAME),
        generated.certificate_pem.as_bytes(),
    )?;
    write_new_file(
        &directory.join(CLIENT_IDENTITY_FILENAME),
        generated.client_identity.to_string().as_bytes(),
    )?;
    println!("Client identity: {}", generated.client_identity);
    println!("Initial certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
    println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rcgen::{CertificateParams, KeyPair, PublicKeyData};
    use tempfile::tempdir;
    use time::{Duration as TimeDuration, OffsetDateTime};

    use runewarp::{
        CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_IDENTITY_FILENAME,
        CLIENT_KEY_FILENAME, ClientIdentity,
    };

    use super::{
        RetryAttemptKind, RetryDisposition, client_tunnel_unauthorized_attempt_kind,
        ensure_client_identity_fresh, retry_with_immediate_retry,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        ImmediateRetry,
        IntervalRetry,
        Permanent,
    }

    #[tokio::test]
    async fn retries_immediately_once_then_waits_for_the_retry_interval() {
        let attempts = Arc::new(Mutex::new(0));
        let retry_attempts = Arc::new(Mutex::new(Vec::new()));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let retry_interval = Duration::from_secs(5);

        let result = retry_with_immediate_retry(
            retry_interval,
            |error: &TestError| match error {
                TestError::ImmediateRetry => RetryDisposition::Immediate,
                TestError::IntervalRetry => RetryDisposition::Interval,
                TestError::Permanent => RetryDisposition::Stop,
            },
            {
                let attempts = attempts.clone();
                let retry_attempts = retry_attempts.clone();
                move |attempt_kind| {
                    let attempts = attempts.clone();
                    let retry_attempts = retry_attempts.clone();
                    async move {
                        retry_attempts.lock().unwrap().push(attempt_kind);
                        let mut attempts = attempts.lock().unwrap();
                        *attempts += 1;
                        match *attempts {
                            1 | 2 => Err(TestError::ImmediateRetry),
                            3 => Ok(()),
                            _ => unreachable!(),
                        }
                    }
                }
            },
            {
                let sleeps = sleeps.clone();
                move |delay| {
                    let sleeps = sleeps.clone();
                    async move {
                        sleeps.lock().unwrap().push(delay);
                    }
                }
            },
        )
        .await;

        assert_eq!(result, Ok(()));
        assert_eq!(
            *retry_attempts.lock().unwrap(),
            vec![
                RetryAttemptKind::Initial,
                RetryAttemptKind::ImmediateRetry,
                RetryAttemptKind::IntervalRetry,
            ]
        );
        assert_eq!(*sleeps.lock().unwrap(), vec![retry_interval]);
    }

    #[tokio::test]
    async fn permanent_errors_do_not_retry() {
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let result = retry_with_immediate_retry(
            Duration::from_secs(5),
            |error: &TestError| match error {
                TestError::ImmediateRetry => RetryDisposition::Immediate,
                TestError::IntervalRetry => RetryDisposition::Interval,
                TestError::Permanent => RetryDisposition::Stop,
            },
            |_attempt_kind| async { Result::<(), TestError>::Err(TestError::Permanent) },
            {
                let sleeps = sleeps.clone();
                move |delay| {
                    let sleeps = sleeps.clone();
                    async move {
                        sleeps.lock().unwrap().push(delay);
                    }
                }
            },
        )
        .await;

        assert_eq!(result, Err(TestError::Permanent));
        assert!(sleeps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn interval_retry_errors_skip_the_immediate_retry_attempt() {
        let retry_attempts = Arc::new(Mutex::new(Vec::new()));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let retry_interval = Duration::from_secs(5);

        let result = retry_with_immediate_retry(
            retry_interval,
            |error: &TestError| match error {
                TestError::ImmediateRetry => RetryDisposition::Immediate,
                TestError::IntervalRetry => RetryDisposition::Interval,
                TestError::Permanent => RetryDisposition::Stop,
            },
            {
                let retry_attempts = retry_attempts.clone();
                move |attempt_kind| {
                    let retry_attempts = retry_attempts.clone();
                    async move {
                        retry_attempts.lock().unwrap().push(attempt_kind);
                        if retry_attempts.lock().unwrap().len() == 1 {
                            Err(TestError::IntervalRetry)
                        } else {
                            Ok(())
                        }
                    }
                }
            },
            {
                let sleeps = sleeps.clone();
                move |delay| {
                    let sleeps = sleeps.clone();
                    async move {
                        sleeps.lock().unwrap().push(delay);
                    }
                }
            },
        )
        .await;

        assert_eq!(result, Ok(()));
        assert_eq!(
            *retry_attempts.lock().unwrap(),
            vec![RetryAttemptKind::Initial, RetryAttemptKind::IntervalRetry]
        );
        assert_eq!(*sleeps.lock().unwrap(), vec![retry_interval]);
    }

    #[test]
    fn unauthorized_tunnel_failures_log_the_next_retry_shape() {
        assert_eq!(
            client_tunnel_unauthorized_attempt_kind(false),
            runewarp::runtime_log::ClientTunnelAttemptKind::Initial
        );
        assert_eq!(
            client_tunnel_unauthorized_attempt_kind(true),
            runewarp::runtime_log::ClientTunnelAttemptKind::IntervalRetry
        );
    }

    #[test]
    fn ensure_client_identity_fresh_renews_due_certificates_before_connecting() {
        let tempdir = tempdir().unwrap();
        write_client_identity_with_not_before(
            tempdir.path(),
            OffsetDateTime::now_utc() - TimeDuration::days(61),
        );

        let original_private_key = fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap();
        let original_certificate = fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap();
        let original_identity =
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap();

        ensure_client_identity_fresh(tempdir.path()).unwrap();

        assert_eq!(
            fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap(),
            original_private_key
        );
        assert_ne!(
            fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap(),
            original_certificate
        );
        assert_eq!(
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap(),
            original_identity
        );
    }

    #[test]
    fn ensure_client_identity_fresh_leaves_not_yet_due_certificates_untouched() {
        let tempdir = tempdir().unwrap();
        write_client_identity_with_not_before(
            tempdir.path(),
            OffsetDateTime::now_utc() - TimeDuration::days(60) + TimeDuration::minutes(1),
        );

        let original_private_key = fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap();
        let original_certificate = fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap();
        let original_identity =
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap();

        ensure_client_identity_fresh(tempdir.path()).unwrap();

        assert_eq!(
            fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap(),
            original_private_key
        );
        assert_eq!(
            fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap(),
            original_certificate
        );
        assert_eq!(
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap(),
            original_identity
        );
    }

    fn write_client_identity_with_not_before(directory: &Path, not_before: OffsetDateTime) {
        let signing_key = KeyPair::generate().unwrap();
        let mut certificate_params =
            CertificateParams::new(vec!["runewarp-client".to_owned()]).unwrap();
        certificate_params.not_before = not_before;
        certificate_params.not_after =
            not_before + TimeDuration::days(CLIENT_CERT_LIFETIME_DAYS as i64);
        let certificate = certificate_params.self_signed(&signing_key).unwrap();
        let client_identity =
            ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

        fs::write(
            directory.join(CLIENT_KEY_FILENAME),
            signing_key.serialize_pem(),
        )
        .unwrap();
        fs::write(directory.join(CLIENT_CERT_FILENAME), certificate.pem()).unwrap();
        fs::write(
            directory.join(CLIENT_IDENTITY_FILENAME),
            client_identity.to_string(),
        )
        .unwrap();
    }
}
