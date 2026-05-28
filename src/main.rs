use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{CommandFactory, Parser};
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientRuntimeArgs,
    ClientSettingsResolutionError, PreparedClient, PreparedServer, ServerSettingsResolutionError,
    SettingsError, XdgPathError, default_client_identity_material_dir,
    default_client_public_cert_material_dir, default_config_path, default_server_cert_material_dir,
    generate_client_identity, initialize_manual_client_public_cert,
    initialize_manual_server_certificate, inspect_manual_server_certificate, read_client_identity,
    renew_client_identity_certificate, renew_manual_client_public_cert,
    renew_manual_server_certificate, resolve_client_identity_material_dir_from_config,
    resolve_client_public_cert_material_dir_from_config, resolve_client_settings_from_cli,
    resolve_server_cert_material_dir_from_config, resolve_server_hostname_from_config,
    resolve_server_settings_from_cli, resolve_terminating_hostnames_from_config,
    rotate_client_identity, rotate_manual_client_public_cert_authority,
    rotate_manual_server_certificate_authority, select_client_config,
};
use rustls_pemfile::certs;
use time::OffsetDateTime;
use tokio::net::lookup_host;
use tokio::sync::Notify;
use x509_parser::parse_x509_certificate;

mod cli;

const MANUAL_CERT_RENEW_AFTER_DAYS: i64 = 60;

enum RunError {
    Cli(clap::Error),
    Other(Box<dyn Error>),
    Logged,
}

#[derive(Debug)]
struct LoggedRuntimeError;

impl std::fmt::Display for LoggedRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("runtime failure already logged")
    }
}

impl Error for LoggedRuntimeError {}

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

#[derive(Clone, Debug)]
struct GracefulShutdown {
    started: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl GracefulShutdown {
    fn new(_grace_period: Duration) -> Self {
        Self {
            started: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn begin(&self) -> bool {
        let began = self
            .started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if began {
            self.notify.notify_waiters();
        }
        began
    }

    fn is_started(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }

    async fn wait(&self) {
        if self.is_started() {
            return;
        }
        loop {
            let notified = self.notify.notified();
            if self.is_started() {
                return;
            }
            notified.await;
            if self.is_started() {
                return;
            }
        }
    }
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
        Err(RunError::Logged) => ExitCode::FAILURE,
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
        Some(cli::TopLevelCommand::Server(command)) => match run_server_command(command).await {
            Ok(()) => Ok(()),
            Err(error) if error.downcast_ref::<LoggedRuntimeError>().is_some() => {
                Err(RunError::Logged)
            }
            Err(error) => Err(RunError::Other(error)),
        },
        Some(cli::TopLevelCommand::Client(command)) => {
            match run_client_command_from_cli(command).await {
                Ok(()) => Ok(()),
                Err(error) if error.downcast_ref::<LoggedRuntimeError>().is_some() => {
                    Err(RunError::Logged)
                }
                Err(error) => Err(RunError::Other(error)),
            }
        }
        None => Ok(()),
    }
}

async fn run_client_command(
    settings: &runewarp::ClientSettings,
    local_bind_addr: SocketAddr,
    shutdown: &GracefulShutdown,
) -> Result<(), Box<dyn Error>> {
    let mut connected_once = false;
    loop {
        if shutdown.is_started() {
            return Ok(());
        }
        ensure_client_identity_fresh(&settings.identity_directory)?;
        let phase = client_tunnel_phase(connected_once);
        let Some((client, connected_dial_target)) = retry_with_immediate_retry(
            settings.reconnect_interval,
            shutdown,
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
                        if !connected_once {
                            runewarp::runtime_log::client_ready(
                                &dial_target.configured_server_addr,
                            );
                        }
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
        .map_err(|error| -> Box<dyn Error> { Box::new(error) })?
        else {
            return Ok(());
        };
        connected_once = true;

        if let Err(error) = client
            .run_until_shutdown({
                let shutdown = shutdown.clone();
                async move {
                    shutdown.wait().await;
                }
            })
            .await
        {
            if is_unauthorized_client_connection_error(&error) {
                runewarp::runtime_log::client_tunnel_unauthorized(
                    client_tunnel_unauthorized_attempt_kind(connected_once),
                    &connected_dial_target.configured_server_addr,
                    &error.to_string(),
                );
                tokio::select! {
                    _ = shutdown.wait() => return Ok(()),
                    _ = tokio::time::sleep(settings.reconnect_interval) => {}
                }
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

fn run_server_cert_command(
    config: Option<std::path::PathBuf>,
    command: cli::ServerCertArgs,
) -> Result<(), Box<dyn Error>> {
    match command.command {
        cli::ServerCertSubcommand::Init(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_dir(config, args.dir)?;
            if let Ok(existing_state) = inspect_manual_server_certificate(&directory) {
                if existing_state.hostname == hostname {
                    print_server_certificate_summary(
                        "Server certificate material already exists",
                        &directory,
                        &existing_state.hostname,
                    )?;
                    return Ok(());
                }

                return Err(format!(
                    "Server certificate material in {} already belongs to Server hostname {}. \
                     Use a different directory or rotate the existing material.",
                    directory.display(),
                    existing_state.hostname
                )
                .into());
            }
            let existing_paths = existing_server_cert_paths(&directory);
            if !existing_paths.is_empty() {
                return Err(format!(
                    "Server certificate material in {} is incomplete or inconsistent. Repair or \
                     remove the existing files and rerun `runewarp server cert init`.\nExisting \
                     files: {}",
                    directory.display(),
                    existing_paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into());
            }
            initialize_manual_server_certificate(&directory, &hostname)?;
            print_server_certificate_summary(
                "Server certificate initialized",
                &directory,
                &hostname,
            )?;
            Ok(())
        }
        cli::ServerCertSubcommand::Renew(args) => {
            let directory = resolve_server_cert_dir(config, args.dir)?;
            renew_manual_server_certificate(&directory)?;
            let hostname = inspect_manual_server_certificate(&directory)?.hostname;
            print_server_certificate_summary("Server certificate renewed", &directory, &hostname)?;
            Ok(())
        }
        cli::ServerCertSubcommand::RotateCa(args) => {
            let hostname = resolve_server_cert_hostname(config.clone(), args.hostname)?;
            let directory = resolve_server_cert_dir(config, args.dir)?;
            rotate_manual_server_certificate_authority(&directory, &hostname)?;
            print_server_certificate_summary(
                "Server certificate authority rotated",
                &directory,
                &hostname,
            )?;
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
    let shutdown = GracefulShutdown::new(Duration::from_millis(100));
    let runtime = run_client_command(&settings, wildcard(0), &shutdown);
    tokio::pin!(runtime);
    let client_result = tokio::select! {
        result = &mut runtime => result,
        signal_result = wait_for_orderly_shutdown_signal() => {
            signal_result?;
            runewarp::runtime_log::client_graceful_shutdown_started();
            shutdown.begin();
            runtime.await
        }
    };
    client_result.map_err(logged_runtime_failure)
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
            print_client_identity_summary(
                "Client identity renewed",
                &directory,
                renewed.client_identity,
            )?;
            Ok(())
        }
        cli::ClientIdentitySubcommand::Rotate(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            let rotated = rotate_client_identity(&directory)?;
            print_client_identity_summary(
                "Client identity rotated",
                &directory,
                rotated.client_identity,
            )?;
            Ok(())
        }
        cli::ClientIdentitySubcommand::Show(args) => {
            let directory = resolve_client_identity_dir(config, args.dir)?;
            println!("{}", read_client_identity(&directory)?);
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
            let directory_config = config.clone();
            let hostnames = resolve_client_public_cert_hostnames(config, args.hostname)?;
            let directory = resolve_client_public_cert_dir(directory_config, args.dir)?;
            let mut initialized_hostnames = Vec::new();
            let mut existing_hostnames = Vec::new();
            for hostname in &hostnames {
                match inspect_client_public_cert_init_state(&directory, hostname) {
                    ClientPublicCertInitState::ReadyToInitialize => {
                        initialize_manual_client_public_cert(&directory, hostname)?;
                        initialized_hostnames.push(hostname.clone());
                    }
                    ClientPublicCertInitState::AlreadyExists => {
                        existing_hostnames.push(hostname.clone());
                    }
                    ClientPublicCertInitState::Partial(existing_paths) => {
                        return Err(format!(
                            "Public hostname certificate material in {} is incomplete or \
                             inconsistent. Repair or remove the existing files and rerun \
                             `runewarp client public-cert init`.\nExisting files: {}",
                            directory.display(),
                            existing_paths
                                .iter()
                                .map(|path| path.display().to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                        .into());
                    }
                }
            }
            if !existing_hostnames.is_empty() {
                println!(
                    "Public hostname certificate material already exists for: {}",
                    existing_hostnames.join(", ")
                );
            }
            println!(
                "Public hostname CA: {}",
                directory
                    .join(runewarp::CLIENT_PUBLIC_CA_FILENAME)
                    .display()
            );
            if !initialized_hostnames.is_empty() {
                println!(
                    "Initialized leaf certificate(s) for: {}",
                    initialized_hostnames.join(", ")
                );
            }
            print_public_cert_timestamps(
                &directory,
                initialized_hostnames.first().unwrap_or(&hostnames[0]),
            )?;
            Ok(())
        }
        cli::ClientPublicCertSubcommand::Renew(args) => {
            let directory_config = config.clone();
            let hostnames = resolve_client_public_cert_hostnames(config, args.hostname)?;
            let directory = resolve_client_public_cert_dir(directory_config, args.dir)?;
            for hostname in &hostnames {
                renew_manual_client_public_cert(&directory, hostname)?;
            }
            println!("Renewed leaf certificate(s) for: {}", hostnames.join(", "));
            print_public_cert_timestamps(&directory, &hostnames[0])?;
            Ok(())
        }
        cli::ClientPublicCertSubcommand::RotateCa(args) => {
            let directory_config = config.clone();
            let hostnames = resolve_client_public_cert_hostnames_from_config_required(config)?;
            let directory = resolve_client_public_cert_dir(directory_config, args.dir)?;
            rotate_manual_client_public_cert_authority(&directory, &hostnames)?;
            println!(
                "Public hostname CA rotated: {}",
                directory
                    .join(runewarp::CLIENT_PUBLIC_CA_FILENAME)
                    .display()
            );
            println!("Reissued leaf certificate(s) for: {}", hostnames.join(", "));
            print_public_cert_timestamps(&directory, &hostnames[0])?;
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
    let Some(config_path) = resolve_selected_client_config_path(config)? else {
        return Err(
            "--hostname is required, or supply --config or a default client config to derive \
             targets from client.services[].public-hostnames (tls-mode = \"terminate\")"
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
    let config_path = match resolve_selected_client_config_path(config.clone())? {
        Some(config_path) => config_path,
        None => {
            let default_path = default_config_path()?;
            return Err(format!(
                "no selected config file for `client public-cert rotate-ca`; use -c, --config \
                 or create the default config at {}",
                default_path.display()
            )
            .into());
        }
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

fn resolve_selected_client_config_path(
    config: Option<std::path::PathBuf>,
) -> Result<Option<std::path::PathBuf>, Box<dyn Error>> {
    match select_client_config(config)? {
        runewarp::SelectedClientConfig::Explicit(path)
        | runewarp::SelectedClientConfig::Discovered(path) => Ok(Some(path)),
        runewarp::SelectedClientConfig::None => Ok(None),
    }
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

async fn retry_with_immediate_retry<T, E, Attempt, AttemptFuture, Sleep, SleepFuture>(
    retry_interval: Duration,
    shutdown: &GracefulShutdown,
    retry_disposition: impl Fn(&E) -> RetryDisposition,
    mut attempt: Attempt,
    mut sleep: Sleep,
) -> Result<Option<T>, E>
where
    Attempt: FnMut(RetryAttemptKind) -> AttemptFuture,
    AttemptFuture: Future<Output = Result<T, E>>,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    let mut used_immediate_retry = false;
    let mut attempt_kind = RetryAttemptKind::Initial;
    loop {
        if shutdown.is_started() {
            return Ok(None);
        }
        let attempt_result = tokio::select! {
            _ = shutdown.wait() => return Ok(None),
            result = attempt(attempt_kind) => result,
        };
        match attempt_result {
            Ok(result) => return Ok(Some(result)),
            Err(error) => match retry_disposition(&error) {
                RetryDisposition::Immediate if used_immediate_retry => {
                    tokio::select! {
                        _ = shutdown.wait() => return Ok(None),
                        _ = sleep(retry_interval) => {}
                    }
                    attempt_kind = RetryAttemptKind::IntervalRetry;
                }
                RetryDisposition::Immediate => {
                    used_immediate_retry = true;
                    attempt_kind = RetryAttemptKind::ImmediateRetry;
                }
                RetryDisposition::Interval => {
                    used_immediate_retry = true;
                    tokio::select! {
                        _ = shutdown.wait() => return Ok(None),
                        _ = sleep(retry_interval) => {}
                    }
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
    if let Ok(existing_identity) = read_client_identity(directory) {
        print_client_identity_summary(
            "Client identity already exists",
            directory,
            existing_identity,
        )?;
        return Ok(());
    }

    let existing_paths = existing_client_identity_paths(directory);
    if !existing_paths.is_empty() {
        return Err(format!(
            "Client identity material in {} is incomplete or inconsistent. Repair or remove the \
             existing files and rerun `runewarp client identity init`.\nExisting files: {}",
            directory.display(),
            existing_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into());
    }

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
    print_client_identity_summary(
        "Client identity initialized",
        directory,
        generated.client_identity,
    )?;
    Ok(())
}

fn print_client_identity_summary(
    headline: &str,
    directory: &Path,
    client_identity: runewarp::ClientIdentity,
) -> Result<(), Box<dyn Error>> {
    let certificate_window = read_certificate_window(&directory.join(CLIENT_CERT_FILENAME))?;

    println!("{headline}: {client_identity}");
    println!("Identity directory: {}", directory.display());
    println!("Certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
    println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
    println!(
        "Issued at (UTC): {}",
        format_utc(certificate_window.issued_at)
    );
    println!(
        "Renew after (UTC): {}",
        format_utc(
            certificate_window.issued_at
                + time::Duration::days(CLIENT_CERT_RENEW_AFTER_DAYS as i64),
        )
    );
    println!(
        "Expires at (UTC): {}",
        format_utc(certificate_window.expires_at)
    );
    Ok(())
}

fn print_server_certificate_summary(
    headline: &str,
    directory: &Path,
    hostname: &str,
) -> Result<(), Box<dyn Error>> {
    let certificate_window = read_certificate_window(&directory.join("server.crt"))?;

    println!("{headline}");
    println!("Server hostname: {hostname}");
    println!("Certificate directory: {}", directory.display());
    println!(
        "Server certificate: {}",
        directory.join("server.crt").display()
    );
    println!(
        "Server certificate authority: {}",
        directory.join(runewarp::SERVER_CA_FILENAME).display()
    );
    println!("Certificate lifetime: 90 days");
    println!(
        "Renew after (UTC): {}",
        format_utc(
            certificate_window.issued_at + time::Duration::days(MANUAL_CERT_RENEW_AFTER_DAYS)
        )
    );
    println!(
        "Issued at (UTC): {}",
        format_utc(certificate_window.issued_at)
    );
    println!(
        "Expires at (UTC): {}",
        format_utc(certificate_window.expires_at)
    );
    Ok(())
}

fn print_public_cert_timestamps(directory: &Path, hostname: &str) -> Result<(), Box<dyn Error>> {
    let certificate_path = runewarp::client_public_cert_leaf_dir(directory, hostname)
        .join(runewarp::CLIENT_PUBLIC_CERT_FILENAME);
    let certificate_window = read_certificate_window(&certificate_path)?;

    println!(
        "Leaf certificate lifetime: {} days",
        runewarp::CLIENT_PUBLIC_CERT_LIFETIME_DAYS
    );
    println!(
        "Issued at (UTC): {}",
        format_utc(certificate_window.issued_at)
    );
    println!(
        "Renew after (UTC): {}",
        format_utc(
            certificate_window.issued_at + time::Duration::days(MANUAL_CERT_RENEW_AFTER_DAYS)
        )
    );
    println!(
        "Expires at (UTC): {}",
        format_utc(certificate_window.expires_at)
    );
    Ok(())
}

struct CertificateWindow {
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

fn read_certificate_window(path: &Path) -> Result<CertificateWindow, Box<dyn Error>> {
    let certificate_pem = fs::read(path)?;
    let certificate_der = certs(&mut std::io::Cursor::new(certificate_pem))
        .next()
        .transpose()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing certificate"))?;
    let (_, certificate) = parse_x509_certificate(certificate_der.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid X.509 certificate"))?;

    Ok(CertificateWindow {
        issued_at: certificate.validity().not_before.to_datetime(),
        expires_at: certificate.validity().not_after.to_datetime(),
    })
}

fn format_utc(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting should succeed")
}

fn logged_runtime_failure(error: Box<dyn Error>) -> Box<dyn Error> {
    runewarp::runtime_log::emit(runewarp::runtime_log::EventLevel::Error, &error.to_string());
    Box::new(LoggedRuntimeError)
}

fn existing_client_identity_paths(directory: &Path) -> Vec<std::path::PathBuf> {
    [
        directory.join(CLIENT_KEY_FILENAME),
        directory.join(CLIENT_CERT_FILENAME),
        directory.join(CLIENT_IDENTITY_FILENAME),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect()
}

fn existing_server_cert_paths(directory: &Path) -> Vec<std::path::PathBuf> {
    [
        directory.join("server.crt"),
        directory.join("server.key"),
        directory.join(runewarp::SERVER_CA_FILENAME),
        directory.join("state/server-ca.key"),
        directory.join("state/server-hostname.txt"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect()
}

enum ClientPublicCertInitState {
    ReadyToInitialize,
    AlreadyExists,
    Partial(Vec<std::path::PathBuf>),
}

fn inspect_client_public_cert_init_state(
    directory: &Path,
    hostname: &str,
) -> ClientPublicCertInitState {
    let ca_cert = directory.join(runewarp::CLIENT_PUBLIC_CA_FILENAME);
    let ca_key = directory.join("state/public-ca.key");
    let leaf_dir = runewarp::client_public_cert_leaf_dir(directory, hostname);
    let leaf_cert = leaf_dir.join(runewarp::CLIENT_PUBLIC_CERT_FILENAME);
    let leaf_key = leaf_dir.join(runewarp::CLIENT_PUBLIC_KEY_FILENAME);

    let ca_complete = ca_cert.exists() && ca_key.exists();
    let ca_partial = ca_cert.exists() ^ ca_key.exists();
    let leaf_complete = leaf_cert.exists() && leaf_key.exists();
    let leaf_partial = leaf_cert.exists() ^ leaf_key.exists();

    if !ca_complete && !leaf_complete && !ca_partial && !leaf_partial {
        return ClientPublicCertInitState::ReadyToInitialize;
    }
    if ca_complete && !leaf_complete && !leaf_partial {
        return ClientPublicCertInitState::ReadyToInitialize;
    }
    if ca_complete && leaf_complete {
        return ClientPublicCertInitState::AlreadyExists;
    }

    ClientPublicCertInitState::Partial(
        [ca_cert, ca_key, leaf_cert, leaf_key]
            .into_iter()
            .filter(|path| path.exists())
            .collect(),
    )
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
        GracefulShutdown, RetryAttemptKind, RetryDisposition,
        client_tunnel_unauthorized_attempt_kind, ensure_client_identity_fresh,
        retry_with_immediate_retry,
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
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));

        let result: Result<Option<()>, TestError> = retry_with_immediate_retry(
            retry_interval,
            &shutdown,
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

        assert_eq!(result, Ok(Some(())));
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
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));

        let result: Result<Option<()>, TestError> = retry_with_immediate_retry(
            Duration::from_secs(5),
            &shutdown,
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
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));

        let result: Result<Option<()>, TestError> = retry_with_immediate_retry(
            retry_interval,
            &shutdown,
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

        assert_eq!(result, Ok(Some(())));
        assert_eq!(
            *retry_attempts.lock().unwrap(),
            vec![RetryAttemptKind::Initial, RetryAttemptKind::IntervalRetry]
        );
        assert_eq!(*sleeps.lock().unwrap(), vec![retry_interval]);
    }

    #[tokio::test]
    async fn shutdown_stops_before_an_immediate_retry_attempt() {
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));
        let retry_attempts = Arc::new(Mutex::new(Vec::new()));

        let result: Result<Option<()>, TestError> = retry_with_immediate_retry(
            Duration::from_secs(5),
            &shutdown,
            |_: &TestError| RetryDisposition::Immediate,
            {
                let retry_attempts = retry_attempts.clone();
                let shutdown = shutdown.clone();
                move |attempt_kind| {
                    let retry_attempts = retry_attempts.clone();
                    let shutdown = shutdown.clone();
                    async move {
                        retry_attempts.lock().unwrap().push(attempt_kind);
                        shutdown.begin();
                        Err(TestError::ImmediateRetry)
                    }
                }
            },
            |_delay| async {},
        )
        .await;

        assert_eq!(result, Ok(None));
        assert_eq!(
            *retry_attempts.lock().unwrap(),
            vec![RetryAttemptKind::Initial]
        );
    }

    #[tokio::test]
    async fn shutdown_stops_while_waiting_for_an_interval_retry() {
        let shutdown = GracefulShutdown::new(Duration::from_millis(25));
        let retry_attempts = Arc::new(Mutex::new(Vec::new()));
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let result: Result<Option<()>, TestError> = retry_with_immediate_retry(
            Duration::from_secs(5),
            &shutdown,
            |_: &TestError| RetryDisposition::Interval,
            {
                let retry_attempts = retry_attempts.clone();
                move |attempt_kind| {
                    let retry_attempts = retry_attempts.clone();
                    async move {
                        retry_attempts.lock().unwrap().push(attempt_kind);
                        Err(TestError::IntervalRetry)
                    }
                }
            },
            {
                let sleeps = sleeps.clone();
                let shutdown = shutdown.clone();
                move |delay| {
                    let sleeps = sleeps.clone();
                    let shutdown = shutdown.clone();
                    async move {
                        sleeps.lock().unwrap().push(delay);
                        shutdown.begin();
                        tokio::task::yield_now().await;
                    }
                }
            },
        )
        .await;

        assert_eq!(result, Ok(None));
        assert_eq!(
            *retry_attempts.lock().unwrap(),
            vec![RetryAttemptKind::Initial]
        );
        assert_eq!(*sleeps.lock().unwrap(), vec![Duration::from_secs(5)]);
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
