mod client_runtime;
mod reconnect_policy;

use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientRuntimeArgs,
    ClientSettingsResolutionError, PreparedServer, ServerSettingsResolutionError, SettingsError,
    XdgPathError, default_client_identity_material_dir, default_client_public_cert_material_dir,
    default_config_path, default_server_cert_material_dir, generate_client_identity,
    initialize_manual_client_public_cert, initialize_manual_server_certificate,
    inspect_manual_server_certificate, read_client_identity, renew_client_identity_certificate,
    renew_manual_client_public_cert, renew_manual_server_certificate,
    resolve_client_identity_material_dir_from_config,
    resolve_client_public_cert_material_dir_from_config, resolve_client_settings_from_cli,
    resolve_server_cert_material_dir_from_config, resolve_server_hostname_from_config,
    resolve_server_settings_from_cli, resolve_terminating_hostnames_from_config,
    rotate_client_identity, rotate_manual_client_public_cert_authority,
    rotate_manual_server_certificate_authority, select_client_config,
};
use rustls_pemfile::certs;
use time::OffsetDateTime;
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
