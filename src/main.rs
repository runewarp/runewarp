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
use runewarp::runtime_log::{emit_stderr, warning_line};
use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientRuntimeArgs,
    ClientSettingsResolutionError, PreparedClient, PreparedServer, SettingsError, XdgPathError,
    default_client_identity_material_dir, default_client_public_cert_material_dir,
    default_config_path, default_server_cert_material_dir, generate_client_identity,
    initialize_manual_client_public_cert, initialize_manual_server_certificate,
    load_server_settings, renew_client_identity_certificate, renew_manual_server_certificate,
    resolve_client_identity_material_dir_from_config,
    resolve_client_public_cert_material_dir_from_config, resolve_client_settings_from_cli,
    resolve_server_cert_material_dir_from_config, resolve_server_hostname_from_config,
    rotate_client_identity, rotate_manual_server_certificate_authority,
};
use time::OffsetDateTime;

mod cli;

enum RunError {
    Cli(clap::Error),
    Other(Box<dyn Error>),
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
    loop {
        ensure_client_identity_fresh(&settings.identity_directory)?;
        let client = retry_with_immediate_retry(
            settings.reconnect_interval,
            should_retry_client_connect_error,
            || async {
                let client = PreparedClient::connect(settings, local_bind_addr).await?;
                if client.native_root_error_count() > 0 {
                    emit_stderr(
                        settings.logs,
                        &warning_line(
                            "client",
                            &format!(
                                "{} system trust-store certificate(s) could not be loaded; continuing with the successfully loaded trust anchors",
                                client.native_root_error_count()
                            ),
                        ),
                    );
                }
                Ok(client)
            },
            |delay| tokio::time::sleep(delay),
        )
        .await
        .map_err(|error| -> Box<dyn Error> { Box::new(error) })?;

        if let Err(error) = client.run().await {
            emit_stderr(
                settings.logs,
                &warning_line(
                    "client",
                    &format!("tunnel connection lost: {error}; reconnecting"),
                ),
            );
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

    let config_path = config_path_or_default(config)?;
    let settings = load_server_settings(&config_path)
        .map_err(|error| wrap_server_settings_error(error, &config_path))?;
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

    let settings = resolve_client_settings_from_cli(
        config,
        ClientRuntimeArgs {
            server_address,
            backend_address,
        },
    )
    .map_err(wrap_client_settings_resolution_error)?;
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
            let hostname = args
                .hostname
                .ok_or("--hostname is required for `client public-cert init`")?;
            let directory = resolve_client_public_cert_dir(config, args.dir)?;
            initialize_manual_client_public_cert(&directory, &hostname)?;
            println!("Client public CA: {}", directory.join(runewarp::CLIENT_PUBLIC_CA_FILENAME).display());
            println!(
                "Leaf certificate lifetime: {} days",
                runewarp::CLIENT_PUBLIC_CERT_LIFETIME_DAYS
            );
            Ok(())
        }
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

fn should_retry_client_connect_error(error: &runewarp::ClientStartupError) -> bool {
    matches!(
        error,
        runewarp::ClientStartupError::Resolve(_)
            | runewarp::ClientStartupError::MissingServerAddress { .. }
            | runewarp::ClientStartupError::Connect(_)
    )
}

async fn retry_with_immediate_retry<T, E, Attempt, AttemptFuture, Sleep, SleepFuture>(
    retry_interval: Duration,
    should_retry: impl Fn(&E) -> bool,
    mut attempt: Attempt,
    mut sleep: Sleep,
) -> Result<T, E>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<T, E>>,
    Sleep: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    let mut used_immediate_retry = false;
    loop {
        match attempt().await {
            Ok(result) => return Ok(result),
            Err(error) if should_retry(&error) => {
                if used_immediate_retry {
                    sleep(retry_interval).await;
                } else {
                    used_immediate_retry = true;
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn config_path_or_default(
    config: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    match config {
        Some(config) => Ok(config),
        None => default_config_path().map_err(|error| -> Box<dyn Error> { Box::new(error) }),
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

fn wrap_server_settings_error(error: SettingsError, config_path: &Path) -> Box<dyn Error> {
    if server_material_missing(&error) {
        return Box::new(io::Error::other(format!(
            "{error}\nHint: {}",
            server_cert_init_hint(config_path)
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

    use super::{ensure_client_identity_fresh, retry_with_immediate_retry};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Retryable,
        Permanent,
    }

    #[tokio::test]
    async fn retries_immediately_once_then_waits_for_the_retry_interval() {
        let attempts = Arc::new(Mutex::new(0));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let retry_interval = Duration::from_secs(5);

        let result = retry_with_immediate_retry(
            retry_interval,
            |error: &TestError| matches!(error, TestError::Retryable),
            {
                let attempts = attempts.clone();
                move || {
                    let attempts = attempts.clone();
                    async move {
                        let mut attempts = attempts.lock().unwrap();
                        *attempts += 1;
                        match *attempts {
                            1 | 2 => Err(TestError::Retryable),
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
        assert_eq!(*sleeps.lock().unwrap(), vec![retry_interval]);
    }

    #[tokio::test]
    async fn permanent_errors_do_not_retry() {
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let result = retry_with_immediate_retry(
            Duration::from_secs(5),
            |error: &TestError| matches!(error, TestError::Retryable),
            || async { Result::<(), TestError>::Err(TestError::Permanent) },
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
