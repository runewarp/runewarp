use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use runewarp::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS,
    CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, PreparedClient, PreparedServer,
    generate_client_identity, initialize_manual_server_certificate, load_client_settings,
    load_server_settings, renew_manual_server_certificate,
    renew_client_identity_certificate, rotate_client_identity,
    rotate_manual_server_certificate_authority,
};
use time::OffsetDateTime;

const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        print_available_commands(None);
        return Ok(());
    };

    match command.as_str() {
        "server" => {
            run_server_command_from_args(args).await
        }
        "client" => {
            run_client_command_from_args(args).await
        }
        _ => {
            print_available_commands(Some(&command));
            Ok(())
        }
    }
}

fn print_available_commands(unrecognized: Option<&str>) {
    if let Some(unrecognized) = unrecognized {
        println!("unrecognized command: {unrecognized}");
    }
    println!("Available commands: server, client");
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
                    eprintln!(
                        "warning: {} system trust-store certificate(s) could not be loaded; continuing with the successfully loaded trust anchors",
                        client.native_root_error_count()
                    );
                }
                Ok(client)
            },
            |delay| tokio::time::sleep(delay),
        )
        .await
        .map_err(|error| -> Box<dyn Error> { Box::new(error) })?;

        tokio::select! {
            run_result = client.run() => {
                if let Err(error) = run_result {
                    eprintln!("warning: tunnel connection lost: {error}; reconnecting");
                    continue;
                }
            }
            renewal_result = maintain_client_identity_certificate(settings.identity_directory.clone()) => {
                renewal_result?;
            }
        }

        return Ok(());
    }
}

fn ensure_client_identity_fresh(directory: &Path) -> Result<(), runewarp::ClientIdentityMaterialError> {
    match runewarp::inspect_client_certificate_renewal(directory, OffsetDateTime::now_utc())? {
        runewarp::ClientCertificateRenewalDecision::NotDue { .. } => Ok(()),
        runewarp::ClientCertificateRenewalDecision::Due { .. }
        | runewarp::ClientCertificateRenewalDecision::Expired { .. } => {
            runewarp::renew_client_identity_certificate(directory)?;
            Ok(())
        }
    }
}

async fn maintain_client_identity_certificate(
    directory: std::path::PathBuf,
) -> Result<(), runewarp::ClientIdentityMaterialError> {
    let mut retry_delay = Duration::from_secs(1);

    loop {
        match runewarp::inspect_client_certificate_renewal(&directory, OffsetDateTime::now_utc())? {
            runewarp::ClientCertificateRenewalDecision::NotDue { renew_at, .. } => {
                retry_delay = Duration::from_secs(1);
                tokio::time::sleep(next_client_identity_check_delay(
                    renew_at,
                    OffsetDateTime::now_utc(),
                ))
                .await;
            }
            runewarp::ClientCertificateRenewalDecision::Due { .. } => {
                if let Err(error) = runewarp::renew_client_identity_certificate(&directory) {
                    eprintln!("warning: failed to renew client certificate: {error}; retrying");
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(60));
                    continue;
                }
                retry_delay = Duration::from_secs(1);
            }
            runewarp::ClientCertificateRenewalDecision::Expired { .. } => {
                runewarp::renew_client_identity_certificate(&directory)?;
                retry_delay = Duration::from_secs(1);
            }
        }
    }
}

fn next_client_identity_check_delay(renew_at: OffsetDateTime, now: OffsetDateTime) -> Duration {
    const MAX_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

    let until_renewal = renew_at - now;
    if until_renewal.is_negative() {
        Duration::from_secs(0)
    } else {
        until_renewal.try_into().unwrap_or(MAX_DELAY).min(MAX_DELAY)
    }
}

async fn run_server_command_from_args(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let Some(argument) = args.next() else {
        let settings = load_server_settings(Path::new(DEFAULT_CONFIG_PATH))?;
        PreparedServer::bind(&settings, wildcard(443), wildcard(443))
            .await?
            .run()
            .await?;
        return Ok(());
    };

    if argument == "cert" {
        return run_server_cert_command(args);
    }

    let config_path = parse_config_path(std::iter::once(argument).chain(args))?;
    let settings = load_server_settings(&config_path)?;
    PreparedServer::bind(&settings, wildcard(443), wildcard(443))
        .await?
        .run()
        .await?;
    Ok(())
}

fn run_server_cert_command(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let Some(command) = args.next() else {
        return Err("missing server cert command".into());
    };

    match command.as_str() {
        "init" => {
            let (directory, hostname) = parse_directory_and_hostname_args(args)?;
            initialize_manual_server_certificate(&directory, &hostname)?;
            Ok(())
        }
        "renew" => {
            let directory = parse_directory_arg(args)?;
            renew_manual_server_certificate(&directory)?;
            Ok(())
        }
        "rotate-ca" => {
            let (directory, hostname) = parse_directory_and_hostname_args(args)?;
            rotate_manual_server_certificate_authority(&directory, &hostname)?;
            Ok(())
        }
        _ => Err(format!("unrecognized server cert command: {command}").into()),
    }
}

async fn run_client_command_from_args(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let Some(argument) = args.next() else {
        let settings = load_client_settings(Path::new(DEFAULT_CONFIG_PATH))?;
        return run_client_command(&settings, wildcard(0)).await;
    };

    if argument == "identity" {
        return run_client_identity_command(args);
    }

    let config_path = parse_config_path(std::iter::once(argument).chain(args))?;
    let settings = load_client_settings(&config_path)?;
    run_client_command(&settings, wildcard(0)).await
}

fn run_client_identity_command(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let Some(command) = args.next() else {
        return Err("missing client identity command".into());
    };

    match command.as_str() {
        "init" => {
            let directory = parse_directory_arg(args)?;
            write_client_identity_artifacts(&directory)
        }
        "renew" => {
            let directory = parse_directory_arg(args)?;
            let renewed = renew_client_identity_certificate(&directory)?;
            println!("Client identity: {}", renewed.client_identity);
            println!("Renewed certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
            println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
            Ok(())
        }
        "rotate" => {
            let directory = parse_directory_arg(args)?;
            let rotated = rotate_client_identity(&directory)?;
            println!("Client identity: {}", rotated.client_identity);
            println!("Rotated certificate lifetime: {CLIENT_CERT_LIFETIME_DAYS} days");
            println!("Renewal target: {CLIENT_CERT_RENEW_AFTER_DAYS} days");
            Ok(())
        }
        _ => Err(format!("unrecognized client identity command: {command}").into()),
    }
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

fn parse_directory_arg(
    mut args: impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let Some(argument) = args.next() else {
        return Err("missing --directory".into());
    };
    if argument != "--directory" {
        return Err(format!("unrecognized command argument: {argument}").into());
    }

    let Some(value) = args.next() else {
        return Err("missing value for --directory".into());
    };

    if let Some(argument) = args.next() {
        return Err(format!("unrecognized command argument: {argument}").into());
    }

    Ok(value.into())
}

fn parse_directory_and_hostname_args(
    mut args: impl Iterator<Item = String>,
) -> Result<(std::path::PathBuf, String), Box<dyn Error>> {
    let mut directory = None;
    let mut hostname = None;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--directory" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --directory".into());
                };
                directory = Some(value.into());
            }
            "--hostname" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --hostname".into());
                };
                hostname = Some(value);
            }
            _ => return Err(format!("unrecognized command argument: {argument}").into()),
        }
    }

    let Some(directory) = directory else {
        return Err("missing --directory".into());
    };
    let Some(hostname) = hostname else {
        return Err("missing --hostname".into());
    };

    Ok((directory, hostname))
}

fn parse_config_path(
    mut args: impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let mut config_path = std::path::PathBuf::from(DEFAULT_CONFIG_PATH);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --config".into());
                };
                config_path = value.into();
            }
            _ => {
                return Err(format!("unrecognized command argument: {argument}").into());
            }
        }
    }

    Ok(config_path)
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
        ensure_client_identity_fresh, maintain_client_identity_certificate,
        retry_with_immediate_retry,
    };

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

        assert_eq!(fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap(), original_private_key);
        assert_ne!(fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap(), original_certificate);
        assert_eq!(
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap(),
            original_identity
        );
    }

    #[tokio::test]
    async fn maintain_client_identity_certificate_renews_due_certificates_while_running() {
        let tempdir = tempdir().unwrap();
        write_client_identity_with_not_before(
            tempdir.path(),
            OffsetDateTime::now_utc() - TimeDuration::days(60) + TimeDuration::seconds(1),
        );

        let original_private_key = fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap();
        let original_certificate = fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap();
        let original_identity =
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap();

        let task = tokio::spawn(maintain_client_identity_certificate(
            tempdir.path().to_path_buf(),
        ));
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(fs::read(tempdir.path().join(CLIENT_KEY_FILENAME)).unwrap(), original_private_key);
        assert_ne!(fs::read(tempdir.path().join(CLIENT_CERT_FILENAME)).unwrap(), original_certificate);
        assert_eq!(
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME)).unwrap(),
            original_identity
        );
        assert!(!task.is_finished());

        task.abort();
        let _ = task.await;
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

        fs::write(directory.join(CLIENT_KEY_FILENAME), signing_key.serialize_pem()).unwrap();
        fs::write(directory.join(CLIENT_CERT_FILENAME), certificate.pem()).unwrap();
        fs::write(directory.join(CLIENT_IDENTITY_FILENAME), client_identity.to_string()).unwrap();
    }
}
