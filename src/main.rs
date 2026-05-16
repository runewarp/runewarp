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
    load_server_settings,
};

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

        if let Err(error) = client.run().await {
            eprintln!("warning: tunnel connection lost: {error}; reconnecting");
            continue;
        }

        return Ok(());
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
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::retry_with_immediate_retry;

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
}
