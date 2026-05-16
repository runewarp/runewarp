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
    CLIENT_CERT_LIFETIME_DAYS, CLIENT_CERT_RENEW_AFTER_DAYS, PreparedClient, PreparedServer,
    generate_client_identity, load_client_settings, load_server_settings,
};

const CLIENT_KEY_FILENAME: &str = "client.key";
const CLIENT_CERT_FILENAME: &str = "client.crt";
const CLIENT_FINGERPRINT_FILENAME: &str = "client-fingerprint.txt";
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
        "keygen" => {
            let out_dir = parse_keygen_out_dir(args)?;
            write_keygen_artifacts(&out_dir)
        }
        "server" => {
            let config_path = parse_config_path(args)?;
            let settings = load_server_settings(&config_path)?;
            PreparedServer::bind(&settings, wildcard(443), wildcard(443))
                .await?
                .run()
                .await?;
            Ok(())
        }
        "client" => {
            let config_path = parse_config_path(args)?;
            let settings = load_client_settings(&config_path)?;
            run_client_command(&settings, wildcard(0)).await
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
    println!("Available commands: server, client, keygen");
}

async fn run_client_command(
    settings: &runewarp::ClientSettings,
    local_bind_addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    loop {
        let client = retry_with_immediate_retry(
            settings.retry_interval,
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

fn parse_keygen_out_dir(
    mut args: impl Iterator<Item = String>,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let mut out_dir = std::path::PathBuf::from("certs");
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--out-dir" => {
                let Some(value) = args.next() else {
                    return Err("missing value for --out-dir".into());
                };
                out_dir = value.into();
            }
            _ => {
                return Err(format!("unrecognized keygen argument: {argument}").into());
            }
        }
    }

    Ok(out_dir)
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

fn write_keygen_artifacts(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(out_dir)?;
    let generated = generate_client_identity()?;
    write_new_file(
        &out_dir.join(CLIENT_KEY_FILENAME),
        generated.private_key_pem.as_bytes(),
    )?;
    write_new_file(
        &out_dir.join(CLIENT_CERT_FILENAME),
        generated.certificate_pem.as_bytes(),
    )?;
    write_new_file(
        &out_dir.join(CLIENT_FINGERPRINT_FILENAME),
        generated.client_identity.to_string().as_bytes(),
    )?;
    println!("Client identity fingerprint: {}", generated.client_identity);
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
