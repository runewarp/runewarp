use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use runewarp::PreparedClient;
use time::OffsetDateTime;
use tokio::net::lookup_host;
use tokio::sync::watch;

use crate::reconnect_policy::ReconnectPolicy;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryDisposition {
    Retry,
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientTunnelDialTarget {
    configured_server_addr: String,
    resolved_server_addr: SocketAddr,
}

pub(crate) async fn run_until_orderly_shutdown<F>(
    settings: &runewarp::ClientConfig,
    local_bind_addr: SocketAddr,
    shutdown_signal: F,
) -> Result<(), Box<dyn Error>>
where
    F: Future<Output = io::Result<()>>,
{
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = run_until_shutdown(settings, local_bind_addr, &shutdown_rx);
    tokio::pin!(runtime);
    tokio::pin!(shutdown_signal);
    let client_result = tokio::select! {
        result = &mut runtime => result,
        signal_result = &mut shutdown_signal => {
            signal_result?;
            runewarp::runtime_log::client_graceful_shutdown_started();
            let _ = shutdown_tx.send(true);
            runtime.await
        }
    };
    client_result
}

async fn run_until_shutdown(
    settings: &runewarp::ClientConfig,
    local_bind_addr: SocketAddr,
    shutdown: &watch::Receiver<bool>,
) -> Result<(), Box<dyn Error>> {
    let mut connected_once = false;
    let mut reconnect_policy = ReconnectPolicy::new();
    loop {
        if shutdown_requested(shutdown) {
            return Ok(());
        }
        ensure_client_identity_fresh(&settings.identity_directory)?;
        let phase = client_tunnel_phase(connected_once);
        let attempt_kind = client_tunnel_attempt_kind(reconnect_policy.is_fresh());
        let dial_target = match tokio::select! {
            _ = wait_for_shutdown(shutdown.clone()) => return Ok(()),
            result = resolve_client_tunnel_dial_target(settings) => result,
        } {
            Ok(dial_target) => dial_target,
            Err(error) => {
                if matches!(
                    retry_disposition_for_client_connect_error(&error),
                    RetryDisposition::Retry
                ) {
                    let retry = reconnect_policy.next_retry();
                    runewarp::runtime_log::client_tunnel_resolution_failed(
                        phase,
                        attempt_kind,
                        &configured_server_addr(
                            settings.server_hostname.as_str(),
                            settings.server_port,
                        ),
                        retry.display_delay_secs,
                        &error.to_string(),
                    );
                    if wait_for_retry_delay(retry.delay, shutdown).await {
                        continue;
                    }
                    return Ok(());
                }
                return Err(Box::new(error));
            }
        };

        runewarp::runtime_log::client_tunnel_connecting(
            phase,
            attempt_kind,
            &dial_target.configured_server_addr,
            dial_target.resolved_server_addr,
        );

        let client = match tokio::select! {
            _ = wait_for_shutdown(shutdown.clone()) => return Ok(()),
            result = PreparedClient::connect_to(settings, local_bind_addr, dial_target.resolved_server_addr) => result,
        } {
            Ok(client) => client,
            Err(error) => {
                if matches!(
                    retry_disposition_for_client_connect_error(&error),
                    RetryDisposition::Retry
                ) {
                    let retry = reconnect_policy.next_retry();
                    if error
                        .source()
                        .and_then(|source| source.downcast_ref::<runewarp::ClientConnectError>())
                        .is_some_and(runewarp::ClientConnectError::is_unauthorized_client_identity)
                    {
                        runewarp::runtime_log::client_tunnel_unauthorized(
                            attempt_kind,
                            &dial_target.configured_server_addr,
                            retry.display_delay_secs,
                            &error.to_string(),
                        );
                    } else {
                        runewarp::runtime_log::client_tunnel_connect_failed(
                            phase,
                            attempt_kind,
                            &dial_target.configured_server_addr,
                            dial_target.resolved_server_addr,
                            retry.display_delay_secs,
                            &error.to_string(),
                        );
                    }
                    if wait_for_retry_delay(retry.delay, shutdown).await {
                        continue;
                    }
                    return Ok(());
                }
                return Err(Box::new(error));
            }
        };

        let first_connection = !connected_once;
        reconnect_policy.reset();
        connected_once = true;
        runewarp::runtime_log::client_tunnel_connected(
            phase,
            &dial_target.configured_server_addr,
            dial_target.resolved_server_addr,
        );
        if first_connection {
            runewarp::runtime_log::client_ready(&dial_target.configured_server_addr);
        }

        if let Err(error) = client
            .run_until_shutdown({
                let shutdown = shutdown.clone();
                async move {
                    wait_for_shutdown(shutdown).await;
                }
            })
            .await
        {
            let next_attempt_kind = client_tunnel_attempt_kind(reconnect_policy.is_fresh());
            let retry = reconnect_policy.next_retry();
            if is_unauthorized_client_connection_error(&error) {
                runewarp::runtime_log::client_tunnel_unauthorized(
                    next_attempt_kind,
                    &dial_target.configured_server_addr,
                    retry.display_delay_secs,
                    &error.to_string(),
                );
            } else if is_clean_client_tunnel_close(&error) {
                runewarp::runtime_log::client_tunnel_closed(
                    &dial_target.configured_server_addr,
                    dial_target.resolved_server_addr,
                    retry.display_delay_secs,
                );
            } else {
                runewarp::runtime_log::client_tunnel_disconnected(
                    &dial_target.configured_server_addr,
                    dial_target.resolved_server_addr,
                    retry.display_delay_secs,
                    &error.to_string(),
                );
            }
            if wait_for_retry_delay(retry.delay, shutdown).await {
                continue;
            }
            return Ok(());
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

fn retry_disposition_for_client_connect_error(
    error: &runewarp::ClientStartupError,
) -> RetryDisposition {
    match error {
        runewarp::ClientStartupError::Resolve(_)
        | runewarp::ClientStartupError::MissingServerAddress { .. }
        | runewarp::ClientStartupError::Connect(_) => RetryDisposition::Retry,
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
    is_fresh_attempt: bool,
) -> runewarp::runtime_log::ClientTunnelAttemptKind {
    if is_fresh_attempt {
        runewarp::runtime_log::ClientTunnelAttemptKind::Initial
    } else {
        runewarp::runtime_log::ClientTunnelAttemptKind::Retry
    }
}

async fn resolve_client_tunnel_dial_target(
    settings: &runewarp::ClientConfig,
) -> Result<ClientTunnelDialTarget, runewarp::ClientStartupError> {
    let mut server_addrs = lookup_host((settings.server_hostname.as_str(), settings.server_port))
        .await
        .map_err(runewarp::ClientStartupError::Resolve)?;
    let Some(resolved_server_addr) = server_addrs.next() else {
        return Err(runewarp::ClientStartupError::MissingServerAddress {
            server_hostname: settings.server_hostname.to_string(),
        });
    };
    Ok(ClientTunnelDialTarget {
        configured_server_addr: configured_server_addr(
            settings.server_hostname.as_str(),
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

fn is_clean_client_tunnel_close(error: &quinn::ConnectionError) -> bool {
    matches!(
        error,
        quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::ConnectionClosed(_)
    )
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

async fn wait_for_retry_delay(delay: Duration, shutdown: &watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = wait_for_shutdown(shutdown.clone()) => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use quinn::{ApplicationClose, ConnectionClose, TransportErrorCode, VarInt};
    use rcgen::{CertificateParams, KeyPair, PublicKeyData};
    use tempfile::tempdir;
    use time::{Duration as TimeDuration, OffsetDateTime};
    use tokio::sync::watch;

    use runewarp::{
        CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_IDENTITY_FILENAME,
        CLIENT_KEY_FILENAME, ClientIdentity,
    };

    use super::{
        RetryDisposition, client_tunnel_attempt_kind, ensure_client_identity_fresh,
        wait_for_retry_delay,
    };

    #[test]
    fn retry_attempt_kind_matches_fresh_policy_state() {
        assert_eq!(
            client_tunnel_attempt_kind(true),
            runewarp::runtime_log::ClientTunnelAttemptKind::Initial
        );
        assert_eq!(
            client_tunnel_attempt_kind(false),
            runewarp::runtime_log::ClientTunnelAttemptKind::Retry
        );
    }

    #[tokio::test]
    async fn wait_for_retry_delay_completes_when_the_delay_elapses() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        assert!(wait_for_retry_delay(Duration::ZERO, &shutdown_rx).await);
    }

    #[tokio::test]
    async fn wait_for_retry_delay_stops_when_shutdown_arrives_first() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = shutdown_tx.send(true);
        });

        assert!(!wait_for_retry_delay(Duration::from_secs(60), &shutdown_rx).await);
    }

    #[test]
    fn client_connect_failures_share_one_retry_disposition() {
        let resolve = runewarp::ClientStartupError::Resolve(std::io::Error::other("lookup failed"));
        let missing = runewarp::ClientStartupError::MissingServerAddress {
            server_hostname: "tunnel.example.test".to_owned(),
        };
        let connect = runewarp::ClientStartupError::Connect(runewarp::ClientConnectError::Bind(
            std::io::Error::other("dial failed"),
        ));

        assert_eq!(
            super::retry_disposition_for_client_connect_error(&resolve),
            RetryDisposition::Retry
        );
        assert_eq!(
            super::retry_disposition_for_client_connect_error(&missing),
            RetryDisposition::Retry
        );
        assert_eq!(
            super::retry_disposition_for_client_connect_error(&connect),
            RetryDisposition::Retry
        );
    }

    #[test]
    fn remote_graceful_tunnel_closes_are_classified_as_clean() {
        assert!(super::is_clean_client_tunnel_close(
            &quinn::ConnectionError::ApplicationClosed(ApplicationClose {
                error_code: VarInt::from_u32(0),
                reason: b"graceful shutdown".to_vec().into(),
            })
        ));
        assert!(super::is_clean_client_tunnel_close(
            &quinn::ConnectionError::ConnectionClosed(ConnectionClose {
                error_code: TransportErrorCode::NO_ERROR,
                frame_type: None,
                reason: b"graceful shutdown".to_vec().into(),
            })
        ));
        assert!(!super::is_clean_client_tunnel_close(
            &quinn::ConnectionError::TimedOut
        ));
    }

    #[test]
    fn ensure_client_identity_fresh_renews_due_certificates_before_connecting() {
        let tempdir = tempdir().expect("tempdir should be created");
        write_client_identity_with_not_before(
            tempdir.path(),
            OffsetDateTime::now_utc() - TimeDuration::days(61),
        );

        let original_private_key = fs::read(tempdir.path().join(CLIENT_KEY_FILENAME))
            .expect("client key should be readable");
        let original_certificate = fs::read(tempdir.path().join(CLIENT_CERT_FILENAME))
            .expect("client certificate should be readable");
        let original_identity = fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME))
            .expect("client identity should be readable");

        ensure_client_identity_fresh(tempdir.path()).expect("due certificate should be renewed");

        assert_eq!(
            fs::read(tempdir.path().join(CLIENT_KEY_FILENAME))
                .expect("client key should remain readable"),
            original_private_key
        );
        assert_ne!(
            fs::read(tempdir.path().join(CLIENT_CERT_FILENAME))
                .expect("renewed client certificate should be readable"),
            original_certificate
        );
        assert_eq!(
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME))
                .expect("client identity should remain readable"),
            original_identity
        );
    }

    #[test]
    fn ensure_client_identity_fresh_leaves_not_yet_due_certificates_untouched() {
        let tempdir = tempdir().expect("tempdir should be created");
        write_client_identity_with_not_before(
            tempdir.path(),
            OffsetDateTime::now_utc() - TimeDuration::days(60) + TimeDuration::minutes(1),
        );

        let original_private_key = fs::read(tempdir.path().join(CLIENT_KEY_FILENAME))
            .expect("client key should be readable");
        let original_certificate = fs::read(tempdir.path().join(CLIENT_CERT_FILENAME))
            .expect("client certificate should be readable");
        let original_identity = fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME))
            .expect("client identity should be readable");

        ensure_client_identity_fresh(tempdir.path())
            .expect("not-yet-due certificate should remain untouched");

        assert_eq!(
            fs::read(tempdir.path().join(CLIENT_KEY_FILENAME))
                .expect("client key should remain readable"),
            original_private_key
        );
        assert_eq!(
            fs::read(tempdir.path().join(CLIENT_CERT_FILENAME))
                .expect("client certificate should remain readable"),
            original_certificate
        );
        assert_eq!(
            fs::read_to_string(tempdir.path().join(CLIENT_IDENTITY_FILENAME))
                .expect("client identity should remain readable"),
            original_identity
        );
    }

    fn write_client_identity_with_not_before(directory: &Path, not_before: OffsetDateTime) {
        let signing_key = KeyPair::generate().expect("test signing key should generate");
        let mut certificate_params = CertificateParams::new(vec!["runewarp-client".to_owned()])
            .expect("test certificate params should build");
        certificate_params.not_before = not_before;
        certificate_params.not_after =
            not_before + TimeDuration::days(CLIENT_CERT_LIFETIME_DAYS as i64);
        let certificate = certificate_params
            .self_signed(&signing_key)
            .expect("test certificate should self-sign");
        let client_identity =
            ClientIdentity::from_subject_public_key_info(&signing_key.subject_public_key_info());

        fs::write(
            directory.join(CLIENT_KEY_FILENAME),
            signing_key.serialize_pem(),
        )
        .expect("test key should be written");
        fs::write(directory.join(CLIENT_CERT_FILENAME), certificate.pem())
            .expect("test certificate should be written");
        fs::write(
            directory.join(CLIENT_IDENTITY_FILENAME),
            client_identity.to_string(),
        )
        .expect("test client identity should be written");
    }
}
