use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use runewarp::{
    AddressController, AddressWorkerControl, AddressWorkerFactory, ClientInstancePrep,
    MaintenanceIntent, PreparedClient, ServerAddress, ShutdownMode,
};
use tokio::net::lookup_host;

use runewarp::reconnect_policy::ReconnectPolicy;

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
    F: Future<Output = io::Result<ShutdownMode>>,
{
    let settings = Arc::new(settings.clone());
    let instance = ClientInstancePrep::prepare(settings.as_ref()).await?;
    instance.start_acme_once();

    if let Some(control) = settings.control.as_ref() {
        let result = run_managed_client(
            Arc::clone(&settings),
            Arc::clone(&instance),
            control,
            local_bind_addr,
            shutdown_signal,
        )
        .await;
        instance.stop_acme().await;
        return result;
    }

    let factory = static_address_worker_factory(
        Arc::clone(&settings),
        Arc::clone(&instance),
        local_bind_addr,
    );
    let mut controller = AddressController::for_static(factory);
    controller.seed_configured(settings.server_addresses.clone());
    let shutdown = controller.shutdown_handle();

    let runtime = controller.run();
    tokio::pin!(runtime);
    tokio::pin!(shutdown_signal);
    let client_result = tokio::select! {
        result = &mut runtime => result,
        signal_result = &mut shutdown_signal => {
            let _mode = signal_result?;
            runewarp::runtime_log::client_graceful_shutdown_started();
            shutdown.request();
            runtime.await
        }
    };
    instance.stop_acme().await;
    client_result.map_err(|error| Box::new(io::Error::other(error)) as Box<dyn Error>)
}

fn static_address_worker_factory(
    settings: Arc<runewarp::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    local_bind_addr: SocketAddr,
) -> AddressWorkerFactory {
    Arc::new(move |server_address, control| {
        let settings = Arc::clone(&settings);
        let instance = Arc::clone(&instance);
        Box::pin(run_server_address_worker(
            settings,
            instance,
            server_address,
            local_bind_addr,
            control,
        ))
    })
}

async fn run_managed_client<F>(
    settings: Arc<runewarp::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    control: &runewarp::ControlConfig,
    local_bind_addr: SocketAddr,
    shutdown_signal: F,
) -> Result<(), Box<dyn Error>>
where
    F: Future<Output = io::Result<ShutdownMode>>,
{
    let factory = static_address_worker_factory(
        Arc::clone(&settings),
        Arc::clone(&instance),
        local_bind_addr,
    );
    let (mut controller, mut adapter) = AddressController::for_managed(factory);
    let shutdown = controller.shutdown_handle();

    let material = runewarp::SessionMaterial {
        control_hostname: control.address.hostname().as_str().to_owned(),
        trust: control.trust.clone(),
        identity: runewarp::ControlClientIdentityMaterial::from_client_identity_dir(
            &settings.identity_directory,
        ),
    };
    let mut session = runewarp::ManagedSession::new(
        control.address.clone(),
        runewarp::ManagedSessionRole::Client,
        material,
    )?;

    let session_runtime = session.run(
        &mut adapter,
        |event| async move {
            runewarp::runtime_log::managed_session_event(
                runewarp::ManagedSessionRole::Client,
                &event,
            );
        },
        shutdown_signal,
    );
    tokio::pin!(session_runtime);
    let runtime = controller.run();
    tokio::pin!(runtime);

    tokio::select! {
        result = &mut runtime => {
            result.map_err(|error| Box::new(io::Error::other(error)) as Box<dyn Error>)
        }
        session_result = &mut session_runtime => {
            let _mode = session_result?;
            runewarp::runtime_log::client_graceful_shutdown_started();
            shutdown.request();
            runtime.await.map_err(|error| {
                Box::new(io::Error::other(error)) as Box<dyn Error>
            })?;
            Ok(())
        }
    }
}

async fn run_server_address_worker(
    settings: Arc<runewarp::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    server_address: ServerAddress,
    local_bind_addr: SocketAddr,
    control: AddressWorkerControl,
) -> Result<(), String> {
    let mut connected_once = false;
    let mut reconnect_policy = ReconnectPolicy::new();
    let configured_server_addr =
        configured_server_addr(server_address.hostname().as_str(), server_address.port());
    let mut maintenance = control.subscribe_maintenance();
    loop {
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            // Establishing / reconnecting work stops on remove. Connected workers reach
            // this check only after their tunnel run ends (Retire does not locally close).
            return Ok(());
        }

        let phase = client_tunnel_phase(connected_once);
        let attempt_kind = client_tunnel_attempt_kind(reconnect_policy.is_fresh());
        let dial_target = match tokio::select! {
            _ = wait_for_shutdown(&control) => return Ok(()),
            changed = maintenance.changed() => {
                if changed.is_err()
                    || control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    return Ok(());
                }
                continue;
            }
            result = resolve_client_tunnel_dial_target(&server_address) => result,
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
                        &configured_server_addr,
                        retry.display_delay_secs,
                        &error.to_string(),
                    );
                    if wait_for_retry_delay(retry.delay, &control).await {
                        continue;
                    }
                    return Ok(());
                }
                return Err(error.to_string());
            }
        };

        if control.maintenance_intent() == MaintenanceIntent::Retire {
            return Ok(());
        }

        runewarp::runtime_log::client_tunnel_connecting(
            phase,
            attempt_kind,
            &dial_target.configured_server_addr,
            dial_target.resolved_server_addr,
        );

        let client = match tokio::select! {
            _ = wait_for_shutdown(&control) => return Ok(()),
            changed = maintenance.changed() => {
                if changed.is_err()
                    || control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    return Ok(());
                }
                continue;
            }
            result = PreparedClient::connect_to_server_address(
                &settings,
                &instance,
                local_bind_addr,
                &server_address,
                dial_target.resolved_server_addr,
            ) => result,
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
                    if wait_for_retry_delay(retry.delay, &control).await {
                        continue;
                    }
                    return Ok(());
                }
                return Err(error.to_string());
            }
        };

        let first_connection = !connected_once;
        let retiring = control.maintenance_intent() == MaintenanceIntent::Retire;
        if !retiring {
            reconnect_policy.reset();
        }
        connected_once = true;
        runewarp::runtime_log::client_tunnel_connected(
            phase,
            &dial_target.configured_server_addr,
            dial_target.resolved_server_addr,
        );
        if first_connection && control.claim_client_ready_log() {
            runewarp::runtime_log::client_ready(&dial_target.configured_server_addr);
        }
        if let Some(status) = control.observe_connected(&server_address) {
            runewarp::runtime_log::client_assignment_convergence(status);
        }

        let run_result = client
            .run_until_shutdown({
                let control = control.clone();
                let configured_server_addr = dial_target.configured_server_addr.clone();
                async move {
                    wait_for_process_shutdown_observing_retire(&control, &configured_server_addr)
                        .await;
                    ShutdownMode::Graceful
                }
            })
            .await;

        if let Some(status) = control.observe_disconnected(&server_address) {
            runewarp::runtime_log::client_assignment_convergence(status);
        }

        // Retiring connections stay live until remote close or process shutdown, then exit
        // without reconnecting. Maintained connections reconnect after unexpected closes.
        if control.shutdown_requested() || control.maintenance_intent() == MaintenanceIntent::Retire
        {
            return Ok(());
        }

        if let Err(error) = run_result {
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
            if wait_for_retry_delay(retry.delay, &control).await {
                continue;
            }
            return Ok(());
        }

        return Ok(());
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
    server_address: &ServerAddress,
) -> Result<ClientTunnelDialTarget, runewarp::ClientStartupError> {
    let mut server_addrs = lookup_host((server_address.hostname().as_str(), server_address.port()))
        .await
        .map_err(runewarp::ClientStartupError::Resolve)?;
    let Some(resolved_server_addr) = server_addrs.next() else {
        return Err(runewarp::ClientStartupError::MissingServerAddress {
            server_hostname: server_address.hostname().to_string(),
        });
    };
    Ok(ClientTunnelDialTarget {
        configured_server_addr: configured_server_addr(
            server_address.hostname().as_str(),
            server_address.port(),
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

async fn wait_for_shutdown(control: &AddressWorkerControl) {
    let mut shutdown = control.subscribe_shutdown();
    if control.shutdown_requested() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Wait for process shutdown while observing Retire without closing the live tunnel.
async fn wait_for_process_shutdown_observing_retire(
    control: &AddressWorkerControl,
    configured_server_addr: &str,
) {
    let mut maintenance = control.subscribe_maintenance();
    let mut shutdown = control.subscribe_shutdown();
    let mut logged_retiring = false;
    if control.maintenance_intent() == MaintenanceIntent::Retire {
        runewarp::runtime_log::client_tunnel_retiring(configured_server_addr);
        logged_retiring = true;
    }
    if control.shutdown_requested() {
        return;
    }
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || control.shutdown_requested() {
                    return;
                }
            }
            changed = maintenance.changed() => {
                if changed.is_err() {
                    return;
                }
                if !logged_retiring
                    && control.maintenance_intent() == MaintenanceIntent::Retire
                {
                    runewarp::runtime_log::client_tunnel_retiring(configured_server_addr);
                    logged_retiring = true;
                }
            }
        }
    }
}

/// Returns true when the worker should continue retrying after the delay.
async fn wait_for_retry_delay(delay: Duration, control: &AddressWorkerControl) -> bool {
    let mut maintenance = control.subscribe_maintenance();
    tokio::select! {
        _ = wait_for_shutdown(control) => false,
        changed = maintenance.changed() => {
            if changed.is_err() {
                return false;
            }
            !control.shutdown_requested()
                && control.maintenance_intent() != MaintenanceIntent::Retire
        }
        _ = tokio::time::sleep(delay) => {
            !control.shutdown_requested()
                && control.maintenance_intent() != MaintenanceIntent::Retire
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::{ApplicationClose, ConnectionClose, TransportErrorCode, VarInt};
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use runewarp::{
        AddressController, AddressWorkerControl, CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME,
        CLIENT_KEY_FILENAME, ClientConfig, ClientTlsMode, LogLevel, PublicHostname, Server,
        ServerAddress, ServerAdmission, ServerAuthorization, ServerBindConfig, ServerHostname,
        ServerTunnelConfig, ServiceConfig, ShutdownMode, generate_client_identity,
        make_server_quic_config_with_client_admission,
    };

    use super::{
        RetryDisposition, client_tunnel_attempt_kind, run_until_orderly_shutdown,
        wait_for_retry_delay, wait_for_shutdown,
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
        let (control, mut controller) = spawn_idle_worker_control().await;
        assert!(wait_for_retry_delay(Duration::ZERO, &control).await);
        controller.request_shutdown();
        controller.run_until_idle().await.unwrap();
    }

    #[tokio::test]
    async fn wait_for_retry_delay_stops_when_shutdown_arrives_first() {
        let (control, mut controller) = spawn_idle_worker_control().await;
        let wait = tokio::spawn({
            let control = control.clone();
            async move { wait_for_retry_delay(Duration::from_secs(60), &control).await }
        });
        tokio::task::yield_now().await;
        controller.request_shutdown();
        assert!(!wait.await.unwrap());
        controller.run_until_idle().await.unwrap();
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

    #[tokio::test]
    #[ignore = "requires local socket binding"]
    async fn client_runtime_keeps_serving_through_a_healthy_server_address_when_another_fails()
    -> io::Result<()> {
        let (backend_cert, backend_key) = make_self_signed_cert("app.example.test")?;
        let backend_listener = TcpListener::bind(localhost(0)).await?;
        let backend_address = backend_listener.local_addr()?;
        let backend_acceptor = TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![backend_cert.clone()],
                    private_key_from_der(&backend_key),
                )
                .map_err(io::Error::other)?,
        ));
        let backend_task = tokio::spawn(async move {
            loop {
                let (tcp_stream, _) = backend_listener.accept().await?;
                let mut tls_stream = backend_acceptor.accept(tcp_stream).await?;
                let mut request = [0_u8; 4];
                tls_stream.read_exact(&mut request).await?;
                if &request != b"ping" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected backend request",
                    ));
                }
                tls_stream.write_all(b"pong").await?;
                tls_stream.shutdown().await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        });

        let certified_server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .map_err(io::Error::other)?;
        let server_cert_pem = certified_server.cert.pem();
        let server_cert = CertificateDer::from(certified_server.cert);
        let server_key = certified_server.signing_key.serialize_der();
        let client_identity = generate_client_identity().map_err(io::Error::other)?;
        let authorization = ServerAuthorization::from_tunnels(
            &server_hostname("localhost"),
            &[ServerTunnelConfig {
                id: None,
                public_hostnames: vec![public_hostname("app.example.test")],
                authorized_client_identities: vec![client_identity.client_identity.clone()],
            }],
        )
        .unwrap();
        let server = Server::bind(ServerBindConfig {
            public_bind_addr: localhost(0),
            tunnel_connection_bind_addr: localhost(0),
            readiness_bind_addr: None,
            server_hostname: server_hostname("localhost"),
            authorization: authorization.clone(),
            public_tls_config: None,
            quic_server_config: make_server_quic_config_with_client_admission(
                vec![server_cert.clone()],
                private_key_from_der(&server_key),
                Arc::new(authorization.clone()),
            )
            .map_err(io::Error::other)?,
            admission: ServerAdmission::Static,
        })
        .await
        .map_err(io::Error::other)?;
        let public_addr = server.public_addr()?;
        let tunnel_addr = server.tunnel_addr()?;
        let server_task = tokio::spawn(server.run());

        let tempdir = tempdir()?;
        fs::write(tempdir.path().join("server-ca.pem"), server_cert_pem)?;
        fs::create_dir(tempdir.path().join("client-identity"))?;
        fs::write(
            tempdir
                .path()
                .join("client-identity")
                .join(CLIENT_CERT_FILENAME),
            &client_identity.certificate_pem,
        )?;
        fs::write(
            tempdir
                .path()
                .join("client-identity")
                .join(CLIENT_KEY_FILENAME),
            &client_identity.private_key_pem,
        )?;
        fs::write(
            tempdir
                .path()
                .join("client-identity")
                .join(CLIENT_IDENTITY_FILENAME),
            client_identity.client_identity.to_string(),
        )?;

        let unused_udp = std::net::UdpSocket::bind(localhost(0))?;
        let failing_port = unused_udp.local_addr()?.port();
        drop(unused_udp);
        let valid_server_address =
            ServerAddress::parse(&format!("localhost:{}", tunnel_addr.port()))
                .map_err(io::Error::other)?;
        let failing_server_address =
            ServerAddress::parse(&format!("localhost:{failing_port}")).map_err(io::Error::other)?;
        let settings = ClientConfig {
            server_addresses: vec![failing_server_address.clone(), valid_server_address.clone()],
            server_hostname: failing_server_address.hostname().clone(),
            server_port: failing_server_address.port(),
            log_level: LogLevel::Off,
            server_ca_file: Some(tempdir.path().join("server-ca.pem")),
            identity_directory: tempdir.path().join("client-identity"),
            services: vec![ServiceConfig {
                public_hostnames: None,
                backend_address: backend_address.to_string(),
                tls_mode: ClientTlsMode::Passthrough,
            }],
            public_cert_config: None,
            control: None,
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let client_future = run_until_orderly_shutdown(&settings, localhost(0), async move {
            let _ = shutdown_rx.await;
            Ok(ShutdownMode::Graceful)
        });
        tokio::pin!(client_future);

        for _ in 0..20 {
            tokio::select! {
                client_result = &mut client_future => {
                    return Err(io::Error::other(format!(
                        "client runtime exited before healthy address served traffic: {}",
                        client_result.err().map(|error| error.to_string()).unwrap_or_else(|| "unexpected clean exit".to_owned())
                    )));
                }
                _ = sleep(Duration::from_millis(100)) => {
                    if let Ok(response) =
                        wait_for_tls_response(public_addr, &backend_cert, "app.example.test").await
                    {
                        assert_eq!(response, *b"pong");
                        shutdown_tx
                            .send(())
                            .map_err(|_| io::Error::other("failed to stop client runtime"))?;
                        timeout(Duration::from_secs(5), &mut client_future)
                            .await
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client shutdown timed out"))?
                            .map_err(|error| io::Error::other(error.to_string()))?;
                        backend_task.abort();
                        server_task.abort();
                        let _ = backend_task.await;
                        let _ = server_task.await;
                        return Ok(());
                    }
                }
            }
        }

        backend_task.abort();
        server_task.abort();
        let _ = backend_task.await;
        let _ = server_task.await;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "healthy server address never became ready",
        ))
    }

    async fn spawn_idle_worker_control() -> (AddressWorkerControl, AddressController) {
        let mut controller = AddressController::new();
        let (control_tx, control_rx) = oneshot::channel();
        assert!(controller.add(
            ServerAddress::parse("tunnel.example.test").unwrap(),
            move |_address, control| {
                async move {
                    let _ = control_tx.send(control.clone());
                    wait_for_shutdown(&control).await;
                    Ok(())
                }
            }
        ));
        let control = control_rx.await.unwrap();
        (control, controller)
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn public_hostname(hostname: &str) -> PublicHostname {
        PublicHostname::try_from(hostname).expect("test public hostname should parse")
    }

    fn server_hostname(hostname: &str) -> ServerHostname {
        ServerHostname::try_from(hostname).expect("test server hostname should parse")
    }

    fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn make_self_signed_cert(hostname: &str) -> io::Result<(CertificateDer<'static>, Vec<u8>)> {
        let certified = rcgen::generate_simple_self_signed(vec![hostname.to_owned()])
            .map_err(io::Error::other)?;
        Ok((
            CertificateDer::from(certified.cert),
            certified.signing_key.serialize_der(),
        ))
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }

    async fn wait_for_tls_response(
        public_addr: SocketAddr,
        backend_cert: &CertificateDer<'static>,
        server_name: &str,
    ) -> io::Result<[u8; 4]> {
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store_with(backend_cert)?)
                .with_no_client_auth(),
        ));
        let tcp_stream = TcpStream::connect(public_addr).await?;
        let mut tls_stream = connector
            .connect(
                ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?,
                tcp_stream,
            )
            .await?;
        tls_stream.write_all(b"ping").await?;
        let mut response = [0_u8; 4];
        tls_stream.read_exact(&mut response).await?;
        Ok(response)
    }
}
