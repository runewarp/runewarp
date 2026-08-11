use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::client::{AddressController, AddressWorkerFactory, AddressWorkerHooks};
use crate::{ClientAdmission, ClientInstancePrep, ShutdownMode};
use tokio::sync::oneshot;

pub struct ClientRuntime {
    settings: Arc<crate::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    local_bind_addr: SocketAddr,
}

impl ClientRuntime {
    pub async fn prepare(
        settings: &crate::ClientConfig,
        local_bind_addr: SocketAddr,
    ) -> Result<Self, crate::ClientStartupError> {
        let settings = Arc::new(settings.clone());
        let instance = ClientInstancePrep::prepare(settings.as_ref()).await?;
        Ok(Self {
            settings,
            instance,
            local_bind_addr,
        })
    }

    pub async fn run<F>(self, shutdown_signal: F) -> Result<(), Box<dyn Error>>
    where
        F: Future<Output = io::Result<ShutdownMode>>,
    {
        let Self {
            settings,
            instance,
            local_bind_addr,
        } = self;
        instance.start_acme_once();

        let result = run_client(
            Arc::clone(&settings),
            Arc::clone(&instance),
            local_bind_addr,
            shutdown_signal,
        )
        .await;
        instance.stop_acme().await;
        result
    }
}

async fn run_client<F>(
    settings: Arc<crate::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    local_bind_addr: SocketAddr,
    shutdown_signal: F,
) -> Result<(), Box<dyn Error>>
where
    F: Future<Output = io::Result<ShutdownMode>>,
{
    match settings.admission {
        ClientAdmission::Managed => {
            let control = settings.control.as_ref().ok_or_else(|| {
                io::Error::other("managed Client admission requires Control config")
            })?;
            run_managed_client(
                Arc::clone(&settings),
                Arc::clone(&instance),
                control,
                local_bind_addr,
                shutdown_signal,
            )
            .await
        }
        ClientAdmission::Static => {
            let factory = production_client_address_worker_factory(
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
                    if signal_result.is_ok() {
                        crate::runtime_log::client_graceful_shutdown_started();
                    }
                    shutdown.request();
                    let runtime_result = runtime.await;
                    signal_result?;
                    runtime_result
                }
            };
            client_result.map_err(|error| Box::new(io::Error::other(error)) as Box<dyn Error>)
        }
    }
}

fn production_client_address_worker_factory(
    settings: Arc<crate::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    local_bind_addr: SocketAddr,
) -> AddressWorkerFactory {
    Arc::new(move |server_address, control| {
        let dial = Arc::new(crate::ClientTunnelAttempt::new(
            Arc::clone(&settings),
            Arc::clone(&instance),
            local_bind_addr,
        ));
        Box::pin(async move {
            crate::client::run_address_worker_with_reconnect_policy(
                server_address,
                control,
                dial,
                Arc::new(RuntimeClientReadyHooks),
            )
            .await
        })
    })
}

struct RuntimeClientReadyHooks;

impl AddressWorkerHooks for RuntimeClientReadyHooks {
    fn on_client_ready(&self, configured_server_addr: &str) {
        crate::runtime_log::client_ready(configured_server_addr);
    }
}

async fn run_managed_client<F>(
    settings: Arc<crate::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    control: &crate::ControlConfig,
    local_bind_addr: SocketAddr,
    shutdown_signal: F,
) -> Result<(), Box<dyn Error>>
where
    F: Future<Output = io::Result<ShutdownMode>>,
{
    let factory = production_client_address_worker_factory(
        Arc::clone(&settings),
        Arc::clone(&instance),
        local_bind_addr,
    );
    let (mut controller, mut adapter) = AddressController::for_managed(factory);
    let shutdown = controller.shutdown_handle();

    let material = crate::SessionMaterial {
        control_hostname: control.address.hostname().as_str().to_owned(),
        trust: control.trust.clone(),
        identity: crate::ControlClientIdentityMaterial::from_client_identity_dir(
            &settings.identity_directory,
        ),
    };
    let mut session = crate::ManagedSession::new(
        control.address.clone(),
        crate::ManagedSessionRole::Client,
        material,
    )?;

    let (session_stop_tx, session_stop_rx) = oneshot::channel();
    let session_runtime = session.run(
        &mut adapter,
        |event| async move {
            crate::runtime_log::managed_session_event(crate::ManagedSessionRole::Client, &event);
        },
        async move {
            tokio::select! {
                signal_result = shutdown_signal => {
                    ClientSessionCompletion::ShutdownSignal(signal_result)
                }
                _ = session_stop_rx => ClientSessionCompletion::ControllerStopped,
            }
        },
    );
    let runtime = controller.run();
    coordinate_managed_client(runtime, session_runtime, shutdown, session_stop_tx).await
}

enum ClientSessionCompletion {
    ShutdownSignal(io::Result<ShutdownMode>),
    ControllerStopped,
}

async fn coordinate_managed_client<Controller, Session>(
    controller: Controller,
    session: Session,
    shutdown: crate::client::AddressControllerShutdown,
    session_stop: oneshot::Sender<()>,
) -> Result<(), Box<dyn Error>>
where
    Controller: Future<Output = Result<(), String>>,
    Session: Future<Output = ClientSessionCompletion>,
{
    tokio::pin!(controller);
    tokio::pin!(session);
    tokio::select! {
        result = &mut controller => {
            let _ = session_stop.send(());
            let _ = session.await;
            result.map_err(|error| Box::new(io::Error::other(error)) as Box<dyn Error>)
        }
        completion = &mut session => {
            match completion {
                ClientSessionCompletion::ShutdownSignal(signal_result) => {
                    if signal_result.is_ok() {
                        crate::runtime_log::client_graceful_shutdown_started();
                    }
                    shutdown.request();
                    let runtime_result = controller.await.map_err(|error| {
                        Box::new(io::Error::other(error)) as Box<dyn Error>
                    });
                    signal_result?;
                    runtime_result?;
                    Ok(())
                }
                ClientSessionCompletion::ControllerStopped => {
                    shutdown.request();
                    let _ = controller.await;
                    Err(Box::new(io::Error::other(
                        "managed Client session stopped unexpectedly",
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::client::{
        AddressController, AddressWorkerControl, wait_for_retry_delay, wait_for_shutdown,
    };
    use crate::{
        CLIENT_CERT_FILENAME, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME, ClientAdmission,
        ClientConfig, ClientTlsMode, LogLevel, PublicHostname, Server, ServerAddress,
        ServerAdmission, ServerAuthorization, ServerBindConfig, ServerHostname, ServerTunnelConfig,
        ServiceConfig, ShutdownMode, generate_client_identity,
        make_server_quic_config_with_client_admission,
    };

    use super::{ClientRuntime, ClientSessionCompletion, coordinate_managed_client};

    #[tokio::test]
    async fn managed_controller_failure_stops_and_awaits_session_before_returning() {
        let controller = AddressController::new();
        let shutdown = controller.shutdown_handle();
        let (stop_tx, stop_rx) = oneshot::channel();
        let session_finished = Arc::new(AtomicBool::new(false));
        let observed_finished = Arc::clone(&session_finished);

        let result = coordinate_managed_client(
            async { Err("controller failed".to_owned()) },
            async move {
                let _ = stop_rx.await;
                observed_finished.store(true, Ordering::SeqCst);
                ClientSessionCompletion::ControllerStopped
            },
            shutdown,
            stop_tx,
        )
        .await;

        assert_eq!(result.unwrap_err().to_string(), "controller failed");
        assert!(session_finished.load(Ordering::SeqCst));
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
        let authorization = ServerAuthorization::from_static_tunnels(
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
            server_trust: crate::ClientServerTrust::CaFile(tempdir.path().join("server-ca.pem")),
            identity_directory: tempdir.path().join("client-identity"),
            services: vec![ServiceConfig {
                public_hostnames: None,
                backend_address: backend_address.to_string(),
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            }],
            public_cert_config: None,
            control: None,
            admission: ClientAdmission::Static,
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let runtime = ClientRuntime::prepare(&settings, localhost(0))
            .await
            .unwrap();
        let client_future = runtime.run(async move {
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
