mod address_controller;
mod address_worker;
mod assignment_convergence;
mod managed_adapter;
mod service;
mod stream_limits;
mod termination_tls;
mod tunnel_attempt;
mod tunnel_stream;

pub use address_controller::{
    AddressController, AddressControllerShutdown, AddressControllerView, AddressWorkerControl,
    AddressWorkerFactory, MaintenanceIntent,
};
pub(crate) use address_worker::run_address_worker_with_reconnect_policy;
pub use address_worker::{
    AddressWorkerBackoff, AddressWorkerDial, AddressWorkerHooks, FixedBackoff,
    SilentAddressWorkerHooks, run_address_worker,
};
#[cfg(test)]
pub(crate) use address_worker::{wait_for_retry_delay, wait_for_shutdown};
pub use assignment_convergence::AssignmentConvergence;
pub use managed_adapter::ClientAssignmentAdapter;
pub use tunnel_attempt::{
    ClientTunnelAttempt, TunnelAttemptFailure, TunnelAttemptOutcome, TunnelConnectionControl,
    TunnelConnectionEnd, TunnelConnectionRun,
};

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::tunnel::{
    ClientTunnelH3, ClientTunnelStream, ReplacementHint, ServerRuntimeGeneration, TunnelH3Error,
    UnconfirmedDrain, WithdrawalOutcome,
};
use quinn::Endpoint;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

pub(crate) use self::stream_limits::{ClientStreamBudget, ClientStreamLimits};
pub(crate) use self::termination_tls::TerminationTlsConfigs;
use self::tunnel_stream::TunnelConnectionStreamHandler;
use crate::{
    ClientTlsMode, HANDSHAKE_TIMEOUT, ServiceConfig,
    quic::with_handshake_timeout,
    shutdown::{OrderlyShutdown, ShutdownMode},
};

pub use crate::config::client::{
    ClientConfigResolutionDefaults, ClientConfigResolutionError, ClientRuntimeArgs,
    SelectedClientConfig, resolve_client_config_from_cli, resolve_selected_client_config,
    select_client_config,
};
pub(crate) use service::{ServiceSelector, validate_services};

#[derive(Clone)]
pub struct ClientConnectConfig {
    pub local_bind_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub backend_address: String,
    pub quic_client_config: quinn::ClientConfig,
}

#[derive(Clone)]
pub(crate) struct RoutedClientConnectConfig {
    pub(crate) local_bind_addr: SocketAddr,
    pub(crate) server_addr: SocketAddr,
    pub(crate) server_name: String,
    pub(crate) services: Vec<ServiceConfig>,
    pub(crate) quic_client_config: quinn::ClientConfig,
    pub(crate) termination_tls_configs: TerminationTlsConfigs,
    pub(crate) stream_budget: Arc<ClientStreamBudget>,
    /// A candidate attempt requires the Server to report this runtime generation.
    pub(crate) expected_generation: Option<ServerRuntimeGeneration>,
}

/// Why a connection run withdrew its connection from placement, and how that ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionDrain {
    /// Graceful Client shutdown withdrew the connection.
    Shutdown(WithdrawalOutcome),
    /// A promoted candidate replaced the connection, which then retired.
    Retirement(WithdrawalOutcome),
}

enum ClientRouteMode {
    CatchAll {
        backend_address: String,
    },
    Routed {
        services: Vec<ServiceConfig>,
        termination_tls_configs: TerminationTlsConfigs,
        stream_budget: Arc<ClientStreamBudget>,
    },
}

pub struct Client {
    endpoint: Endpoint,
    connection: ClientTunnelH3,
    tunnel_stream_handler: TunnelConnectionStreamHandler,
}

#[derive(Debug)]
pub enum ClientConnectError {
    Bind(io::Error),
    Connect(quinn::ConnectError),
    Handshake(quinn::ConnectionError),
    Tunnel(TunnelH3Error),
}

impl fmt::Display for ClientConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(_) => formatter.write_str("failed to bind the client endpoint"),
            Self::Connect(_) => formatter.write_str("failed to start the client connection"),
            Self::Handshake(_) => formatter.write_str("client QUIC handshake failed"),
            Self::Tunnel(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClientConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::Tunnel(error) => Some(error),
        }
    }
}

impl ClientConnectError {
    pub fn is_unauthorized_client_identity(&self) -> bool {
        match self {
            Self::Handshake(error) => is_tls_access_denied(error),
            Self::Tunnel(error) => error.is_unauthorized_client_identity(),
            _ => false,
        }
    }
}

pub(crate) use crate::quic::is_tls_access_denied;

impl Client {
    pub async fn connect(config: ClientConnectConfig) -> Result<Self, ClientConnectError> {
        Self::connect_internal(
            config.local_bind_addr,
            config.server_addr,
            config.server_name,
            config.quic_client_config,
            ClientRouteMode::CatchAll {
                backend_address: config.backend_address,
            },
            None,
        )
        .await
    }

    pub(crate) async fn connect_with_services(
        config: RoutedClientConnectConfig,
    ) -> Result<Self, ClientConnectError> {
        Self::connect_internal(
            config.local_bind_addr,
            config.server_addr,
            config.server_name,
            config.quic_client_config,
            ClientRouteMode::Routed {
                services: config.services,
                termination_tls_configs: config.termination_tls_configs,
                stream_budget: config.stream_budget,
            },
            config.expected_generation,
        )
        .await
    }

    async fn connect_internal(
        local_bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: String,
        quic_client_config: quinn::ClientConfig,
        route_mode: ClientRouteMode,
        expected_generation: Option<ServerRuntimeGeneration>,
    ) -> Result<Self, ClientConnectError> {
        let hostname = crate::ServerHostname::try_from(server_name.as_str()).map_err(|_| {
            ClientConnectError::Connect(quinn::ConnectError::InvalidServerName(server_name.clone()))
        })?;
        let mut endpoint = Endpoint::client(local_bind_addr).map_err(ClientConnectError::Bind)?;
        endpoint.set_default_client_config(quic_client_config);

        let connection = with_handshake_timeout(
            endpoint
                .connect(server_addr, &server_name)
                .map_err(ClientConnectError::Connect)?,
            HANDSHAKE_TIMEOUT,
            || quinn::ConnectionError::TimedOut,
        )
        .await
        .map_err(ClientConnectError::Handshake)?;
        let (services, termination_tls_configs, stream_budget) =
            services_and_configs_for_route_mode(route_mode);
        let connection = ClientTunnelH3::establish_with_budget_observer(
            connection,
            &hostname,
            stream_budget.semaphore(),
            {
                let stream_budget = stream_budget.clone();
                Arc::new(move |available| {
                    if available {
                        stream_budget.note_recovery();
                    } else {
                        stream_budget.note_saturation();
                    }
                })
            },
            expected_generation,
        )
        .await
        .map_err(ClientConnectError::Tunnel)?;
        let tunnel_stream_handler = TunnelConnectionStreamHandler::new(
            services,
            termination_tls_configs,
            stream_budget.limits(),
        );

        Ok(Self {
            endpoint,
            connection,
            tunnel_stream_handler,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Replacement hint the address worker may act on for this connection.
    pub fn replacement_hint(&self) -> watch::Receiver<ReplacementHint> {
        self.connection.replacement_hint()
    }

    pub async fn run(mut self) -> Result<(), quinn::ConnectionError> {
        while let Some(stream) = self.connection.accept_tunnel_stream().await {
            self.spawn_stream_handler(stream);
        }
        Err(self.connection.closed().await)
    }

    /// Run until `shutdown_signal`, then close at once in either mode.
    pub async fn run_until_shutdown<Shutdown>(
        self,
        shutdown_signal: Shutdown,
    ) -> Result<(), quinn::ConnectionError>
    where
        Shutdown: Future<Output = ShutdownMode> + Send + 'static,
    {
        let shutdown = OrderlyShutdown::new(
            std::time::Duration::from_secs(0),
            crate::server::QUIC_CLOSE_FLUSH_DURATION,
        );
        let shutdown_trigger = shutdown.clone();
        tokio::spawn(async move {
            match shutdown_signal.await {
                ShutdownMode::Graceful => {
                    let _ = shutdown_trigger.begin_graceful();
                }
                ShutdownMode::Fast => {
                    let _ = shutdown_trigger.begin_fast();
                }
            }
        });
        // A zero graceful duration never withdraws, so there is no outcome to report.
        self.run_with_shutdown(&shutdown).await.map(|_| ())
    }

    /// Run until the connection closes or `shutdown` starts.
    ///
    /// Fast shutdown, or Graceful with a zero duration, closes at once and returns `None`.
    /// Graceful withdraws this connection from placement while continuing to accept Visitors the
    /// Server committed first, and returns the withdrawal outcome. The shared graceful deadline
    /// or a later Fast escalation closes the connection with an unconfirmed drain.
    pub async fn run_with_shutdown(
        self,
        shutdown: &OrderlyShutdown,
    ) -> Result<Option<WithdrawalOutcome>, quinn::ConnectionError> {
        Ok(self
            .run_with_control(shutdown, None)
            .await?
            .map(|drain| match drain {
                ConnectionDrain::Shutdown(outcome) | ConnectionDrain::Retirement(outcome) => {
                    outcome
                }
            }))
    }

    /// Like [`Self::run_with_shutdown`], and retire the connection when `retirement` yields a
    /// deadline.
    ///
    /// Retirement withdraws the connection from placement as graceful shutdown does, bounded by
    /// that deadline. Under GOAWAY no withdrawal is sent and the Server's drain retires the
    /// connection. A later graceful shutdown joins the retirement under the earlier of the two
    /// deadlines; Fast closes at once.
    pub(crate) async fn run_with_control(
        mut self,
        shutdown: &OrderlyShutdown,
        mut retirement: Option<oneshot::Receiver<Instant>>,
    ) -> Result<Option<ConnectionDrain>, quinn::ConnectionError> {
        let closed = self.connection.closed();
        tokio::pin!(closed);
        let mut accepting = true;
        let mut withdrawal: Option<
            std::pin::Pin<Box<dyn Future<Output = WithdrawalOutcome> + Send>>,
        > = None;
        let mut retirement_deadline = None;
        let mut joined_shutdown = false;
        loop {
            let withdrawing = withdrawal.is_some();
            let retiring = retirement_deadline.is_some();
            let deadline = match (retirement_deadline, shutdown.graceful_deadline()) {
                (Some(retirement), Some(shutdown)) => Some(Instant::min(retirement, shutdown)),
                (retirement, shutdown) => retirement.or(shutdown),
            };
            let outcome = tokio::select! {
                biased;
                // The withdrawal observes connection loss itself, so only its result counts.
                outcome = async {
                    withdrawal.as_mut().expect("withdrawal started").await
                }, if withdrawing => outcome,
                _ = shutdown.wait_for_fast(), if withdrawing => {
                    WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::FastShutdown)
                }
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }, if withdrawing => WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::Deadline),
                // Graceful shutdown joins an in-flight retirement; only its deadline applies.
                _ = shutdown.wait_started(), if retiring && !joined_shutdown => {
                    joined_shutdown = true;
                    continue;
                }
                mode = shutdown.wait_started(), if !withdrawing => {
                    if mode == ShutdownMode::Graceful
                        && !shutdown.graceful_shutdown_duration().is_zero()
                    {
                        withdrawal = Some(Box::pin(self.connection.withdrawal()));
                        continue;
                    }
                    crate::runtime_log::client_graceful_shutdown_closing_tunnel_connection();
                    self.connection.close();
                    tokio::time::sleep(shutdown.quic_close_flush_duration()).await;
                    return Ok(None);
                }
                deadline = async {
                    retirement.as_mut().expect("retirement pending").await
                }, if !withdrawing && retirement.is_some() => {
                    retirement = None;
                    if let Ok(deadline) = deadline {
                        retirement_deadline = Some(deadline);
                        withdrawal = Some(Box::pin(self.connection.retirement_withdrawal()));
                    }
                    continue;
                }
                error = &mut closed, if !withdrawing => return Err(error),
                stream = self.connection.accept_tunnel_stream(), if accepting => {
                    match stream {
                        Some(stream) => self.spawn_stream_handler(stream),
                        None => accepting = false,
                    }
                    continue;
                }
            };
            // A `204` already received stays confirmed even if Fast or the deadline wins while
            // local Visitor leases drain.
            let outcome = if self.connection.withdrawal_confirmed() {
                WithdrawalOutcome::Confirmed
            } else {
                outcome
            };
            self.connection.close();
            tokio::time::sleep(shutdown.quic_close_flush_duration()).await;
            return Ok(Some(if retiring {
                ConnectionDrain::Retirement(outcome)
            } else {
                ConnectionDrain::Shutdown(outcome)
            }));
        }
    }

    fn spawn_stream_handler(&self, stream: ClientTunnelStream) {
        let tunnel_stream_handler = self.tunnel_stream_handler.clone();
        tokio::spawn(async move {
            let _ = tunnel_stream_handler.handle(stream).await;
        });
    }
}

fn services_and_configs_for_route_mode(
    route_mode: ClientRouteMode,
) -> (
    Vec<ServiceConfig>,
    TerminationTlsConfigs,
    Arc<ClientStreamBudget>,
) {
    match route_mode {
        ClientRouteMode::CatchAll { backend_address } => (
            vec![ServiceConfig {
                public_hostnames: None,
                backend_address,
                tls_mode: ClientTlsMode::Passthrough,
                proxy_protocol: None,
            }],
            TerminationTlsConfigs::empty(),
            Arc::new(ClientStreamBudget::new(ClientStreamLimits::default())),
        ),
        ClientRouteMode::Routed {
            services,
            termination_tls_configs,
            stream_budget,
        } => (services, termination_tls_configs, stream_budget),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::pem::Error as PemError;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::time::timeout;

    use super::{Client, ClientConnectConfig, ClientConnectError};
    use crate::tls_material::{certificate_chain_from_pem, private_key_from_pem};
    use crate::tunnel::test_support::test_server_h3_config;
    use crate::{GeneratedClientIdentity, generate_client_identity, make_client_tunnel_h3_config};

    #[test]
    fn client_connect_error_display_omits_nested_transport_detail() {
        assert_eq!(
            ClientConnectError::Bind(io::Error::other("address already in use")).to_string(),
            "failed to bind the client endpoint"
        );
        assert_eq!(
            ClientConnectError::Handshake(quinn::ConnectionError::TimedOut).to_string(),
            "client QUIC handshake failed"
        );
    }

    #[tokio::test]
    async fn handshake_errors_detect_unauthorized_client_identity() -> io::Result<()> {
        let authorized_client_identity = generate_test_client_identity()?;
        let unauthorized_client_identity = generate_test_client_identity()?;
        let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
        let server_endpoint = Endpoint::server(
            test_server_h3_config(
                vec![certificate.clone()],
                private_key_from_der(&private_key),
                std::slice::from_ref(&authorized_client_identity.client_identity),
            )
            .map_err(io::Error::other)?,
            localhost(0),
        )
        .map_err(io::Error::other)?;

        let client_config = ClientConnectConfig {
            local_bind_addr: localhost(0),
            server_addr: server_endpoint.local_addr()?,
            server_name: "tunnel.example.test".to_owned(),
            backend_address: "127.0.0.1:443".to_owned(),
            quic_client_config: make_client_tunnel_h3_config(
                root_store_with(&certificate)?,
                client_certificate_chain(&unauthorized_client_identity)?,
                client_private_key(&unauthorized_client_identity)?,
            )
            .map_err(io::Error::other)?,
        };

        let accept_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(1), server_endpoint.accept())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
                })?;
            let _ = timeout(Duration::from_secs(1), incoming)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?;
            Ok::<(), io::Error>(())
        });

        match Client::connect(client_config).await {
            Err(error) => {
                assert!(error.is_unauthorized_client_identity(), "{error:?}");
            }
            Ok(client) => {
                let run_error = timeout(Duration::from_secs(1), client.run())
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "unauthorized connection should close quickly",
                        )
                    })?
                    .expect_err("unauthorized connection should not stay open");
                assert!(
                    run_error
                        .to_string()
                        .contains("ApplicationVerificationFailure")
                );
            }
        }
        accept_task.await.map_err(|join_error| {
            io::Error::other(format!("accept task failed: {join_error}"))
        })??;
        Ok(())
    }

    /// A Server peer and a routed Client on one Tunnel connection, sharing `budget`.
    async fn retirement_pair(
        budget: Arc<super::ClientStreamBudget>,
    ) -> (crate::tunnel::ServerTunnelH3, Client) {
        let identity = generate_test_client_identity().unwrap();
        let (certificate, private_key) = make_self_signed_cert("tunnel.example.test").unwrap();
        let endpoint = Endpoint::server(
            test_server_h3_config(
                vec![certificate.clone()],
                private_key_from_der(&private_key),
                std::slice::from_ref(&identity.client_identity),
            )
            .unwrap(),
            localhost(0),
        )
        .unwrap();
        let config = super::RoutedClientConnectConfig {
            local_bind_addr: localhost(0),
            server_addr: endpoint.local_addr().unwrap(),
            server_name: "tunnel.example.test".to_owned(),
            services: vec![crate::ServiceConfig {
                public_hostnames: None,
                backend_address: "127.0.0.1:9".to_owned(),
                tls_mode: crate::ClientTlsMode::Passthrough,
                proxy_protocol: None,
            }],
            quic_client_config: make_client_tunnel_h3_config(
                root_store_with(&certificate).unwrap(),
                client_certificate_chain(&identity).unwrap(),
                client_private_key(&identity).unwrap(),
            )
            .unwrap(),
            termination_tls_configs: super::TerminationTlsConfigs::empty(),
            stream_budget: budget,
            expected_generation: None,
        };
        let server = async {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            crate::tunnel::ServerTunnelH3::establish(
                connection,
                crate::ServerHostname::try_from("tunnel.example.test").unwrap(),
                crate::tunnel::ServerRuntimeGeneration::generate(),
            )
            .await
            .unwrap()
        };
        let (server, client) = tokio::join!(server, Client::connect_with_services(config));
        (server, client.unwrap())
    }

    fn budget(permits: usize) -> Arc<super::ClientStreamBudget> {
        Arc::new(super::ClientStreamBudget::new(super::ClientStreamLimits {
            max_stream_handlers: permits,
            ..super::ClientStreamLimits::default()
        }))
    }

    fn shutdown(graceful: Duration) -> crate::OrderlyShutdown {
        crate::OrderlyShutdown::new(graceful, Duration::ZERO)
    }

    /// Run `client` with a retirement trigger; returns the trigger and the running task.
    fn run_retirable(
        client: Client,
        shutdown: crate::OrderlyShutdown,
    ) -> (
        tokio::sync::oneshot::Sender<tokio::time::Instant>,
        tokio::task::JoinHandle<Result<Option<super::ConnectionDrain>, quinn::ConnectionError>>,
    ) {
        let (retire, retirement) = tokio::sync::oneshot::channel();
        let task =
            tokio::spawn(async move { client.run_with_control(&shutdown, Some(retirement)).await });
        (retire, task)
    }

    async fn wait_for_permits(budget: &super::ClientStreamBudget, permits: usize) {
        timeout(Duration::from_secs(2), async {
            while budget.semaphore().available_permits() != permits {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("permits settle");
    }

    #[tokio::test]
    async fn retirement_withdraws_and_returns_every_permit_once_confirmed() {
        let budget = budget(8);
        let (_server, client) = retirement_pair(budget.clone()).await;
        wait_for_permits(&budget, 0).await;
        let (retire, task) = run_retirable(client, shutdown(Duration::from_secs(30)));

        retire
            .send(tokio::time::Instant::now() + Duration::from_secs(10))
            .unwrap();
        let drain = timeout(Duration::from_secs(2), task)
            .await
            .expect("retirement finishes")
            .unwrap()
            .unwrap();

        assert_eq!(
            drain,
            Some(super::ConnectionDrain::Retirement(
                crate::WithdrawalOutcome::Confirmed
            ))
        );
        wait_for_permits(&budget, 8).await;
    }

    #[tokio::test]
    async fn the_retirement_deadline_closes_an_unconfirmed_connection() {
        let budget = budget(8);
        let (server, client) = retirement_pair(budget.clone()).await;
        // A committed Visitor that never sends its header keeps the connection from quiescing.
        let _visitor = server
            .open_tunnel_stream(Duration::from_secs(1))
            .await
            .unwrap();
        let (retire, task) = run_retirable(client, shutdown(Duration::from_secs(30)));

        let started = tokio::time::Instant::now();
        retire.send(started + Duration::from_millis(300)).unwrap();
        let drain = timeout(Duration::from_secs(2), task)
            .await
            .expect("deadline ends retirement")
            .unwrap()
            .unwrap();

        assert_eq!(
            drain,
            Some(super::ConnectionDrain::Retirement(
                crate::WithdrawalOutcome::Unconfirmed(crate::UnconfirmedDrain::Deadline)
            ))
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        timeout(Duration::from_secs(2), server.closed())
            .await
            .expect("connection closes");
    }

    #[tokio::test]
    async fn graceful_shutdown_joins_an_in_flight_retirement() {
        let budget = budget(8);
        let (server, client) = retirement_pair(budget.clone()).await;
        let visitor = server
            .open_tunnel_stream(Duration::from_secs(1))
            .await
            .unwrap();
        let shutdown = shutdown(Duration::from_secs(30));
        let (retire, task) = run_retirable(client, shutdown.clone());
        retire
            .send(tokio::time::Instant::now() + Duration::from_secs(30))
            .unwrap();
        timeout(Duration::from_secs(2), async {
            while server.accepts_visitors() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement withdrawal commits");

        let _ = shutdown.begin_graceful();
        // The one in-flight withdrawal serves both and confirms once the Visitor ends.
        drop(visitor);
        let drain = timeout(Duration::from_secs(2), task)
            .await
            .expect("joined drain finishes")
            .unwrap()
            .unwrap();

        assert_eq!(
            drain,
            Some(super::ConnectionDrain::Retirement(
                crate::WithdrawalOutcome::Confirmed
            ))
        );
        wait_for_permits(&budget, 8).await;
    }

    #[tokio::test]
    async fn a_shorter_shutdown_deadline_bounds_an_in_flight_retirement() {
        let budget = budget(8);
        let (server, client) = retirement_pair(budget.clone()).await;
        let _visitor = server
            .open_tunnel_stream(Duration::from_secs(1))
            .await
            .unwrap();
        let shutdown = shutdown(Duration::from_millis(200));
        let (retire, task) = run_retirable(client, shutdown.clone());
        retire
            .send(tokio::time::Instant::now() + Duration::from_secs(30))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = shutdown.begin_graceful();
        let drain = timeout(Duration::from_secs(2), task)
            .await
            .expect("shutdown deadline ends retirement")
            .unwrap()
            .unwrap();

        assert_eq!(
            drain,
            Some(super::ConnectionDrain::Retirement(
                crate::WithdrawalOutcome::Unconfirmed(crate::UnconfirmedDrain::Deadline)
            ))
        );
    }

    #[tokio::test]
    async fn fast_shutdown_closes_a_retiring_connection_at_once() {
        let budget = budget(8);
        let (server, client) = retirement_pair(budget.clone()).await;
        let _visitor = server
            .open_tunnel_stream(Duration::from_secs(1))
            .await
            .unwrap();
        let shutdown = shutdown(Duration::from_secs(30));
        let (retire, task) = run_retirable(client, shutdown.clone());
        retire
            .send(tokio::time::Instant::now() + Duration::from_secs(30))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = shutdown.begin_fast();
        let drain = timeout(Duration::from_secs(2), task)
            .await
            .expect("Fast ends retirement")
            .unwrap()
            .unwrap();

        assert_eq!(
            drain,
            Some(super::ConnectionDrain::Retirement(
                crate::WithdrawalOutcome::Unconfirmed(crate::UnconfirmedDrain::FastShutdown)
            ))
        );
    }

    #[tokio::test]
    async fn after_goaway_retirement_sends_no_withdrawal_and_leaves_closing_to_the_server() {
        let budget = budget(8);
        let (server, client) = retirement_pair(budget.clone()).await;
        let server = Arc::new(server);
        let visitor = server
            .open_tunnel_stream(Duration::from_secs(1))
            .await
            .unwrap();
        let draining = tokio::spawn({
            let server = Arc::clone(&server);
            async move { server.shutdown(Duration::from_secs(10)).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (retire, task) = run_retirable(client, shutdown(Duration::from_secs(30)));

        retire
            .send(tokio::time::Instant::now() + Duration::from_secs(30))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !task.is_finished(),
            "the connection stays open for the Server drain"
        );

        drop(visitor);
        let drain = timeout(Duration::from_secs(5), task)
            .await
            .expect("Server drain closes the connection")
            .unwrap()
            .unwrap();
        assert_eq!(
            drain,
            Some(super::ConnectionDrain::Retirement(
                crate::WithdrawalOutcome::Unconfirmed(crate::UnconfirmedDrain::RequestsForbidden)
            ))
        );
        draining.await.unwrap();
    }

    fn generate_test_client_identity() -> io::Result<GeneratedClientIdentity> {
        generate_client_identity().map_err(io::Error::other)
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn make_self_signed_cert(server_name: &str) -> io::Result<(CertificateDer<'static>, Vec<u8>)> {
        let certified_key =
            generate_simple_self_signed(vec![server_name.to_owned()]).map_err(io::Error::other)?;
        Ok((
            CertificateDer::from(certified_key.cert),
            certified_key.signing_key.serialize_der(),
        ))
    }

    fn private_key_from_der(der: &[u8]) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(der.to_vec()).into()
    }

    fn client_certificate_chain(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<Vec<CertificateDer<'static>>> {
        certificate_chain_from_pem(client_identity.certificate_pem.as_bytes())
            .map_err(io::Error::other)
    }

    fn client_private_key(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<PrivateKeyDer<'static>> {
        private_key_from_pem(client_identity.private_key_pem.as_bytes()).map_err(|source| {
            match source {
                PemError::NoItemsFound => {
                    io::Error::new(io::ErrorKind::InvalidData, "missing client private key")
                }
                other => io::Error::other(other),
            }
        })
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }
}
