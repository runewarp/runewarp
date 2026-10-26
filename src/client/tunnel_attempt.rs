//! One production **Tunnel connection** attempt for a Client **Server address**.
//!
//! DNS is the only internal seam: production uses the system resolver while deterministic
//! tests script results. Resolution order, material reload, QUIC establishment, connection-end
//! classification, and lifecycle reporting stay behind this module's interface.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures_util::future::BoxFuture;

use super::AddressWorkerDial;
use crate::{ClientInstancePrep, PreparedClient, ServerAddress};

/// Runs one authenticated Tunnel connection until remote close or process shutdown.
///
/// The argument is the Client-instance [`crate::OrderlyShutdown`]: Graceful withdraws the
/// connection under its shared deadline, and Fast closes it at once.
pub type TunnelConnectionRun = Box<
    dyn FnOnce(crate::OrderlyShutdown) -> BoxFuture<'static, Result<(), TunnelConnectionEnd>>
        + Send,
>;

/// Typed result of one production Tunnel-connection attempt.
pub enum TunnelAttemptOutcome {
    Connected {
        configured_server_addr: String,
        run: TunnelConnectionRun,
    },
    Retryable(TunnelAttemptFailure),
    FatalLocalMaterial(String),
}

/// Typed retryable attempt failure with its operator-reporting context.
pub struct TunnelAttemptFailure {
    kind: AttemptFailureKind,
    message: String,
}

enum AttemptFailureKind {
    Resolution(AttemptContext),
    Unauthorized(AttemptContext),
    Transport(AttemptContext, SocketAddr),
    Unclassified,
}

/// Typed end of an authenticated Tunnel connection.
pub struct TunnelConnectionEnd {
    kind: ConnectionEndKind,
    message: Option<String>,
}

enum ConnectionEndKind {
    Clean(ConnectionContext),
    Unauthorized(ConnectionContext),
    Transport(ConnectionContext),
    /// The Server violated the withdrawal contract during graceful shutdown.
    WithdrawalProtocolFailure,
    Unclassified,
}

#[derive(Clone)]
struct AttemptContext {
    phase: crate::runtime_log::ClientTunnelPhase,
    attempt_kind: crate::runtime_log::ClientTunnelAttemptKind,
    configured_server_addr: String,
}

#[derive(Clone)]
struct ConnectionContext {
    configured_server_addr: String,
    resolved_server_addr: SocketAddr,
}

impl TunnelAttemptFailure {
    pub fn unclassified(message: impl Into<String>) -> Self {
        Self {
            kind: AttemptFailureKind::Unclassified,
            message: message.into(),
        }
    }

    pub(crate) fn unclassified_message(&self) -> Option<&str> {
        matches!(self.kind, AttemptFailureKind::Unclassified).then_some(&self.message)
    }

    pub(crate) fn report_after_retry_delay(&self, delay_secs: u64) {
        match &self.kind {
            AttemptFailureKind::Resolution(context) => {
                crate::runtime_log::client_tunnel_resolution_failed(
                    context.phase,
                    context.attempt_kind,
                    &context.configured_server_addr,
                    delay_secs,
                    &self.message,
                );
            }
            AttemptFailureKind::Unauthorized(context) => {
                crate::runtime_log::client_tunnel_unauthorized(
                    context.attempt_kind,
                    &context.configured_server_addr,
                    delay_secs,
                    &self.message,
                );
            }
            AttemptFailureKind::Transport(context, resolved_server_addr) => {
                crate::runtime_log::client_tunnel_connect_failed(
                    context.phase,
                    context.attempt_kind,
                    &context.configured_server_addr,
                    *resolved_server_addr,
                    delay_secs,
                    &self.message,
                );
            }
            AttemptFailureKind::Unclassified => {}
        }
    }

    fn resolution(context: AttemptContext, message: String) -> Self {
        Self {
            kind: AttemptFailureKind::Resolution(context),
            message,
        }
    }

    fn unauthorized(context: AttemptContext, message: String) -> Self {
        Self {
            kind: AttemptFailureKind::Unauthorized(context),
            message,
        }
    }

    fn transport(
        context: AttemptContext,
        resolved_server_addr: SocketAddr,
        message: String,
    ) -> Self {
        Self {
            kind: AttemptFailureKind::Transport(context, resolved_server_addr),
            message,
        }
    }
}

impl TunnelConnectionEnd {
    pub fn unclassified(message: impl Into<String>) -> Self {
        Self {
            kind: ConnectionEndKind::Unclassified,
            message: Some(message.into()),
        }
    }

    pub(crate) fn unclassified_message(&self) -> Option<&str> {
        matches!(self.kind, ConnectionEndKind::Unclassified)
            .then_some(self.message.as_deref())
            .flatten()
    }

    /// A withdrawal protocol failure, which becomes the process error after teardown.
    pub fn withdrawal_protocol_failure(message: impl Into<String>) -> Self {
        Self {
            kind: ConnectionEndKind::WithdrawalProtocolFailure,
            message: Some(message.into()),
        }
    }

    pub(crate) fn withdrawal_protocol_failure_message(&self) -> Option<&str> {
        matches!(self.kind, ConnectionEndKind::WithdrawalProtocolFailure)
            .then_some(self.message.as_deref())
            .flatten()
    }

    pub(crate) fn report_after_retry_delay(&self, delay_secs: u64) {
        match &self.kind {
            ConnectionEndKind::Clean(context) => {
                crate::runtime_log::client_tunnel_closed(
                    &context.configured_server_addr,
                    context.resolved_server_addr,
                    delay_secs,
                );
            }
            ConnectionEndKind::Unauthorized(context) => {
                crate::runtime_log::client_tunnel_unauthorized(
                    crate::runtime_log::ClientTunnelAttemptKind::Initial,
                    &context.configured_server_addr,
                    delay_secs,
                    self.message.as_deref().unwrap_or_default(),
                );
            }
            ConnectionEndKind::Transport(context) => {
                crate::runtime_log::client_tunnel_disconnected(
                    &context.configured_server_addr,
                    context.resolved_server_addr,
                    delay_secs,
                    self.message.as_deref().unwrap_or_default(),
                );
            }
            ConnectionEndKind::WithdrawalProtocolFailure | ConnectionEndKind::Unclassified => {}
        }
    }
}

trait TunnelResolver: Send + Sync {
    fn resolve(&self, address: ServerAddress) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>>;
}

struct SystemTunnelResolver;

impl TunnelResolver for SystemTunnelResolver {
    fn resolve(&self, address: ServerAddress) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            tokio::net::lookup_host((address.hostname().as_str(), address.port()))
                .await
                .map(|addresses| addresses.collect())
        })
    }
}

/// Reusable production attempt for one Client **Server address** worker.
pub struct ClientTunnelAttempt {
    settings: Arc<crate::ClientConfig>,
    instance: Arc<ClientInstancePrep>,
    local_bind_addr: SocketAddr,
    resolver: Arc<dyn TunnelResolver>,
    connected_once: Arc<AtomicBool>,
    establish_attempts: Arc<AtomicUsize>,
}

impl ClientTunnelAttempt {
    pub fn new(
        settings: Arc<crate::ClientConfig>,
        instance: Arc<ClientInstancePrep>,
        local_bind_addr: SocketAddr,
    ) -> Self {
        Self::with_resolver(
            settings,
            instance,
            local_bind_addr,
            Arc::new(SystemTunnelResolver),
        )
    }

    fn with_resolver(
        settings: Arc<crate::ClientConfig>,
        instance: Arc<ClientInstancePrep>,
        local_bind_addr: SocketAddr,
        resolver: Arc<dyn TunnelResolver>,
    ) -> Self {
        Self {
            settings,
            instance,
            local_bind_addr,
            resolver,
            connected_once: Arc::new(AtomicBool::new(false)),
            establish_attempts: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AddressWorkerDial for ClientTunnelAttempt {
    fn establish(&self, address: ServerAddress) -> BoxFuture<'static, TunnelAttemptOutcome> {
        let settings = Arc::clone(&self.settings);
        let instance = Arc::clone(&self.instance);
        let local_bind_addr = self.local_bind_addr;
        let resolver = Arc::clone(&self.resolver);
        let connected_once = Arc::clone(&self.connected_once);
        let establish_attempts = Arc::clone(&self.establish_attempts);
        Box::pin(async move {
            let phase = client_tunnel_phase(connected_once.load(Ordering::SeqCst));
            let attempt_number = establish_attempts.fetch_add(1, Ordering::SeqCst);
            let attempt_kind = client_tunnel_attempt_kind(attempt_number == 0);
            let configured_server_addr =
                configured_server_addr(address.hostname().as_str(), address.port());
            let unresolved_context = AttemptContext {
                phase,
                attempt_kind,
                configured_server_addr: configured_server_addr.clone(),
            };

            let resolved_server_addr = match resolve_first(resolver.as_ref(), address.clone()).await
            {
                Ok(resolved_server_addr) => resolved_server_addr,
                Err(error) => {
                    let message = error.to_string();
                    return TunnelAttemptOutcome::Retryable(TunnelAttemptFailure::resolution(
                        unresolved_context,
                        message,
                    ));
                }
            };
            let context = AttemptContext {
                phase,
                attempt_kind,
                configured_server_addr: configured_server_addr.clone(),
            };

            crate::runtime_log::client_tunnel_connecting(
                phase,
                attempt_kind,
                &configured_server_addr,
                resolved_server_addr,
            );
            let client = match PreparedClient::connect_to_server_address(
                &settings,
                &instance,
                local_bind_addr,
                &address,
                resolved_server_addr,
            )
            .await
            {
                Ok(client) => client,
                Err(error) => {
                    return classify_connect_failure(error, context, resolved_server_addr);
                }
            };

            connected_once.store(true, Ordering::SeqCst);
            establish_attempts.store(0, Ordering::SeqCst);
            crate::runtime_log::client_tunnel_connected(
                phase,
                &configured_server_addr,
                resolved_server_addr,
            );
            let connection_context = ConnectionContext {
                configured_server_addr: configured_server_addr.clone(),
                resolved_server_addr,
            };
            TunnelAttemptOutcome::Connected {
                configured_server_addr: configured_server_addr.clone(),
                run: Box::new(move |shutdown| {
                    Box::pin(async move {
                        match client.run_with_shutdown(&shutdown).await {
                            Ok(withdrawal) => report_withdrawal(withdrawal, &connection_context),
                            Err(error) => {
                                let message = error.to_string();
                                Err(classify_connection_end(error, connection_context, message))
                            }
                        }
                    })
                }),
            }
        })
    }
}

/// Report how graceful withdrawal ended. Only a protocol failure fails the process.
fn report_withdrawal(
    withdrawal: Option<crate::WithdrawalOutcome>,
    context: &ConnectionContext,
) -> Result<(), TunnelConnectionEnd> {
    use crate::WithdrawalOutcome;
    let address = &context.configured_server_addr;
    match withdrawal {
        None => Ok(()),
        Some(WithdrawalOutcome::Confirmed) => {
            crate::runtime_log::client_tunnel_withdrawal_confirmed(address);
            Ok(())
        }
        Some(WithdrawalOutcome::Unconfirmed(reason)) => {
            crate::runtime_log::client_tunnel_withdrawal_unconfirmed(address, reason);
            Ok(())
        }
        Some(WithdrawalOutcome::ProtocolFailure(failure)) => {
            crate::runtime_log::client_tunnel_withdrawal_failed(address, failure);
            Err(TunnelConnectionEnd::withdrawal_protocol_failure(format!(
                "tunnel placement withdrawal failed for {address}: {failure}"
            )))
        }
    }
}

async fn resolve_first(
    resolver: &dyn TunnelResolver,
    address: ServerAddress,
) -> Result<SocketAddr, crate::ClientStartupError> {
    let server_hostname = address.hostname().to_string();
    resolver
        .resolve(address)
        .await
        .map_err(crate::ClientStartupError::Resolve)?
        .into_iter()
        .next()
        .ok_or(crate::ClientStartupError::MissingServerAddress { server_hostname })
}

fn client_tunnel_phase(connected_once: bool) -> crate::runtime_log::ClientTunnelPhase {
    if connected_once {
        crate::runtime_log::ClientTunnelPhase::Reconnecting
    } else {
        crate::runtime_log::ClientTunnelPhase::Establishing
    }
}

fn client_tunnel_attempt_kind(
    is_fresh_attempt: bool,
) -> crate::runtime_log::ClientTunnelAttemptKind {
    if is_fresh_attempt {
        crate::runtime_log::ClientTunnelAttemptKind::Initial
    } else {
        crate::runtime_log::ClientTunnelAttemptKind::Retry
    }
}

fn configured_server_addr(server_hostname: &str, server_port: u16) -> String {
    if server_hostname.contains(':') && !server_hostname.starts_with('[') {
        format!("[{server_hostname}]:{server_port}")
    } else {
        format!("{server_hostname}:{server_port}")
    }
}

fn is_unauthorized_client_connection_error(error: &quinn::ConnectionError) -> bool {
    super::is_tls_access_denied(error)
}

fn is_clean_client_tunnel_close(error: &quinn::ConnectionError) -> bool {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => close.error_code.into_inner() == 0x100,
        quinn::ConnectionError::ConnectionClosed(close) => {
            close.error_code == quinn::TransportErrorCode::NO_ERROR
        }
        _ => false,
    }
}

fn classify_connect_failure(
    error: crate::ClientStartupError,
    context: AttemptContext,
    resolved_server_addr: SocketAddr,
) -> TunnelAttemptOutcome {
    let crate::ClientStartupError::Connect(connect_error) = error else {
        return TunnelAttemptOutcome::FatalLocalMaterial(error.to_string());
    };
    let unauthorized = connect_error.is_unauthorized_client_identity();
    let message = connect_error.to_string();
    TunnelAttemptOutcome::Retryable(if unauthorized {
        TunnelAttemptFailure::unauthorized(context, message)
    } else {
        TunnelAttemptFailure::transport(context, resolved_server_addr, message)
    })
}

fn classify_connection_end(
    error: quinn::ConnectionError,
    context: ConnectionContext,
    message: String,
) -> TunnelConnectionEnd {
    if is_unauthorized_client_connection_error(&error) {
        TunnelConnectionEnd {
            kind: ConnectionEndKind::Unauthorized(context),
            message: Some(message),
        }
    } else if is_clean_client_tunnel_close(&error) {
        TunnelConnectionEnd {
            kind: ConnectionEndKind::Clean(context),
            message: None,
        }
    } else {
        TunnelConnectionEnd {
            kind: ConnectionEndKind::Transport(context),
            message: Some(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn attempt_context() -> AttemptContext {
        AttemptContext {
            phase: crate::runtime_log::ClientTunnelPhase::Establishing,
            attempt_kind: crate::runtime_log::ClientTunnelAttemptKind::Initial,
            configured_server_addr: "tunnel.example.test:443".to_owned(),
        }
    }

    fn connection_context() -> ConnectionContext {
        ConnectionContext {
            configured_server_addr: "tunnel.example.test:443".to_owned(),
            resolved_server_addr: "127.0.0.1:443".parse().unwrap(),
        }
    }

    struct ScriptedResolver {
        results: Mutex<VecDeque<io::Result<Vec<SocketAddr>>>>,
    }

    impl TunnelResolver for ScriptedResolver {
        fn resolve(
            &self,
            _address: ServerAddress,
        ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
            let result = self.results.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn resolution_preserves_the_resolvers_first_address() {
        let ipv6 = "[::1]:443".parse().unwrap();
        let ipv4 = "127.0.0.1:443".parse().unwrap();
        let resolver = ScriptedResolver {
            results: Mutex::new(VecDeque::from([Ok(vec![ipv6, ipv4])])),
        };

        let resolved = resolve_first(
            &resolver,
            ServerAddress::parse("tunnel.example.test").unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(resolved, ipv6);
    }

    #[tokio::test]
    async fn resolution_accepts_a_single_ipv4_address() {
        let ipv4 = "127.0.0.1:443".parse().unwrap();
        let resolver = ScriptedResolver {
            results: Mutex::new(VecDeque::from([Ok(vec![ipv4])])),
        };

        assert_eq!(
            resolve_first(
                &resolver,
                ServerAddress::parse("tunnel.example.test").unwrap(),
            )
            .await
            .unwrap(),
            ipv4
        );
    }

    #[tokio::test]
    async fn resolution_accepts_a_single_ipv6_address() {
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();
        let resolver = ScriptedResolver {
            results: Mutex::new(VecDeque::from([Ok(vec![ipv6])])),
        };

        assert_eq!(
            resolve_first(
                &resolver,
                ServerAddress::parse("tunnel.example.test").unwrap(),
            )
            .await
            .unwrap(),
            ipv6
        );
    }

    #[tokio::test]
    async fn resolution_preserves_ipv4_before_ipv6_order() {
        let ipv4 = "127.0.0.1:443".parse().unwrap();
        let ipv6 = "[::1]:443".parse().unwrap();
        let resolver = ScriptedResolver {
            results: Mutex::new(VecDeque::from([Ok(vec![ipv4, ipv6])])),
        };

        assert_eq!(
            resolve_first(
                &resolver,
                ServerAddress::parse("tunnel.example.test").unwrap(),
            )
            .await
            .unwrap(),
            ipv4
        );
    }

    #[tokio::test]
    async fn empty_resolution_is_retryable() {
        let resolver = ScriptedResolver {
            results: Mutex::new(VecDeque::from([Ok(Vec::new())])),
        };

        let error = resolve_first(
            &resolver,
            ServerAddress::parse("tunnel.example.test").unwrap(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            crate::ClientStartupError::MissingServerAddress { .. }
        ));
    }

    #[tokio::test]
    async fn every_retry_resolves_again() {
        let first = "127.0.0.1:443".parse().unwrap();
        let second = "127.0.0.2:443".parse().unwrap();
        let resolver = ScriptedResolver {
            results: Mutex::new(VecDeque::from([Ok(vec![first]), Ok(vec![second])])),
        };
        let address = ServerAddress::parse("tunnel.example.test").unwrap();

        assert_eq!(
            resolve_first(&resolver, address.clone()).await.unwrap(),
            first
        );
        assert_eq!(resolve_first(&resolver, address).await.unwrap(), second);
    }

    #[tokio::test]
    async fn cancelling_resolution_drops_the_dns_future() {
        struct HangingResolver(Arc<AtomicBool>);
        struct DropGuard(Arc<AtomicBool>);

        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        impl TunnelResolver for HangingResolver {
            fn resolve(
                &self,
                _address: ServerAddress,
            ) -> BoxFuture<'static, io::Result<Vec<SocketAddr>>> {
                let dropped = Arc::clone(&self.0);
                Box::pin(async move {
                    let _guard = DropGuard(dropped);
                    std::future::pending().await
                })
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let resolver: Arc<dyn TunnelResolver> = Arc::new(HangingResolver(Arc::clone(&dropped)));
        let task = tokio::spawn(async move {
            resolve_first(
                resolver.as_ref(),
                ServerAddress::parse("tunnel.example.test").unwrap(),
            )
            .await
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn unauthorized_failure_has_a_typed_outcome() {
        let outcome = TunnelAttemptOutcome::Retryable(TunnelAttemptFailure::unauthorized(
            attempt_context(),
            "access denied".to_owned(),
        ));
        assert!(matches!(
            outcome,
            TunnelAttemptOutcome::Retryable(TunnelAttemptFailure {
                kind: AttemptFailureKind::Unauthorized(_),
                ..
            })
        ));
    }

    #[test]
    fn transient_handshake_is_a_typed_transport_failure() {
        let error = crate::ClientStartupError::Connect(crate::ClientConnectError::Handshake(
            quinn::ConnectionError::TimedOut,
        ));

        let outcome =
            classify_connect_failure(error, attempt_context(), "127.0.0.1:443".parse().unwrap());

        assert!(matches!(
            outcome,
            TunnelAttemptOutcome::Retryable(TunnelAttemptFailure {
                kind: AttemptFailureKind::Transport(_, _),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn incompatible_h3_peer_fails_the_attempt_without_offering_visitor_credit() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            use rustls::pki_types::pem::PemObject;
            let directory = tempfile::tempdir().unwrap();
            let identity = crate::generate_client_identity().unwrap();
            let certificate =
                rcgen::generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
            std::fs::write(directory.path().join("ca.pem"), certificate.cert.pem()).unwrap();
            std::fs::write(
                directory.path().join("client.crt"),
                &identity.certificate_pem,
            )
            .unwrap();
            std::fs::write(
                directory.path().join("client.key"),
                &identity.private_key_pem,
            )
            .unwrap();
            std::fs::write(
                directory.path().join("client-identity.txt"),
                identity.client_identity.to_string(),
            )
            .unwrap();
            std::fs::write(
                directory.path().join("config.toml"),
                r#"
[client]
server-address = "tunnel.example.test"
server-trust = "ca-file"
server-ca-file = "ca.pem"
identity-dir = "."
[[client.services]]
backend-address = "127.0.0.1:443"
"#,
            )
            .unwrap();
            let settings =
                Arc::new(crate::load_client_config(&directory.path().join("config.toml")).unwrap());
            let endpoint = quinn::Endpoint::server(
                crate::tunnel_h3::test_support::test_server_h3_config(
                    vec![rustls::pki_types::CertificateDer::from(certificate.cert)],
                    rustls::pki_types::PrivateKeyDer::from_pem_slice(
                        certificate.signing_key.serialize_pem().as_bytes(),
                    )
                    .unwrap(),
                    &[identity.client_identity],
                )
                .unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let target = endpoint.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let mut server = h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .unwrap();
                let (request, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.method(), http::Method::GET);
                assert_eq!(request.uri().path(), "/v1/tunnel/events");
                stream
                    .send_response(
                        http::Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let state = concat!(
                    "event: state\n",
                    "data: {\"version\":2,",
                    "\"generation\":\"0123456789abcdef0123456789abcdef\"}\n\n",
                );
                stream
                    .send_data(bytes::Bytes::from_static(state.as_bytes()))
                    .await
                    .unwrap();
                // The incompatible state must close the connection, before session establishment or Visitor credit.
                assert!(server.accept().await.unwrap_or(None).is_none());
            });
            let instance = ClientInstancePrep::prepare(&settings).await.unwrap();
            let dial = ClientTunnelAttempt::with_resolver(
                settings,
                instance,
                "127.0.0.1:0".parse().unwrap(),
                Arc::new(ScriptedResolver {
                    results: Mutex::new(VecDeque::from([Ok(vec![target])])),
                }),
            );
            let outcome = dial
                .establish(ServerAddress::parse("tunnel.example.test").unwrap())
                .await;
            assert!(matches!(
                outcome,
                TunnelAttemptOutcome::Retryable(TunnelAttemptFailure {
                    kind: AttemptFailureKind::Transport(_, _),
                    ..
                })
            ));
            peer.await.unwrap();
        })
        .await
        .expect("incompatible attempt finishes promptly");
    }

    #[test]
    fn local_material_failure_is_fatal() {
        let outcome = classify_connect_failure(
            crate::ClientStartupError::InvalidSettings("invalid material".to_owned()),
            attempt_context(),
            "127.0.0.1:443".parse().unwrap(),
        );

        assert!(matches!(
            outcome,
            TunnelAttemptOutcome::FatalLocalMaterial(message) if message == "invalid material"
        ));
    }

    #[test]
    fn h3_no_error_application_close_is_clean() {
        let error = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(0x100),
            reason: bytes::Bytes::new(),
        });

        let end = classify_connection_end(error, connection_context(), "closed".to_owned());

        assert!(matches!(end.kind, ConnectionEndKind::Clean(_)));
    }

    #[test]
    fn other_application_close_is_transport_failure() {
        let error = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(1),
            reason: bytes::Bytes::from_static(b"failed"),
        });

        let end = classify_connection_end(error, connection_context(), "failed".to_owned());

        assert!(matches!(end.kind, ConnectionEndKind::Transport(_)));
    }
}
