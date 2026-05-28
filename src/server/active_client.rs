use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use quinn::Connection;
use tokio::sync::RwLock;

use crate::{ClientIdentity, runtime_log};

#[derive(Clone)]
struct ActiveClientInstance {
    generation: u64,
    connection: Connection,
}

#[derive(Clone)]
pub(crate) struct ActiveClientSlot {
    active_client: Arc<RwLock<Option<ActiveClientInstance>>>,
    next_generation: Arc<AtomicU64>,
}

impl ActiveClientSlot {
    pub(crate) fn new() -> Self {
        Self {
            active_client: Arc::new(RwLock::new(None)),
            next_generation: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) async fn current_connection(&self) -> Option<Connection> {
        self.active_client
            .read()
            .await
            .as_ref()
            .map(|active_client| active_client.connection.clone())
    }

    pub(crate) async fn register(&self, connection: Connection, client_identity: ClientIdentity) {
        let remote_addr = connection.remote_address();
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let (installed, previous) = {
            let mut active_client = self.active_client.write().await;
            let current_generation = active_client.as_ref().map(|active| active.generation);
            if !incoming_generation_supersedes(current_generation, generation) {
                (false, None)
            } else {
                (
                    true,
                    active_client.replace(ActiveClientInstance {
                        generation,
                        connection: connection.clone(),
                    }),
                )
            }
        };
        if !installed {
            connection.close(0_u32.into(), b"replaced");
            return;
        }

        if let Some(previous) = previous {
            runtime_log::server_tunnel_connection_replaced(
                &client_identity,
                remote_addr,
                previous.connection.remote_address(),
            );
            previous.connection.close(0_u32.into(), b"replaced");
        } else {
            runtime_log::server_tunnel_connection_accepted(&client_identity, remote_addr);
        }

        let active_client = self.active_client.clone();
        let client_identity_for_close = client_identity.clone();
        tokio::spawn(async move {
            let close_error = connection.closed().await;
            runtime_log::server_tunnel_connection_terminated(
                &client_identity_for_close,
                remote_addr,
                &close_error,
            );
            let mut active_client_guard = active_client.write().await;
            if active_client_guard
                .as_ref()
                .is_some_and(|active| active.generation == generation)
            {
                *active_client_guard = None;
            }
        });
    }

    pub(crate) async fn close_active_connection(&self, reason: &'static [u8]) -> bool {
        let Some(connection) = self.current_connection().await else {
            return false;
        };
        connection.close(0_u32.into(), reason);
        true
    }
}

fn incoming_generation_supersedes(
    current_generation: Option<u64>,
    incoming_generation: u64,
) -> bool {
    current_generation.is_none_or(|current_generation| incoming_generation > current_generation)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Write};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::time::{Duration, timeout};
    use tracing_subscriber::fmt::writer::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{ActiveClientSlot, incoming_generation_supersedes};
    use crate::{
        GeneratedClientIdentity, generate_client_identity,
        make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    };

    #[test]
    fn newer_generations_supersede_older_active_connections() {
        assert!(incoming_generation_supersedes(None, 1));
        assert!(incoming_generation_supersedes(Some(1), 2));
    }

    #[test]
    fn stale_generations_do_not_replace_newer_active_connections() {
        assert!(!incoming_generation_supersedes(Some(2), 1));
        assert!(!incoming_generation_supersedes(Some(2), 2));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registers_an_active_tunnel_connection_and_logs_acceptance() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let slot = ActiveClientSlot::new();
        let remote_addr = fixture.server_connection.remote_address();
        let expected_log = format!(
            "server tunnel connection accepted: client-identity={} remote-address={remote_addr}",
            client_identity.client_identity
        );
        let slot_for_registration = slot.clone();
        let expected_log_for_wait = expected_log.clone();

        let output = capture_logs(|buffer| async move {
            slot_for_registration
                .register(
                    fixture.server_connection.clone(),
                    client_identity.client_identity.clone(),
                )
                .await;
            wait_for_log(&buffer, expected_log_for_wait.as_str()).await;
        })
        .await;

        assert!(output.contains(&expected_log));
        assert!(slot.current_connection().await.is_some());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replaces_and_clears_active_tunnel_connections_with_lifecycle_logs() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let first_fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let slot = ActiveClientSlot::new();
        let first_remote_addr = first_fixture.server_connection.remote_address();
        let second_remote_addr = second_fixture.server_connection.remote_address();
        let expected_replacement_log = format!(
            "server tunnel connection replaced: client-identity={} remote-address={second_remote_addr} previous-remote-address={first_remote_addr}",
            client_identity.client_identity
        );
        let expected_closed_log = format!(
            "server tunnel connection closed: client-identity={} remote-address={second_remote_addr}",
            client_identity.client_identity
        );
        let slot_for_registration = slot.clone();
        let client_identity_for_registration = client_identity.client_identity.clone();
        let expected_replacement_log_for_wait = expected_replacement_log.clone();
        let expected_closed_log_for_wait = expected_closed_log.clone();

        let output = capture_logs(|buffer| async move {
            slot_for_registration
                .register(
                    first_fixture.server_connection.clone(),
                    client_identity_for_registration.clone(),
                )
                .await;
            slot_for_registration
                .register(
                    second_fixture.server_connection.clone(),
                    client_identity_for_registration,
                )
                .await;
            wait_for_log(&buffer, expected_replacement_log_for_wait.as_str()).await;

            second_fixture
                .client_connection
                .close(0_u32.into(), b"test complete");
            wait_for_log(&buffer, expected_closed_log_for_wait.as_str()).await;
        })
        .await;

        assert!(output.contains(&expected_replacement_log));
        assert!(output.contains(&expected_closed_log));
        assert!(slot.current_connection().await.is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closes_the_active_tunnel_connection_and_clears_the_slot() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let slot = ActiveClientSlot::new();
        let remote_addr = fixture.server_connection.remote_address();
        let expected_closed_log = format!(
            "server tunnel connection closed: client-identity={} remote-address={remote_addr}",
            client_identity.client_identity
        );
        let slot_for_registration = slot.clone();
        let client_identity_for_registration = client_identity.client_identity.clone();
        let expected_closed_log_for_wait = expected_closed_log.clone();

        let output = capture_logs(|buffer| async move {
            slot_for_registration
                .register(
                    fixture.server_connection.clone(),
                    client_identity_for_registration,
                )
                .await;
            assert!(
                slot_for_registration
                    .close_active_connection(b"graceful shutdown")
                    .await
            );
            wait_for_log(&buffer, expected_closed_log_for_wait.as_str()).await;
        })
        .await;

        assert!(output.contains(&expected_closed_log));
        assert!(slot.current_connection().await.is_none());
        Ok(())
    }

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(SharedBuffer);

    impl SharedBuffer {
        fn read(&self) -> String {
            String::from_utf8(self.0.lock().expect("buffer mutex poisoned").clone())
                .expect("runtime log output must be valid UTF-8")
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .0
                .lock()
                .expect("buffer mutex poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedBuffer {
        type Writer = BufferWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            BufferWriter(self.clone())
        }
    }

    async fn capture_logs<F, Fut>(action: F) -> String
    where
        F: FnOnce(SharedBuffer) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(buffer.clone())
                .with_ansi(false)
                .without_time()
                .with_target(false),
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        action(buffer.clone()).await;
        buffer.read()
    }

    async fn wait_for_log(buffer: &SharedBuffer, needle: &str) {
        timeout(Duration::from_secs(1), async {
            loop {
                if buffer.read().contains(needle) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expected log line to be emitted within timeout");
    }

    struct TunnelConnectionFixture {
        _server_endpoint: Endpoint,
        _client_endpoint: Endpoint,
        #[allow(dead_code)]
        client_connection: Connection,
        server_connection: Connection,
    }

    impl TunnelConnectionFixture {
        async fn connect(client_identity: &GeneratedClientIdentity) -> io::Result<Self> {
            let (certificate, private_key) = make_self_signed_cert("tunnel.example.test")?;
            let server_endpoint = Endpoint::server(
                make_server_quic_config_with_client_auth(
                    vec![certificate.clone()],
                    private_key_from_der(&private_key),
                    std::slice::from_ref(&client_identity.client_identity),
                )
                .map_err(io::Error::other)?,
                localhost(0),
            )
            .map_err(io::Error::other)?;
            let server_addr = server_endpoint.local_addr()?;

            let mut client_endpoint = Endpoint::client(localhost(0)).map_err(io::Error::other)?;
            client_endpoint.set_default_client_config(
                make_client_quic_config_with_client_auth(
                    root_store_with(&certificate)?,
                    client_certificate_chain(client_identity)?,
                    client_private_key(client_identity)?,
                )
                .map_err(io::Error::other)?,
            );

            let accept_connection = async {
                let incoming = timeout(Duration::from_secs(1), server_endpoint.accept())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "accept timed out"))?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "server endpoint closed")
                    })?;
                timeout(Duration::from_secs(1), incoming)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
                    .map_err(io::Error::other)
            };
            let connect_client = async {
                let connect = client_endpoint
                    .connect(server_addr, "tunnel.example.test")
                    .map_err(io::Error::other)?;
                timeout(Duration::from_secs(1), connect)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
                    .map_err(io::Error::other)
            };
            let (server_connection, client_connection) =
                tokio::try_join!(accept_connection, connect_client)?;

            Ok(Self {
                _server_endpoint: server_endpoint,
                _client_endpoint: client_endpoint,
                client_connection,
                server_connection,
            })
        }
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
        rustls_pemfile::certs(&mut Cursor::new(client_identity.certificate_pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)
    }

    fn client_private_key(
        client_identity: &GeneratedClientIdentity,
    ) -> io::Result<PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut Cursor::new(client_identity.private_key_pem.as_bytes()))
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing client private key"))
    }

    fn root_store_with(certificate: &CertificateDer<'static>) -> io::Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(io::Error::other)?;
        Ok(roots)
    }
}
