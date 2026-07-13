use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use quinn::Connection;
use tokio::sync::RwLock;

use crate::{ClientIdentity, runtime_log};

#[derive(Clone)]
struct PoolMember {
    member_id: u64,
    client_identity: ClientIdentity,
    connection: Connection,
    active_streams: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub(crate) struct SelectedTunnelConnection {
    member_id: u64,
    client_identity: ClientIdentity,
    connection: Connection,
    active_streams: Arc<AtomicUsize>,
}

impl SelectedTunnelConnection {
    pub(crate) fn connection(&self) -> Connection {
        self.connection.clone()
    }

    pub(crate) fn member_id(&self) -> u64 {
        self.member_id
    }

    pub(crate) fn client_identity(&self) -> &ClientIdentity {
        &self.client_identity
    }

    pub(crate) fn record_open_stream(&self) -> ActiveStreamGuard {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        ActiveStreamGuard {
            active_streams: self.active_streams.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn active_stream_count(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }
}

pub(crate) struct ActiveStreamGuard {
    active_streams: Arc<AtomicUsize>,
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub(crate) struct ActiveClientPool {
    members: Arc<RwLock<Vec<PoolMember>>>,
    next_member_id: Arc<AtomicU64>,
    next_round_robin_offset: Arc<AtomicU64>,
}

/// A pool member detached from its previous Tunnel pool without closing the connection.
pub(crate) struct TakenPoolMember {
    pub(crate) client_identity: ClientIdentity,
    connection: Connection,
    active_streams: Arc<AtomicUsize>,
}

impl ActiveClientPool {
    pub(crate) fn new() -> Self {
        Self {
            members: Arc::new(RwLock::new(Vec::new())),
            next_member_id: Arc::new(AtomicU64::new(1)),
            next_round_robin_offset: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) async fn select_connection(&self) -> Option<SelectedTunnelConnection> {
        let members = self.members.read().await.clone();
        let len = members.len();
        if len == 0 {
            return None;
        }

        let lowest_active_streams = members
            .iter()
            .map(|member| member.active_streams.load(Ordering::Relaxed))
            .min()
            .expect("members length checked above");
        let start = (self.next_round_robin_offset.fetch_add(1, Ordering::Relaxed) as usize) % len;

        (0..len)
            .map(|offset| (start + offset) % len)
            .find_map(|index| {
                let member = &members[index];
                (member.active_streams.load(Ordering::Relaxed) == lowest_active_streams).then(
                    || SelectedTunnelConnection {
                        member_id: member.member_id,
                        client_identity: member.client_identity.clone(),
                        connection: member.connection.clone(),
                        active_streams: member.active_streams.clone(),
                    },
                )
            })
    }

    pub(crate) async fn register(&self, connection: Connection, client_identity: ClientIdentity) {
        let member_id = self.next_member_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut members = self.members.write().await;
            members.push(PoolMember {
                member_id,
                client_identity: client_identity.clone(),
                connection: connection.clone(),
                active_streams: Arc::new(AtomicUsize::new(0)),
            });
        }
        runtime_log::server_tunnel_connection_accepted(&client_identity);

        let members = self.members.clone();
        let client_identity_for_close = client_identity.clone();
        tokio::spawn(async move {
            let close_error = connection.closed().await;
            runtime_log::server_tunnel_connection_terminated(
                &client_identity_for_close,
                &close_error,
            );
            let mut members_guard = members.write().await;
            members_guard.retain(|member| member.member_id != member_id);
        });
    }

    pub(crate) async fn close_all_connections(&self, reason: &'static [u8]) -> usize {
        let members = self.members.read().await.clone();
        for member in &members {
            member.connection.close(0_u32.into(), reason);
        }
        members.len()
    }

    pub(crate) async fn close_connections_for_identities(
        &self,
        identities: &std::collections::HashSet<ClientIdentity>,
        reason: &'static [u8],
    ) -> usize {
        let members = self.members.read().await.clone();
        let mut closed = 0;
        for member in &members {
            if identities.contains(&member.client_identity) {
                member.connection.close(0_u32.into(), reason);
                closed += 1;
            }
        }
        closed
    }

    /// Remove every live member without closing their connections.
    ///
    /// Used when Tunnel indices change across an authorization commit so
    /// surviving connections can be adopted into the pool that matches their
    /// Client identity under the new snapshot.
    pub(crate) async fn take_members(&self) -> Vec<TakenPoolMember> {
        let members = std::mem::take(&mut *self.members.write().await);
        members
            .into_iter()
            .map(|member| TakenPoolMember {
                client_identity: member.client_identity,
                connection: member.connection,
                active_streams: member.active_streams,
            })
            .collect()
    }

    /// Place a previously taken member into this pool and watch it for close.
    ///
    /// Allocates a fresh `member_id` in this pool so a close watcher from the
    /// member's previous pool cannot remove an unrelated connection that
    /// happened to share the same per-pool id.
    pub(crate) async fn adopt_member(&self, member: TakenPoolMember) {
        let TakenPoolMember {
            client_identity,
            connection,
            active_streams,
        } = member;
        let member_id = self.next_member_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut members = self.members.write().await;
            members.push(PoolMember {
                member_id,
                client_identity: client_identity.clone(),
                connection: connection.clone(),
                active_streams,
            });
        }

        let members = self.members.clone();
        let client_identity_for_close = client_identity;
        tokio::spawn(async move {
            let close_error = connection.closed().await;
            runtime_log::server_tunnel_connection_terminated(
                &client_identity_for_close,
                &close_error,
            );
            let mut members_guard = members.write().await;
            members_guard.retain(|member| member.member_id != member_id);
        });
    }

    #[cfg(test)]
    pub(crate) async fn retained_client_identities(&self) -> Vec<ClientIdentity> {
        self.members
            .read()
            .await
            .iter()
            .map(|member| member.client_identity.clone())
            .collect()
    }

    pub(crate) async fn connection_count(&self) -> usize {
        self.members.read().await.len()
    }

    pub(crate) async fn active_stream_count(&self) -> usize {
        self.members
            .read()
            .await
            .iter()
            .map(|member| member.active_streams.load(Ordering::Relaxed))
            .sum()
    }
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

    use super::ActiveClientPool;
    use crate::{
        GeneratedClientIdentity, generate_client_identity,
        make_client_quic_config_with_client_auth, make_server_quic_config_with_client_auth,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn closes_only_connections_matching_client_identities() -> io::Result<()> {
        let first_identity = generate_test_client_identity()?;
        let second_identity = generate_test_client_identity()?;
        let first_fixture = TunnelConnectionFixture::connect(&first_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&second_identity).await?;
        let pool = ActiveClientPool::new();
        pool.register(
            first_fixture.server_connection.clone(),
            first_identity.client_identity.clone(),
        )
        .await;
        pool.register(
            second_fixture.server_connection.clone(),
            second_identity.client_identity.clone(),
        )
        .await;

        let mut revoke = std::collections::HashSet::new();
        revoke.insert(first_identity.client_identity.clone());
        assert_eq!(
            pool.close_connections_for_identities(&revoke, b"authorization revoked")
                .await,
            1
        );

        timeout(
            Duration::from_secs(1),
            first_fixture.server_connection.closed(),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "revoked connection should close"))?;
        timeout(Duration::from_secs(1), async {
            loop {
                if pool.connection_count().await == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "revoked pool member should be removed after close",
            )
        })?;
        assert_eq!(
            pool.retained_client_identities().await,
            vec![second_identity.client_identity.clone()]
        );
        assert_eq!(pool.connection_count().await, 1);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn registers_multiple_same_tunnel_connections_without_replacement() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let first_fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let pool = ActiveClientPool::new();
        let first_remote_addr = first_fixture.server_connection.remote_address();
        let second_remote_addr = second_fixture.server_connection.remote_address();
        let expected_first_log = format!(
            "server tunnel connection accepted: client-identity={}",
            client_identity.client_identity
        );
        let expected_second_log = format!(
            "server tunnel connection accepted: client-identity={}",
            client_identity.client_identity
        );
        let pool_for_registration = pool.clone();
        let client_identity_for_registration = client_identity.client_identity.clone();
        let expected_first_log_for_wait = expected_first_log.clone();
        let expected_second_log_for_wait = expected_second_log.clone();

        let output = capture_logs(|buffer| async move {
            pool_for_registration
                .register(
                    first_fixture.server_connection.clone(),
                    client_identity_for_registration.clone(),
                )
                .await;
            wait_for_log(&buffer, expected_first_log_for_wait.as_str()).await;
            pool_for_registration
                .register(
                    second_fixture.server_connection.clone(),
                    client_identity_for_registration,
                )
                .await;
            wait_for_log(&buffer, expected_second_log_for_wait.as_str()).await;
        })
        .await;

        assert!(output.contains(&expected_first_log));
        assert!(output.contains(&expected_second_log));
        assert!(!output.contains(first_remote_addr.to_string().as_str()));
        assert!(!output.contains(second_remote_addr.to_string().as_str()));
        assert_eq!(pool.connection_count().await, 2);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selects_least_active_connection_and_round_robins_equal_load_ties() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let first_fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let second_fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let pool = ActiveClientPool::new();
        pool.register(
            first_fixture.server_connection.clone(),
            client_identity.client_identity.clone(),
        )
        .await;
        pool.register(
            second_fixture.server_connection.clone(),
            client_identity.client_identity.clone(),
        )
        .await;

        let first_selection = pool
            .select_connection()
            .await
            .expect("first pool member should be selectable");
        let first_selected_addr = first_selection.connection().remote_address();
        let first_stream_guard = first_selection.record_open_stream();

        let second_selection = pool
            .select_connection()
            .await
            .expect("second pool member should be selectable");
        assert_ne!(
            second_selection.connection().remote_address(),
            first_selected_addr,
            "equal-load ties should rotate to the other member"
        );
        let second_stream_guard = second_selection.record_open_stream();

        drop(first_stream_guard);
        drop(second_stream_guard);

        let third_selection = pool
            .select_connection()
            .await
            .expect("pool should still select a member after loads return to zero");
        let third_selected_addr = third_selection.connection().remote_address();
        let third_stream_guard = third_selection.record_open_stream();

        let fourth_selection = pool
            .select_connection()
            .await
            .expect("pool should place onto the least-active member");
        assert_ne!(
            fourth_selection.connection().remote_address(),
            third_selected_addr,
            "the zero-load member should win once the selected member becomes busier"
        );
        assert_eq!(third_selection.active_stream_count(), 1);
        assert_eq!(fourth_selection.active_stream_count(), 0);

        drop(third_stream_guard);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closes_all_connections_and_clears_the_pool() -> io::Result<()> {
        let client_identity = generate_test_client_identity()?;
        let fixture = TunnelConnectionFixture::connect(&client_identity).await?;
        let pool = ActiveClientPool::new();
        let remote_addr = fixture.server_connection.remote_address();
        let expected_closed_log = format!(
            "server tunnel connection closed: client-identity={}",
            client_identity.client_identity
        );
        let pool_for_registration = pool.clone();
        let client_identity_for_registration = client_identity.client_identity.clone();
        let expected_closed_log_for_wait = expected_closed_log.clone();

        let output = capture_logs(|buffer| async move {
            pool_for_registration
                .register(
                    fixture.server_connection.clone(),
                    client_identity_for_registration,
                )
                .await;
            assert_eq!(
                pool_for_registration
                    .close_all_connections(b"graceful shutdown")
                    .await,
                1
            );
            wait_for_log(&buffer, expected_closed_log_for_wait.as_str()).await;
        })
        .await;

        assert!(output.contains(&expected_closed_log));
        assert!(!output.contains(remote_addr.to_string().as_str()));
        assert_eq!(pool.connection_count().await, 0);
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
