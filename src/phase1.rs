use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::client_hello::read_client_hello;

pub const RUNEWARP_ALPN: &[u8] = b"runewarp/1";
pub const PHASE1_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const PHASE1_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2 * 60);
pub const PHASE1_MAX_SERVER_OPENED_BIDI_STREAMS: u32 = 1024;

#[derive(Clone)]
pub struct Phase1ServerConfig {
    pub public_bind_addr: SocketAddr,
    pub tunnel_bind_addr: SocketAddr,
    pub quic_server_config: quinn::ServerConfig,
}

pub struct Phase1Server {
    public_listener: TcpListener,
    tunnel_endpoint: Endpoint,
    active_client: Arc<RwLock<Option<ActiveClient>>>,
    next_client_generation: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct Phase1ClientConfig {
    pub local_bind_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub backend_addr: SocketAddr,
    pub quic_client_config: quinn::ClientConfig,
}

pub struct Phase1Client {
    backend_addr: SocketAddr,
    endpoint: Endpoint,
    connection: Connection,
}

#[derive(Clone)]
struct ActiveClient {
    generation: u64,
    connection: Connection,
}

#[derive(Debug)]
pub enum Phase1ClientConnectError {
    Bind(io::Error),
    Connect(quinn::ConnectError),
    Handshake(quinn::ConnectionError),
}

#[derive(Debug)]
pub enum Phase1QuicConfigError {
    Rustls(rustls::Error),
    NoInitialCipherSuite(quinn::crypto::rustls::NoInitialCipherSuite),
}

impl fmt::Display for Phase1ClientConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => write!(
                formatter,
                "failed to bind the phase-1 client endpoint: {error}"
            ),
            Self::Connect(error) => {
                write!(
                    formatter,
                    "failed to start the phase-1 client connection: {error}"
                )
            }
            Self::Handshake(error) => {
                write!(formatter, "phase-1 client QUIC handshake failed: {error}")
            }
        }
    }
}

impl std::error::Error for Phase1ClientConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::Handshake(error) => Some(error),
        }
    }
}

impl fmt::Display for Phase1QuicConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rustls(error) => write!(formatter, "TLS configuration error: {error}"),
            Self::NoInitialCipherSuite(error) => {
                write!(formatter, "QUIC TLS configuration error: {error}")
            }
        }
    }
}

impl std::error::Error for Phase1QuicConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rustls(error) => Some(error),
            Self::NoInitialCipherSuite(error) => Some(error),
        }
    }
}

impl From<rustls::Error> for Phase1QuicConfigError {
    fn from(error: rustls::Error) -> Self {
        Self::Rustls(error)
    }
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for Phase1QuicConfigError {
    fn from(error: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite(error)
    }
}

pub fn make_quic_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, Phase1QuicConfigError> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;
    server_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .expect("newly created QUIC server configs should expose a unique transport config");
    configure_server_transport(transport_config);

    Ok(server_config)
}

pub fn make_quic_client_config(
    roots: RootCertStore,
) -> Result<quinn::ClientConfig, Phase1QuicConfigError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![RUNEWARP_ALPN.to_vec()];

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(client_transport_config()));

    Ok(client_config)
}

impl Phase1Server {
    pub async fn bind(config: Phase1ServerConfig) -> io::Result<Self> {
        let public_listener = TcpListener::bind(config.public_bind_addr).await?;
        let tunnel_endpoint = Endpoint::server(config.quic_server_config, config.tunnel_bind_addr)?;

        Ok(Self {
            public_listener,
            tunnel_endpoint,
            active_client: Arc::new(RwLock::new(None)),
            next_client_generation: Arc::new(AtomicU64::new(1)),
        })
    }

    pub fn public_addr(&self) -> io::Result<SocketAddr> {
        self.public_listener.local_addr()
    }

    pub fn tunnel_addr(&self) -> io::Result<SocketAddr> {
        self.tunnel_endpoint.local_addr()
    }

    pub async fn run(self) -> io::Result<()> {
        loop {
            tokio::select! {
                accept_result = self.public_listener.accept() => {
                    let (stream, _) = accept_result?;
                    let active_client = self.active_client.clone();
                    tokio::spawn(async move {
                        let _ = handle_public_connection(stream, active_client).await;
                    });
                }
                incoming = self.tunnel_endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };

                    let active_client = self.active_client.clone();
                    let next_client_generation = self.next_client_generation.clone();
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            register_active_client(connection, active_client, next_client_generation).await;
                        }
                    });
                }
            }
        }
    }
}

impl Phase1Client {
    pub async fn connect(config: Phase1ClientConfig) -> Result<Self, Phase1ClientConnectError> {
        let mut endpoint =
            Endpoint::client(config.local_bind_addr).map_err(Phase1ClientConnectError::Bind)?;
        endpoint.set_default_client_config(config.quic_client_config);

        let connection = endpoint
            .connect(config.server_addr, &config.server_name)
            .map_err(Phase1ClientConnectError::Connect)?
            .await
            .map_err(Phase1ClientConnectError::Handshake)?;

        Ok(Self {
            backend_addr: config.backend_addr,
            endpoint,
            connection,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub async fn run(self) -> Result<(), quinn::ConnectionError> {
        loop {
            match self.connection.accept_bi().await {
                Ok((send, recv)) => {
                    let backend_addr = self.backend_addr;
                    tokio::spawn(async move {
                        let _ = handle_tunnel_stream(send, recv, backend_addr).await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }
}

async fn register_active_client(
    connection: Connection,
    active_client: Arc<RwLock<Option<ActiveClient>>>,
    next_client_generation: Arc<AtomicU64>,
) {
    let generation = next_client_generation.fetch_add(1, Ordering::Relaxed);
    let previous = {
        let mut active_client_guard = active_client.write().await;
        active_client_guard.replace(ActiveClient {
            generation,
            connection: connection.clone(),
        })
    };

    if let Some(previous) = previous {
        previous.connection.close(0_u32.into(), b"replaced");
    }

    tokio::spawn(async move {
        let _ = connection.closed().await;
        let mut active_client_guard = active_client.write().await;
        if active_client_guard
            .as_ref()
            .is_some_and(|active| active.generation == generation)
        {
            *active_client_guard = None;
        }
    });
}

async fn handle_public_connection(
    mut public_stream: TcpStream,
    active_client: Arc<RwLock<Option<ActiveClient>>>,
) -> io::Result<()> {
    let parsed_client_hello = match read_client_hello(&mut public_stream).await {
        Ok(parsed_client_hello) => parsed_client_hello,
        Err(_) => return Ok(()),
    };
    let _ = parsed_client_hello.server_name();

    let active_connection = {
        active_client
            .read()
            .await
            .as_ref()
            .map(|active| active.connection.clone())
    };
    let Some(active_connection) = active_connection else {
        return Ok(());
    };

    let (send, recv) = match active_connection.open_bi().await {
        Ok(stream) => stream,
        Err(_) => return Ok(()),
    };

    proxy_tcp_over_quic(
        public_stream,
        parsed_client_hello.into_buffered_bytes(),
        send,
        recv,
    )
    .await
}

async fn handle_tunnel_stream(
    send: SendStream,
    recv: RecvStream,
    backend_addr: SocketAddr,
) -> io::Result<()> {
    let backend_stream = match TcpStream::connect(backend_addr).await {
        Ok(stream) => stream,
        Err(error) => {
            let mut send = send;
            let mut recv = recv;
            let _ = send.reset(proxy_stream_error_code());
            let _ = recv.stop(proxy_stream_error_code());
            return Err(error);
        }
    };

    proxy_tcp_over_quic(backend_stream, Vec::new(), send, recv).await
}

async fn proxy_tcp_over_quic(
    tcp_stream: TcpStream,
    initial_bytes: Vec<u8>,
    quic_send: SendStream,
    quic_recv: RecvStream,
) -> io::Result<()> {
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();

    let (send_result, recv_result) = tokio::join!(
        forward_tcp_to_quic(tcp_reader, quic_send, initial_bytes),
        forward_quic_to_tcp(quic_recv, tcp_writer)
    );

    send_result?;
    recv_result
}

async fn forward_tcp_to_quic(
    mut tcp_reader: OwnedReadHalf,
    mut quic_send: SendStream,
    initial_bytes: Vec<u8>,
) -> io::Result<()> {
    let result = async {
        if !initial_bytes.is_empty() {
            quic_send.write_all(&initial_bytes).await?;
        }

        copy(&mut tcp_reader, &mut quic_send).await?;
        quic_send.finish().map_err(io::Error::other)
    }
    .await;

    if result.is_err() {
        let _ = quic_send.reset(proxy_stream_error_code());
    }

    result
}

async fn forward_quic_to_tcp(
    mut quic_recv: RecvStream,
    mut tcp_writer: OwnedWriteHalf,
) -> io::Result<()> {
    let result = async {
        copy(&mut quic_recv, &mut tcp_writer).await?;
        tcp_writer.shutdown().await
    }
    .await;

    if result.is_err() {
        let _ = quic_recv.stop(proxy_stream_error_code());
    }

    result
}

fn configure_server_transport(transport_config: &mut TransportConfig) {
    transport_config.max_concurrent_bidi_streams(0_u8.into());
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_idle_timeout(Some(
        PHASE1_IDLE_TIMEOUT
            .try_into()
            .expect("the fixed phase-1 idle timeout should fit quinn's idle timeout type"),
    ));
    transport_config.keep_alive_interval(Some(PHASE1_KEEPALIVE_INTERVAL));
}

fn client_transport_config() -> TransportConfig {
    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(PHASE1_MAX_SERVER_OPENED_BIDI_STREAMS.into());
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_idle_timeout(Some(
        PHASE1_IDLE_TIMEOUT
            .try_into()
            .expect("the fixed phase-1 idle timeout should fit quinn's idle timeout type"),
    ));
    transport_config.keep_alive_interval(Some(PHASE1_KEEPALIVE_INTERVAL));
    transport_config
}

fn proxy_stream_error_code() -> quinn::VarInt {
    1_u32.into()
}
