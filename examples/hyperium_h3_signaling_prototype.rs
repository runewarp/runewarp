//! PROTOTYPE — throwaway patched h3 + h3-quinn vertical slice for #239.
//!
//! Run with sibling patched dependency checkouts present:
//! `cargo run --example hyperium_h3_signaling_prototype`

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future;
use h3::{ConnectionState, error::Code, ext::Protocol, quic::StreamId};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_quinn::quinn::{self, Endpoint, TransportConfig};
use http::{Method, Request, Response, StatusCode};
use rcgen::generate_simple_self_signed;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

const SIGNALING_SETTING: u64 = 0x370e_8f9b_5f48_4846;
const PUBLIC_QUIC_SETTING: u64 = 0x370e_8f9b_5051_5549;
const SERVER_NAME: &str = "patched-h3.prototype";
const CONTEXT_ID: u8 = 7;
const INITIAL_SIZE: usize = 1200;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

type PrototypeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> PrototypeResult<()> {
    println!("PROTOTYPE — patched h3 + h3-quinn signaling and Public QUIC seam");
    let material = Material::new()?;
    let inner_initial = capture_real_initial(&material.server_certificate).await?;

    let server_endpoint = Endpoint::server(server_config(&material)?, localhost(0))?;
    let server_addr = server_endpoint.local_addr()?;
    let server_accept = server_endpoint.clone();
    let server = tokio::spawn(async move {
        let accepted = timeout(IO_TIMEOUT, server_accept.accept())
            .await?
            .ok_or("server endpoint closed")?;
        let quinn_connection = timeout(IO_TIMEOUT, accepted).await??;
        let peer_certificates = quinn_connection
            .peer_identity()
            .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
            .ok_or("mTLS peer identity missing")?;
        if peer_certificates.is_empty() {
            return Err("empty mTLS peer identity".into());
        }

        let mut builder = h3::server::builder();
        builder
            .additional_setting(SIGNALING_SETTING, 1)?
            .additional_setting(PUBLIC_QUIC_SETTING, 1)?
            .enable_extended_connect(true)
            .enable_datagram(true);
        let mut connection = builder
            .build(h3_quinn::Connection::new(quinn_connection.clone()))
            .await?;
        let mut datagram_sender = connection.get_datagram_sender(stream_id(4)?);
        let mut datagram_reader = connection.get_datagram_reader();

        let withdrawal_started = Instant::now();
        let withdrawal = connection.accept().await?.ok_or("withdrawal missing")?;
        let (request, mut stream) = withdrawal.resolve_request().await?;
        require(request.method() == Method::PUT, "withdrawal method")?;
        require(
            request.uri().path() == "/v1/tunnel/withdrawal",
            "withdrawal path",
        )?;
        require(
            stream.recv_data().await?.is_none(),
            "withdrawal bodyless request",
        )?;
        require(
            connection.settings().raw(SIGNALING_SETTING) == Some(1),
            "peer signaling SETTINGS",
        )?;
        require(
            connection.settings().raw(PUBLIC_QUIC_SETTING) == Some(1),
            "peer Public QUIC SETTINGS",
        )?;
        sleep(Duration::from_millis(10)).await;
        let commit = Instant::now();
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let response_sent = Instant::now();

        let carrier_started = Instant::now();
        let carrier = connection.accept().await?.ok_or("carrier missing")?;
        let (request, mut stream) = carrier.resolve_request().await?;
        require(
            request.method() == Method::CONNECT,
            "carrier Extended CONNECT",
        )?;
        require(
            request.extensions().get::<Protocol>().map(Protocol::as_str)
                == Some("runewarp-public-quic"),
            "carrier protocol dispatch",
        )?;
        require(stream.id() == stream_id(4)?, "carrier request routing")?;
        let mut capsule = stream
            .recv_data()
            .await?
            .ok_or("registration capsule missing")?;
        require(
            capsule.copy_to_bytes(capsule.remaining()).as_ref() == [0, 1, CONTEXT_ID],
            "registration capsule",
        )?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream
            .send_data(Bytes::from_static(&[0, 1, CONTEXT_ID]))
            .await?;
        let carrier_ready = Instant::now();

        let datagram = timeout(IO_TIMEOUT, datagram_reader.read_datagram()).await??;
        require(
            datagram.stream_id() == stream_id(4)?,
            "Quarter Stream ID routing",
        )?;
        let payload = datagram.into_payload();
        require(
            payload.len() == INITIAL_SIZE + 1 && payload[0] == CONTEXT_ID,
            "Context ID plus 1200-byte Initial",
        )?;
        require(is_quic_v1_initial(&payload[1..]), "real inner QUIC Initial")?;
        datagram_sender.send_datagram(payload)?;
        stream
            .send_data(Bytes::from_static(&[1, 1, CONTEXT_ID]))
            .await?;
        stream.finish().await?;
        let carrier_done = Instant::now();

        sleep(Duration::from_millis(50)).await;
        connection.shutdown_at(stream_id(8)?).await?;
        sleep(Duration::from_millis(50)).await;
        quinn_connection.close(Code::H3_NO_ERROR.value().try_into()?, b"prototype complete");
        Ok::<_, Box<dyn Error + Send + Sync>>((
            peer_certificates[0].len(),
            commit.duration_since(withdrawal_started),
            response_sent.duration_since(commit),
            carrier_ready.duration_since(carrier_started),
            carrier_done.duration_since(carrier_ready),
        ))
    });

    let mut client_endpoint = Endpoint::client(localhost(0))?;
    client_endpoint.set_default_client_config(client_config(&material)?);
    let setup_started = Instant::now();
    let quinn_connection = timeout(
        IO_TIMEOUT,
        client_endpoint.connect(server_addr, SERVER_NAME)?,
    )
    .await??;
    let authenticated_setup = setup_started.elapsed();
    let datagram_ceiling = quinn_connection
        .max_datagram_size()
        .ok_or("QUIC Datagram unavailable")?;

    let mut builder = h3::client::builder();
    builder
        .additional_setting(SIGNALING_SETTING, 1)?
        .additional_setting(PUBLIC_QUIC_SETTING, 1)?
        .enable_extended_connect(true)
        .enable_datagram(true);
    let (mut driver, mut requests) = builder
        .build(h3_quinn::Connection::new(quinn_connection.clone()))
        .await?;
    let mut datagram_sender = driver.get_datagram_sender(stream_id(4)?);
    let mut datagram_reader = driver.get_datagram_reader();
    let driver_task =
        tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let withdrawal_started = Instant::now();
    let mut withdrawal = requests
        .send_request(Request::put(format!("https://{SERVER_NAME}/v1/tunnel/withdrawal")).body(())?)
        .await?;
    withdrawal.finish().await?;
    let withdrawal_response = withdrawal.recv_response().await?;
    require(
        withdrawal_response.status() == StatusCode::NO_CONTENT,
        "delayed bodyless 204",
    )?;
    require(withdrawal.recv_data().await?.is_none(), "bodyless 204")?;
    let withdrawal_latency = withdrawal_started.elapsed();
    require(
        requests.settings().raw(SIGNALING_SETTING) == Some(1),
        "server signaling SETTINGS",
    )?;
    require(
        requests.settings().raw(PUBLIC_QUIC_SETTING) == Some(1),
        "server Public QUIC SETTINGS",
    )?;

    let mut carrier_request =
        Request::connect(format!("https://{SERVER_NAME}/v1/public-quic")).body(())?;
    carrier_request
        .extensions_mut()
        .insert("runewarp-public-quic".parse::<Protocol>()?);
    let mut carrier = requests.send_request(carrier_request).await?;
    require(carrier.id() == stream_id(4)?, "expected carrier stream 4")?;
    carrier
        .send_data(Bytes::from_static(&[0, 1, CONTEXT_ID]))
        .await?;
    let response = carrier.recv_response().await?;
    require(response.status() == StatusCode::OK, "carrier response")?;
    let mut registered = carrier
        .recv_data()
        .await?
        .ok_or("registration response capsule missing")?;
    require(
        registered.copy_to_bytes(registered.remaining()).as_ref() == [0, 1, CONTEXT_ID],
        "registration response capsule",
    )?;

    let mut framed = BytesMut::with_capacity(INITIAL_SIZE + 1);
    framed.extend_from_slice(&[CONTEXT_ID]);
    framed.extend_from_slice(&inner_initial);
    let framed = framed.freeze();
    let wire_size = framed.len() + 1;
    require(
        wire_size <= datagram_ceiling,
        "live Datagram ceiling carries framed Initial",
    )?;
    datagram_sender.send_datagram(framed.clone())?;
    let echoed = timeout(IO_TIMEOUT, datagram_reader.read_datagram()).await??;
    require(
        echoed.stream_id() == stream_id(4)?,
        "echo Quarter Stream ID",
    )?;
    require(
        echoed.into_payload() == framed,
        "bidirectional Datagram payload",
    )?;
    let mut closed = carrier.recv_data().await?.ok_or("close capsule missing")?;
    require(
        closed.copy_to_bytes(closed.remaining()).as_ref() == [1, 1, CONTEXT_ID],
        "close capsule",
    )?;
    require(
        carrier.recv_data().await?.is_none(),
        "carrier response finish",
    )?;

    drop(carrier);
    let server_metrics = server.await??;
    drop(requests);
    quinn_connection.close(Code::H3_NO_ERROR.value().try_into()?, b"prototype complete");
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    let _ = timeout(Duration::from_millis(100), driver_task).await;

    println!(
        "measured.authenticated_h3_setup_us={}",
        authenticated_setup.as_micros()
    );
    println!("measured.mtls_peer_certificate_bytes={}", server_metrics.0);
    println!(
        "measured.withdrawal_request_to_commit_us={}",
        server_metrics.1.as_micros()
    );
    println!(
        "measured.withdrawal_commit_to_204_send_us={}",
        server_metrics.2.as_micros()
    );
    println!(
        "measured.withdrawal_round_trip_us={}",
        withdrawal_latency.as_micros()
    );
    println!("measured.carrier_setup_us={}", server_metrics.3.as_micros());
    println!(
        "measured.carrier_datagram_to_teardown_us={}",
        server_metrics.4.as_micros()
    );
    println!("measured.quinn_datagram_ceiling_bytes={datagram_ceiling}");
    println!("measured.h3_datagram_wire_bytes={wire_size}");
    println!(
        "verified=custom-settings,raw-peer-settings,mtls,no-app-0rtt,withdrawal-204,extended-connect,capsules,bidirectional-h3-datagram,exact-goaway-send,teardown"
    );
    println!(
        "unsupported=full-malformed-matrix,observed-goaway-id,datagram-load-benchmark,cid-router"
    );
    println!(
        "note=same-Server rebinding remains unidentified when tuple and backend DCID both change"
    );
    Ok(())
}

fn require(condition: bool, label: &str) -> PrototypeResult<()> {
    condition
        .then_some(())
        .ok_or_else(|| format!("prototype assertion failed: {label}").into())
}

fn stream_id(value: u64) -> PrototypeResult<StreamId> {
    StreamId::try_from(value).map_err(|_| format!("invalid prototype stream ID {value}").into())
}

struct Material {
    server_certificate: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    client_certificate: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
}

impl Material {
    fn new() -> PrototypeResult<Self> {
        let server = generate_simple_self_signed(vec![SERVER_NAME.to_owned()])?;
        let client = generate_simple_self_signed(vec!["runewarp-client.prototype".to_owned()])?;
        Ok(Self {
            server_certificate: CertificateDer::from(server.cert),
            server_key: PrivatePkcs8KeyDer::from(server.signing_key.serialize_der()).into(),
            client_certificate: CertificateDer::from(client.cert),
            client_key: PrivatePkcs8KeyDer::from(client.signing_key.serialize_der()).into(),
        })
    }
}

fn transport() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        .initial_mtu(1452)
        .mtu_discovery_config(None)
        .datagram_receive_buffer_size(Some(64 * 1024))
        .datagram_send_buffer_size(64 * 1024);
    Arc::new(config)
}

fn server_config(material: &Material) -> PrototypeResult<quinn::ServerConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(material.client_certificate.clone())?;
    let verifier = WebPkiClientVerifier::builder(roots.into()).build()?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![material.server_certificate.clone()],
            material.server_key.clone_key(),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    config.transport = transport();
    Ok(config)
}

fn client_config(material: &Material) -> PrototypeResult<quinn::ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(material.server_certificate.clone())?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![material.client_certificate.clone()],
            material.client_key.clone_key(),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    Ok(config)
}

async fn capture_real_initial(
    server_certificate: &CertificateDer<'static>,
) -> PrototypeResult<Bytes> {
    let socket = UdpSocket::bind(localhost(0)).await?;
    let mut endpoint = Endpoint::client(localhost(0))?;
    let mut roots = RootCertStore::empty();
    roots.add(server_certificate.clone())?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    endpoint.set_default_client_config(config);
    let connecting = endpoint.connect(socket.local_addr()?, SERVER_NAME)?;
    let task = tokio::spawn(connecting);
    let mut buffer = vec![0; 2048];
    let (length, _) = timeout(IO_TIMEOUT, socket.recv_from(&mut buffer)).await??;
    task.abort();
    endpoint.close(0_u8.into(), b"captured");
    buffer.truncate(length);
    require(
        length == INITIAL_SIZE && is_quic_v1_initial(&buffer),
        "real 1200-byte QUIC v1 Initial capture",
    )?;
    Ok(Bytes::from(buffer))
}

fn is_quic_v1_initial(bytes: &[u8]) -> bool {
    bytes.len() == INITIAL_SIZE
        && bytes[0] & 0xc0 == 0xc0
        && bytes[0] & 0x30 == 0
        && bytes[1..5] == 1_u32.to_be_bytes()
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
