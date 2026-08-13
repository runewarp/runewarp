//! PROTOTYPE: published-quiche-first HTTP/3 signaling experiment

use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use quiche::h3;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tempfile::TempDir;
use tokio::net::UdpSocket;

const SETTINGS_RUNEWARP_SIGNALING: u64 = 0x370e_8f9b_5f48_4846;
const SETTINGS_RUNEWARP_PUBLIC_QUIC_PROTOTYPE: u64 = 0x370e_8f9b_5f48_4847;
const MAX_DATAGRAM_SIZE: usize = 1_452;
const H3_NO_ERROR: u64 = 0x100;
const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
const H3_SETTINGS_ERROR: u64 = 0x109;
const H3_MISSING_SETTINGS: u64 = 0x10a;
const H3_REQUEST_CANCELLED: u64 = 0x10c;

type AnyError = Box<dyn Error>;

#[derive(Debug)]
#[allow(dead_code)] // Every field is deliberately surfaced by the runnable report.
struct PrototypeReport {
    client_peer_settings: Vec<(u64, u64)>,
    server_peer_settings: Vec<(u64, u64)>,
    server_observed_client_identity: bool,
    anonymous_client_rejected: bool,
    setup_micros: u128,
    withdrawal_stream_id: u64,
    withdrawal_status: u16,
    withdrawal_request_to_commit_micros: u128,
    withdrawal_commit_to_response_micros: u128,
    carrier_stream_id: u64,
    carrier_setup_micros: u128,
    lifecycle_capsule_round_trip: bool,
    datagram_ceiling: usize,
    framed_initial_bytes: usize,
    client_to_server_initial_identical: bool,
    server_to_client_initial_identical: bool,
    datagram_workload_sent: usize,
    datagram_workload_received: usize,
    datagram_workload_mbps: f64,
    signaling_latency_with_datagrams_micros: u128,
    exact_goaway_boundary: u64,
    directional_cancellation_code: u64,
    carrier_cleanup_isolated_from_signaling: bool,
    teardown_reached_terminal_state: bool,
}

struct CertificatePaths {
    _directory: TempDir,
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

struct Fixture {
    client_socket: UdpSocket,
    server_socket: UdpSocket,
    client: quiche::Connection,
    server: quiche::Connection,
    client_h3: h3::Connection,
    server_h3: h3::Connection,
    _certificates: CertificatePaths,
}

impl Fixture {
    async fn connect() -> Result<Self, AnyError> {
        Self::connect_with_client_certificate(true).await
    }

    async fn connect_with_client_certificate(present: bool) -> Result<Self, AnyError> {
        let certificates = write_certificates()?;
        let client_socket = UdpSocket::bind(localhost(0)).await?;
        let server_socket = UdpSocket::bind(localhost(0)).await?;
        let client_address = client_socket.local_addr()?;
        let server_address = server_socket.local_addr()?;

        let mut client_config = transport_config()?;
        if present {
            client_config.load_cert_chain_from_pem_file(&certificates.client_cert)?;
            client_config.load_priv_key_from_pem_file(&certificates.client_key)?;
        }
        client_config.load_verify_locations_from_file(&certificates.ca)?;
        client_config.verify_peer(true);

        let mut server_tls = SslContextBuilder::new(SslMethod::tls())?;
        server_tls.set_certificate_chain_file(&certificates.server_cert)?;
        server_tls.set_private_key_file(&certificates.server_key, SslFiletype::PEM)?;
        server_tls.set_ca_file(&certificates.ca)?;
        server_tls.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        let mut server_config = transport_config_with_tls(server_tls)?;

        let client_scid_bytes = [0xc1; quiche::MAX_CONN_ID_LEN];
        let client_scid = quiche::ConnectionId::from_ref(&client_scid_bytes);
        let mut client = quiche::connect(
            Some("localhost"),
            &client_scid,
            client_address,
            server_address,
            &mut client_config,
        )?;

        let mut output = vec![0_u8; 65_535];
        let (written, send_info) = client.send(&mut output)?;
        client_socket
            .send_to(&output[..written], send_info.to)
            .await?;

        let mut input = vec![0_u8; 65_535];
        let (read, from) = server_socket.recv_from(&mut input).await?;
        let header = quiche::Header::from_slice(&mut input[..read], quiche::MAX_CONN_ID_LEN)?;
        let server_scid = header.dcid.clone();
        let mut server =
            quiche::accept(&server_scid, None, server_address, from, &mut server_config)?;
        server.recv(
            &mut input[..read],
            quiche::RecvInfo {
                from,
                to: server_address,
            },
        )?;

        drive_until(
            &client_socket,
            &server_socket,
            &mut client,
            &mut server,
            |c, s| c.is_established() && s.is_established(),
        )
        .await?;

        let client_h3_config = h3_config()?;
        let server_h3_config = h3_config()?;
        let client_h3 = h3::Connection::with_transport(&mut client, &client_h3_config)?;
        let server_h3 = h3::Connection::with_transport(&mut server, &server_h3_config)?;

        Ok(Self {
            client_socket,
            server_socket,
            client,
            server,
            client_h3,
            server_h3,
            _certificates: certificates,
        })
    }

    async fn exchange_settings(&mut self) -> Result<(), AnyError> {
        for _ in 0..1_000 {
            self.drive_once().await?;
            drain_h3(&mut self.client_h3, &mut self.client)?;
            drain_h3(&mut self.server_h3, &mut self.server)?;
            if self.client_h3.peer_settings_raw().is_some()
                && self.server_h3.peer_settings_raw().is_some()
            {
                return Ok(());
            }
        }
        Err("timed out waiting for bilateral H3 SETTINGS".into())
    }

    async fn drive_once(&mut self) -> Result<(), AnyError> {
        drive_once(
            &self.client_socket,
            &self.server_socket,
            &mut self.client,
            &mut self.server,
        )
        .await
    }

    async fn next_server_event(&mut self) -> Result<(u64, h3::Event), AnyError> {
        for _ in 0..10_000 {
            self.drive_once().await?;
            match self.server_h3.poll(&mut self.server) {
                Ok(event) => return Ok(event),
                Err(h3::Error::Done) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("timed out waiting for Server H3 event".into())
    }

    async fn next_client_event(&mut self) -> Result<(u64, h3::Event), AnyError> {
        for _ in 0..10_000 {
            self.drive_once().await?;
            match self.client_h3.poll(&mut self.client) {
                Ok(event) => return Ok(event),
                Err(h3::Error::Done) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("timed out waiting for Client H3 event".into())
    }

    async fn receive_server_datagram(&mut self) -> Result<Vec<u8>, AnyError> {
        let mut buffer = vec![0_u8; 65_535];
        for _ in 0..10_000 {
            self.drive_once().await?;
            match self.server.dgram_recv(&mut buffer) {
                Ok(read) => return Ok(buffer[..read].to_vec()),
                Err(quiche::Error::Done) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("timed out waiting for Server Datagram".into())
    }

    async fn receive_client_datagram(&mut self) -> Result<Vec<u8>, AnyError> {
        let mut buffer = vec![0_u8; 65_535];
        for _ in 0..10_000 {
            self.drive_once().await?;
            match self.client.dgram_recv(&mut buffer) {
                Ok(read) => return Ok(buffer[..read].to_vec()),
                Err(quiche::Error::Done) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("timed out waiting for Client Datagram".into())
    }

    async fn close(mut self) -> Result<bool, AnyError> {
        self.client
            .close(true, H3_NO_ERROR, b"prototype complete")?;
        for _ in 0..10_000 {
            self.drive_once().await?;
            if self.client.is_closed() && self.server.is_closed() {
                return Ok(true);
            }
            if self.client.timeout() == Some(Duration::ZERO) {
                self.client.on_timeout();
            }
            if self.server.timeout() == Some(Duration::ZERO) {
                self.server.on_timeout();
            }
        }
        Ok(false)
    }
}

async fn run_settings_scenario() -> Result<PrototypeReport, AnyError> {
    let anonymous_client_rejected = Fixture::connect_with_client_certificate(false)
        .await
        .is_err();
    let started = Instant::now();
    let mut fixture = Fixture::connect().await?;
    fixture.exchange_settings().await?;

    let client_peer_settings = fixture
        .client_h3
        .peer_settings_raw()
        .ok_or("Client did not observe Server SETTINGS")?
        .to_vec();
    let server_peer_settings = fixture
        .server_h3
        .peer_settings_raw()
        .ok_or("Server did not observe Client SETTINGS")?
        .to_vec();
    validate_signaling_settings(Some(&client_peer_settings))
        .map_err(|code| format!("Client signaling SETTINGS failed with H3 code {code:#x}"))?;
    validate_signaling_settings(Some(&server_peer_settings))
        .map_err(|code| format!("Server signaling SETTINGS failed with H3 code {code:#x}"))?;
    let server_observed_client_identity = fixture.server.peer_cert().is_some();
    let setup_micros = started.elapsed().as_micros();

    let withdrawal_started = Instant::now();
    let withdrawal_headers = [
        h3::Header::new(b":method", b"PUT"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", b"localhost"),
        h3::Header::new(b":path", b"/v1/tunnel/withdrawal"),
    ];
    let withdrawal_stream_id =
        fixture
            .client_h3
            .send_request(&mut fixture.client, &withdrawal_headers, true)?;
    let (server_stream_id, event) = fixture.next_server_event().await?;
    require_headers(event, b"PUT", b"/v1/tunnel/withdrawal")
        .map_err(|error| format!("stream {server_stream_id}: {error}"))?;
    if server_stream_id != withdrawal_stream_id {
        return Err("withdrawal stream routing mismatch".into());
    }
    let withdrawal_request_to_commit_micros = withdrawal_started.elapsed().as_micros();
    let committed = Instant::now();
    fixture.server_h3.send_response(
        &mut fixture.server,
        withdrawal_stream_id,
        &[h3::Header::new(b":status", b"204")],
        true,
    )?;
    let mut withdrawal_status = None;
    let mut withdrawal_finished = false;
    while withdrawal_status.is_none() || !withdrawal_finished {
        let (stream_id, event) = fixture.next_client_event().await?;
        if stream_id != withdrawal_stream_id {
            continue;
        }
        match event {
            h3::Event::Headers { list, .. } => {
                withdrawal_status = header_value(&list, b":status")
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|value| value.parse().ok());
            }
            h3::Event::Finished => withdrawal_finished = true,
            _ => return Err("withdrawal response was not bodyless".into()),
        }
    }
    let withdrawal_commit_to_response_micros = committed.elapsed().as_micros();

    let carrier_started = Instant::now();
    let carrier_headers = [
        h3::Header::new(b":method", b"CONNECT"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", b"localhost"),
        h3::Header::new(b":path", b"/prototype/public-quic"),
        h3::Header::new(b":protocol", b"runewarp-public-quic-prototype"),
        h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    let carrier_stream_id =
        fixture
            .client_h3
            .send_request(&mut fixture.client, &carrier_headers, false)?;
    let (server_stream_id, event) = loop {
        let candidate = fixture.next_server_event().await?;
        if candidate.0 == carrier_stream_id && matches!(candidate.1, h3::Event::Headers { .. }) {
            break candidate;
        }
    };
    require_headers(event, b"CONNECT", b"/prototype/public-quic")?;
    if server_stream_id != carrier_stream_id {
        return Err("carrier stream routing mismatch".into());
    }
    fixture.server_h3.send_response(
        &mut fixture.server,
        carrier_stream_id,
        &[
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"capsule-protocol", b"?1"),
        ],
        false,
    )?;
    let (_, event) = fixture.next_client_event().await?;
    let status = event_header_value(event, b":status")?;
    if status != b"200" {
        return Err("carrier request was not accepted".into());
    }
    let carrier_setup_micros = carrier_started.elapsed().as_micros();

    let lifecycle_capsule = encode_lifecycle_capsule(7);
    fixture.client_h3.send_body(
        &mut fixture.client,
        carrier_stream_id,
        &lifecycle_capsule,
        false,
    )?;
    let (_, event) = fixture.next_server_event().await?;
    if !matches!(event, h3::Event::Data) {
        return Err("Server did not receive lifecycle Capsule DATA".into());
    }
    let mut capsule_buffer = [0_u8; 32];
    let read =
        fixture
            .server_h3
            .recv_body(&mut fixture.server, carrier_stream_id, &mut capsule_buffer)?;
    let server_received_capsule = decode_lifecycle_capsule(&capsule_buffer[..read]) == Some(7);
    fixture.server_h3.send_body(
        &mut fixture.server,
        carrier_stream_id,
        &lifecycle_capsule,
        false,
    )?;
    let (_, event) = fixture.next_client_event().await?;
    if !matches!(event, h3::Event::Data) {
        return Err("Client did not receive lifecycle Capsule DATA".into());
    }
    let read =
        fixture
            .client_h3
            .recv_body(&mut fixture.client, carrier_stream_id, &mut capsule_buffer)?;
    let lifecycle_capsule_round_trip =
        server_received_capsule && decode_lifecycle_capsule(&capsule_buffer[..read]) == Some(7);

    let inner_initial = real_inner_quic_initial()?;
    let framed_initial = frame_h3_datagram(carrier_stream_id / 4, 7, &inner_initial)?;
    let datagram_ceiling = fixture
        .client
        .dgram_max_writable_len()
        .ok_or("Client did not negotiate QUIC Datagram")?;
    if framed_initial.len() > datagram_ceiling {
        return Err(format!(
            "live Datagram ceiling {datagram_ceiling} cannot carry {} bytes",
            framed_initial.len()
        )
        .into());
    }
    fixture.client.dgram_send(&framed_initial)?;
    let server_datagram = fixture.receive_server_datagram().await?;
    fixture.server.dgram_send(&framed_initial)?;
    let client_datagram = fixture.receive_client_datagram().await?;

    const WORKLOAD_DATAGRAMS: usize = 128;
    for _ in 0..WORKLOAD_DATAGRAMS {
        fixture.client.dgram_send(&framed_initial)?;
    }
    let workload_started = Instant::now();
    let concurrent_signal_started = Instant::now();
    let concurrent_signal_stream_id =
        fixture
            .client_h3
            .send_request(&mut fixture.client, &withdrawal_headers, true)?;
    loop {
        let (stream_id, event) = fixture.next_server_event().await?;
        if stream_id == concurrent_signal_stream_id && matches!(event, h3::Event::Headers { .. }) {
            break;
        }
    }
    fixture.server_h3.send_response(
        &mut fixture.server,
        concurrent_signal_stream_id,
        &[h3::Header::new(b":status", b"204")],
        true,
    )?;
    let mut concurrent_signal_status = false;
    let mut concurrent_signal_finished = false;
    while !concurrent_signal_status || !concurrent_signal_finished {
        let (stream_id, event) = fixture.next_client_event().await?;
        if stream_id != concurrent_signal_stream_id {
            continue;
        }
        match event {
            h3::Event::Headers { list, .. } => {
                concurrent_signal_status = header_value(&list, b":status") == Some(b"204");
            }
            h3::Event::Finished => concurrent_signal_finished = true,
            _ => {}
        }
    }
    let signaling_latency_with_datagrams_micros = concurrent_signal_started.elapsed().as_micros();
    let mut datagram_workload_received = 0;
    let mut workload_buffer = vec![0_u8; 65_535];
    while datagram_workload_received < WORKLOAD_DATAGRAMS {
        fixture.drive_once().await?;
        loop {
            match fixture.server.dgram_recv(&mut workload_buffer) {
                Ok(_) => datagram_workload_received += 1,
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    let workload_seconds = workload_started.elapsed().as_secs_f64();
    let datagram_workload_mbps = (datagram_workload_received * framed_initial.len() * 8) as f64
        / workload_seconds
        / 1_000_000.0;

    fixture.client.stream_shutdown(
        carrier_stream_id,
        quiche::Shutdown::Read,
        H3_REQUEST_CANCELLED,
    )?;
    fixture.client.stream_shutdown(
        carrier_stream_id,
        quiche::Shutdown::Write,
        H3_REQUEST_CANCELLED,
    )?;
    let directional_cancellation_code = loop {
        let (stream_id, event) = fixture.next_server_event().await?;
        if stream_id == carrier_stream_id
            && let h3::Event::Reset(code) = event
        {
            break code;
        }
    };

    let post_carrier_withdrawal_stream_id =
        fixture
            .client_h3
            .send_request(&mut fixture.client, &withdrawal_headers, true)?;
    loop {
        let (stream_id, event) = fixture.next_server_event().await?;
        if stream_id == post_carrier_withdrawal_stream_id
            && matches!(event, h3::Event::Headers { .. })
        {
            break;
        }
    }
    fixture.server_h3.send_response(
        &mut fixture.server,
        post_carrier_withdrawal_stream_id,
        &[h3::Header::new(b":status", b"204")],
        true,
    )?;
    let mut post_carrier_status = false;
    let mut post_carrier_finished = false;
    while !post_carrier_status || !post_carrier_finished {
        let (stream_id, event) = fixture.next_client_event().await?;
        if stream_id != post_carrier_withdrawal_stream_id {
            continue;
        }
        match event {
            h3::Event::Headers { list, .. } => {
                post_carrier_status = header_value(&list, b":status") == Some(b"204");
            }
            h3::Event::Finished => post_carrier_finished = true,
            _ => {}
        }
    }
    let carrier_cleanup_isolated_from_signaling = post_carrier_status && post_carrier_finished;

    let exact_goaway_boundary = post_carrier_withdrawal_stream_id + 4;
    fixture
        .server_h3
        .send_goaway(&mut fixture.server, exact_goaway_boundary)?;
    let (observed_goaway, event) = fixture.next_client_event().await?;
    let observed_goaway = match event {
        h3::Event::GoAway => observed_goaway,
        _ => return Err("Client did not observe GOAWAY".into()),
    };
    if observed_goaway != exact_goaway_boundary {
        return Err("GOAWAY boundary changed on wire".into());
    }

    let teardown_reached_terminal_state = fixture.close().await?;

    Ok(PrototypeReport {
        client_peer_settings,
        server_peer_settings,
        server_observed_client_identity,
        anonymous_client_rejected,
        setup_micros,
        withdrawal_stream_id,
        withdrawal_status: withdrawal_status.ok_or("missing withdrawal status")?,
        withdrawal_request_to_commit_micros,
        withdrawal_commit_to_response_micros,
        carrier_stream_id,
        carrier_setup_micros,
        lifecycle_capsule_round_trip,
        datagram_ceiling,
        framed_initial_bytes: framed_initial.len(),
        client_to_server_initial_identical: server_datagram == framed_initial,
        server_to_client_initial_identical: client_datagram == framed_initial,
        datagram_workload_sent: WORKLOAD_DATAGRAMS,
        datagram_workload_received,
        datagram_workload_mbps,
        signaling_latency_with_datagrams_micros,
        exact_goaway_boundary,
        directional_cancellation_code,
        carrier_cleanup_isolated_from_signaling,
        teardown_reached_terminal_state,
    })
}

fn require_headers(event: h3::Event, method: &[u8], path: &[u8]) -> Result<(), AnyError> {
    let h3::Event::Headers { list, .. } = event else {
        return Err(format!("expected request HEADERS, observed {event:?}").into());
    };
    if header_value(&list, b":method") != Some(method)
        || header_value(&list, b":path") != Some(path)
    {
        return Err("request HEADERS did not match adapter route".into());
    }
    Ok(())
}

fn event_header_value(event: h3::Event, name: &[u8]) -> Result<Vec<u8>, AnyError> {
    let h3::Event::Headers { list, .. } = event else {
        return Err("expected response HEADERS".into());
    };
    header_value(&list, name)
        .map(ToOwned::to_owned)
        .ok_or_else(|| "required response field missing".into())
}

fn header_value<'a>(headers: &'a [h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    use h3::NameValue;
    headers
        .iter()
        .find(|header| header.name() == name)
        .map(h3::NameValue::value)
}

fn encode_lifecycle_capsule(context_id: u8) -> Vec<u8> {
    vec![0x3f, 1, context_id]
}

fn validate_signaling_settings(settings: Option<&[(u64, u64)]>) -> Result<(), u64> {
    let Some(settings) = settings else {
        return Err(H3_MISSING_SETTINGS);
    };
    match settings
        .iter()
        .find(|(identifier, _)| *identifier == SETTINGS_RUNEWARP_SIGNALING)
    {
        None => Err(H3_GENERAL_PROTOCOL_ERROR),
        Some((_, 1)) => Ok(()),
        Some(_) => Err(H3_SETTINGS_ERROR),
    }
}

fn decode_lifecycle_capsule(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [0x3f, 1, context_id] => Some(*context_id),
        _ => None,
    }
}

fn frame_h3_datagram(
    quarter_stream_id: u64,
    context_id: u64,
    packet: &[u8],
) -> Result<Vec<u8>, AnyError> {
    let mut framed = encode_varint(quarter_stream_id)?;
    framed.extend(encode_varint(context_id)?);
    framed.extend(packet);
    Ok(framed)
}

fn encode_varint(value: u64) -> Result<Vec<u8>, AnyError> {
    if value < 64 {
        Ok(vec![value as u8])
    } else if value < 16_384 {
        Ok(((value as u16) | 0x4000).to_be_bytes().to_vec())
    } else if value < 1_073_741_824 {
        Ok(((value as u32) | 0x8000_0000).to_be_bytes().to_vec())
    } else if value < (1_u64 << 62) {
        Ok((value | 0xc000_0000_0000_0000).to_be_bytes().to_vec())
    } else {
        Err("value does not fit a QUIC variable-length integer".into())
    }
}

fn real_inner_quic_initial() -> Result<Vec<u8>, AnyError> {
    let local = localhost(10_001);
    let peer = localhost(10_002);
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"])?;
    config.set_max_send_udp_payload_size(1_200);
    let scid_bytes = [0x71; quiche::MAX_CONN_ID_LEN];
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut connection = quiche::connect(Some("inner.example"), &scid, local, peer, &mut config)?;
    let mut packet = vec![0_u8; 1_200];
    let (written, _) = connection.send(&mut packet)?;
    if written != 1_200 {
        return Err(format!("inner QUIC Initial was {written} bytes, expected 1200").into());
    }
    Ok(packet)
}

fn transport_config() -> Result<quiche::Config, AnyError> {
    let config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    finish_transport_config(config)
}

fn transport_config_with_tls(tls: SslContextBuilder) -> Result<quiche::Config, AnyError> {
    let config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
    finish_transport_config(config)
}

fn finish_transport_config(mut config: quiche::Config) -> Result<quiche::Config, AnyError> {
    config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(5_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.enable_dgram(true, 1_024, 1_024);
    Ok(config)
}

fn h3_config() -> Result<h3::Config, AnyError> {
    let mut config = h3::Config::new()?;
    config.enable_extended_connect(true);
    config.set_additional_settings(vec![
        (SETTINGS_RUNEWARP_SIGNALING, 1),
        (SETTINGS_RUNEWARP_PUBLIC_QUIC_PROTOTYPE, 1),
    ])?;
    Ok(config)
}

async fn drive_until(
    client_socket: &UdpSocket,
    server_socket: &UdpSocket,
    client: &mut quiche::Connection,
    server: &mut quiche::Connection,
    complete: impl Fn(&quiche::Connection, &quiche::Connection) -> bool,
) -> Result<(), AnyError> {
    for _ in 0..10_000 {
        drive_once(client_socket, server_socket, client, server).await?;
        if complete(client, server) {
            return Ok(());
        }
    }
    Err("timed out driving quiche connection".into())
}

async fn drive_once(
    client_socket: &UdpSocket,
    server_socket: &UdpSocket,
    client: &mut quiche::Connection,
    server: &mut quiche::Connection,
) -> Result<(), AnyError> {
    flush(client_socket, client).await?;
    flush(server_socket, server).await?;
    tokio::task::yield_now().await;
    receive(server_socket, server)?;
    receive(client_socket, client)?;
    Ok(())
}

async fn flush(socket: &UdpSocket, connection: &mut quiche::Connection) -> Result<(), AnyError> {
    let mut output = vec![0_u8; 65_535];
    loop {
        match connection.send(&mut output) {
            Ok((written, send_info)) => {
                socket.send_to(&output[..written], send_info.to).await?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive(socket: &UdpSocket, connection: &mut quiche::Connection) -> Result<(), AnyError> {
    let local = socket.local_addr()?;
    let mut input = vec![0_u8; 65_535];
    loop {
        match socket.try_recv_from(&mut input) {
            Ok((read, from)) => {
                connection.recv(&mut input[..read], quiche::RecvInfo { from, to: local })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

fn drain_h3(
    h3_connection: &mut h3::Connection,
    connection: &mut quiche::Connection,
) -> Result<(), AnyError> {
    loop {
        match h3_connection.poll(connection) {
            Ok(_) => {}
            Err(h3::Error::Done) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

fn write_certificates() -> Result<CertificatePaths, AnyError> {
    let directory = tempfile::tempdir()?;
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Runewarp quiche prototype CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()])?;
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let server_cert = server_params.signed_by(&server_key, &issuer)?;

    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::new(vec!["runewarp-client".to_owned()])?;
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client_cert = client_params.signed_by(&client_key, &issuer)?;

    let ca = write_pem(directory.path(), "ca.crt", &ca_cert.pem())?;
    let server_cert_path = write_pem(directory.path(), "server.crt", &server_cert.pem())?;
    let server_key_path = write_pem(directory.path(), "server.key", &server_key.serialize_pem())?;
    let client_cert_path = write_pem(directory.path(), "client.crt", &client_cert.pem())?;
    let client_key_path = write_pem(directory.path(), "client.key", &client_key.serialize_pem())?;

    Ok(CertificatePaths {
        _directory: directory,
        ca,
        server_cert: server_cert_path,
        server_key: server_key_path,
        client_cert: client_cert_path,
        client_key: client_key_path,
    })
}

fn write_pem(directory: &Path, name: &str, contents: &str) -> Result<String, AnyError> {
    let path = directory.join(name);
    fs::write(&path, contents)?;
    Ok(path.to_string_lossy().into_owned())
}

const fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let report = run_settings_scenario().await?;
    println!("PROTOTYPE quiche H3 signaling\n{report:#?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_network_vertical_slice_exercises_signaling_and_carrier() {
        let report = run_settings_scenario().await.unwrap();

        assert!(report.server_observed_client_identity);
        assert!(report.anonymous_client_rejected);
        assert!(
            report
                .client_peer_settings
                .contains(&(SETTINGS_RUNEWARP_SIGNALING, 1))
        );
        assert!(report.setup_micros > 0);
        assert!(
            report
                .server_peer_settings
                .contains(&(SETTINGS_RUNEWARP_SIGNALING, 1))
        );
        assert_eq!(report.withdrawal_stream_id, 0);
        assert_eq!(report.withdrawal_status, 204);
        assert!(report.withdrawal_request_to_commit_micros > 0);
        assert!(report.withdrawal_commit_to_response_micros > 0);
        assert_eq!(report.carrier_stream_id, 4);
        assert!(report.carrier_setup_micros > 0);
        assert!(report.lifecycle_capsule_round_trip);
        assert!(report.datagram_ceiling >= report.framed_initial_bytes);
        assert_eq!(report.framed_initial_bytes, 1_202);
        assert!(report.client_to_server_initial_identical);
        assert!(report.server_to_client_initial_identical);
        assert_eq!(report.datagram_workload_sent, 128);
        assert_eq!(report.datagram_workload_received, 128);
        assert!(report.datagram_workload_mbps > 0.0);
        assert!(report.signaling_latency_with_datagrams_micros > 0);
        assert_eq!(report.exact_goaway_boundary, 16);
        assert_eq!(report.directional_cancellation_code, H3_REQUEST_CANCELLED);
        assert!(report.carrier_cleanup_isolated_from_signaling);
        assert!(report.teardown_reached_terminal_state);
    }

    #[test]
    fn mandatory_signaling_settings_map_to_settled_h3_errors() {
        assert_eq!(validate_signaling_settings(None), Err(H3_MISSING_SETTINGS));
        assert_eq!(
            validate_signaling_settings(Some(&[])),
            Err(H3_GENERAL_PROTOCOL_ERROR)
        );
        assert_eq!(
            validate_signaling_settings(Some(&[(SETTINGS_RUNEWARP_SIGNALING, 2)])),
            Err(H3_SETTINGS_ERROR)
        );
        assert_eq!(
            validate_signaling_settings(Some(&[(SETTINGS_RUNEWARP_SIGNALING, 1)])),
            Ok(())
        );
    }
}
