//! PROTOTYPE — throwaway Public QUIC MTU/framing packet lab for issue #180.
//!
//! Question: can a live Quinn QUIC DATAGRAM carry one complete 1200-byte inner
//! QUIC Initial after the HTTP/3 Quarter Stream ID and Runewarp Context ID are
//! prepended, and where do QUIC variable-length integer width cliffs change the
//! answer?
//!
//! Run with: cargo run --example public_quic_mtu_prototype

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::{Connection, Endpoint, SendDatagramError, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const SERVER_NAME: &str = "public-quic-mtu.prototype";
const INNER_INITIAL_MINIMUM: usize = 1200;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);
const DATAGRAM_BUFFER: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct FramingCase {
    quarter_stream_id: u64,
    context_id: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("PROTOTYPE — Public QUIC live MTU/framing packet lab");
    println!(
        "Question: does Quarter Stream ID + Context ID + one 1200-byte inner QUIC Initial fit?"
    );
    println!(
        "Scope: measured on IPv4 loopback with Quinn 0.11.11; not a general path-MTU claim.\n"
    );

    let (certificate, private_key) = certificate()?;
    let inner_initial = capture_real_quic_initial(&certificate).await?;
    println!("Captured inner input");
    println!("  UDP payload bytes: {}", inner_initial.len());
    let version = u32::from_be_bytes(inner_initial[1..5].try_into()?);
    println!(
        "  QUIC version / long-header / fixed / v1 Initial type: {version:#010x} / {} / {} / {}",
        inner_initial[0] & 0x80 != 0,
        inner_initial[0] & 0x40 != 0,
        inner_initial[0] & 0x30 == 0
    );
    println!(
        "  Meaning: a real Quinn-generated QUIC Initial UDP payload, carried unchanged below\n"
    );

    print_varint_cliffs();
    run_profile(
        "conservative outer estimate",
        1200,
        certificate.clone(),
        private_key.clone_key(),
        inner_initial.clone(),
    )
    .await?;
    run_profile(
        "explicit loopback lab estimate",
        1452,
        certificate,
        private_key,
        inner_initial,
    )
    .await?;

    println!("Verdict");
    println!("  Quinn max_datagram_size is the application DATAGRAM payload ceiling.");
    println!(
        "  The application payload includes both H3/Runewarp varints and the complete inner packet."
    );
    println!("  A 1200-byte outer QUIC UDP estimate cannot nest a 1200-byte inner Initial.");
    println!("  The 1452-byte configured loopback estimate can in this run, in both directions.");
    println!(
        "  TooLarge is an unreliable-packet drop here. No stream or DATAGRAM-Capsule fallback exists."
    );
    println!("  Still unresolved: real Internet/VPN paths, PMTU changes, and inner-PMTU feedback.");
    Ok(())
}

async fn capture_real_quic_initial(
    certificate: &CertificateDer<'static>,
) -> Result<Bytes, Box<dyn Error>> {
    let capture_socket = UdpSocket::bind(localhost(0)).await?;
    let capture_address = capture_socket.local_addr()?;
    let mut endpoint = Endpoint::client(localhost(0))?;
    endpoint.set_default_client_config(client_config(certificate, 1200)?);
    let connecting = endpoint.connect(capture_address, SERVER_NAME)?;
    let connection_task = tokio::spawn(connecting);
    let mut buffer = vec![0_u8; 2048];
    let (length, _) = timeout(RECEIVE_TIMEOUT, capture_socket.recv_from(&mut buffer)).await??;
    connection_task.abort();
    endpoint.close(0_u8.into(), b"prototype capture complete");
    buffer.truncate(length);
    if length != INNER_INITIAL_MINIMUM {
        return Err(format!("expected a 1200-byte Quinn Initial, captured {length} bytes").into());
    }
    if buffer[0] & 0xc0 != 0xc0 || buffer[0] & 0x30 != 0 || buffer[1..5] != 1_u32.to_be_bytes() {
        return Err("captured payload was not a QUIC v1 Initial".into());
    }
    Ok(Bytes::from(buffer))
}

fn print_varint_cliffs() {
    println!("Framing budget (RFC 9297 payload = Quarter Stream ID + extension payload)");
    println!("  Quarter Stream ID and provisional Runewarp Context ID use QUIC varints.");
    println!("  representative value                each width    both IDs    framed Initial");
    for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
        let width = varint_width(value);
        println!(
            "  {value:<35} {width:<13} {:<11} {}",
            width * 2,
            INNER_INITIAL_MINIMUM + width * 2
        );
    }
    println!();
}

async fn run_profile(
    name: &str,
    initial_mtu: u16,
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    inner_initial: Bytes,
) -> Result<(), Box<dyn Error>> {
    let server_endpoint = Endpoint::server(
        server_config(certificate.clone(), private_key, initial_mtu)?,
        localhost(0),
    )?;
    let server_address = server_endpoint.local_addr()?;
    let accept_endpoint = server_endpoint.clone();
    let accept_task = tokio::spawn(async move {
        accept_endpoint
            .accept()
            .await
            .ok_or("server endpoint closed")?
            .await
            .map_err(|error| error.to_string())
    });

    let mut client_endpoint = Endpoint::client(localhost(0))?;
    client_endpoint.set_default_client_config(client_config(&certificate, initial_mtu)?);
    let client = timeout(
        RECEIVE_TIMEOUT,
        client_endpoint.connect(server_address, SERVER_NAME)?,
    )
    .await??;
    let server = timeout(RECEIVE_TIMEOUT, accept_task).await???;

    println!("Live profile: {name}");
    println!("  configured initial outer QUIC UDP estimate: {initial_mtu}");
    run_direction("Client -> Server", &client, &server, &inner_initial).await?;
    run_direction("Server -> Client", &server, &client, &inner_initial).await?;

    client.close(0_u8.into(), b"prototype complete");
    server_endpoint.close(0_u8.into(), b"prototype complete");
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    println!();
    Ok(())
}

async fn run_direction(
    label: &str,
    sender: &Connection,
    receiver: &Connection,
    inner_initial: &Bytes,
) -> Result<(), Box<dyn Error>> {
    let max = sender
        .max_datagram_size()
        .ok_or("live peer did not negotiate QUIC DATAGRAM")?;
    println!("  {label}");
    println!("    live Quinn application DATAGRAM ceiling: {max}");

    for case in [
        FramingCase {
            quarter_stream_id: 0,
            context_id: 0,
        },
        FramingCase {
            quarter_stream_id: 63,
            context_id: 63,
        },
        FramingCase {
            quarter_stream_id: 64,
            context_id: 64,
        },
        FramingCase {
            quarter_stream_id: 16_384,
            context_id: 16_384,
        },
    ] {
        let framed = frame(case, inner_initial);
        let expected = framed.clone();
        let result = sender.send_datagram(framed);
        match result {
            Ok(()) => {
                let received = timeout(RECEIVE_TIMEOUT, receiver.read_datagram()).await??;
                if received != expected {
                    return Err("received DATAGRAM did not preserve framing or inner packet".into());
                }
                println!(
                    "    qsid={} ({}B), context={} ({}B): {}B -> success, received unchanged",
                    case.quarter_stream_id,
                    varint_width(case.quarter_stream_id),
                    case.context_id,
                    varint_width(case.context_id),
                    expected.len()
                );
            }
            Err(SendDatagramError::TooLarge) => println!(
                "    qsid={} ({}B), context={} ({}B): {}B -> TooLarge, dropped; no reliable fallback",
                case.quarter_stream_id,
                varint_width(case.quarter_stream_id),
                case.context_id,
                varint_width(case.context_id),
                expected.len()
            ),
            Err(error) => return Err(format!("unexpected DATAGRAM send error: {error}").into()),
        }
    }

    match sender.send_datagram(Bytes::from(vec![0_u8; max + 1])) {
        Err(SendDatagramError::TooLarge) => {
            println!("    ceiling + 1 ({}B): TooLarge, as reported", max + 1);
        }
        result => return Err(format!("ceiling + 1 did not return TooLarge: {result:?}").into()),
    }
    Ok(())
}

fn frame(case: FramingCase, inner_initial: &Bytes) -> Bytes {
    let mut framed = Vec::with_capacity(
        varint_width(case.quarter_stream_id) + varint_width(case.context_id) + inner_initial.len(),
    );
    encode_varint(case.quarter_stream_id, &mut framed);
    encode_varint(case.context_id, &mut framed);
    framed.extend_from_slice(inner_initial);
    Bytes::from(framed)
}

fn varint_width(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        1_073_741_824..=4_611_686_018_427_387_903 => 8,
        _ => panic!("prototype input exceeds the QUIC varint range"),
    }
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    let width = varint_width(value);
    let prefix = width.trailing_zeros() as u64;
    let encoded = value | (prefix << (width * 8 - 2));
    output.extend_from_slice(&encoded.to_be_bytes()[8 - width..]);
}

fn server_config(
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    initial_mtu: u16,
) -> Result<quinn::ServerConfig, Box<dyn Error>> {
    let mut config = runewarp::make_server_quic_config(vec![certificate], private_key)?;
    config.transport = transport(initial_mtu);
    Ok(config)
}

fn client_config(
    certificate: &CertificateDer<'static>,
    initial_mtu: u16,
) -> Result<quinn::ClientConfig, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    let mut config = runewarp::make_client_quic_config(roots)?;
    config.transport_config(transport(initial_mtu));
    Ok(config)
}

fn transport(initial_mtu: u16) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport
        .initial_mtu(initial_mtu)
        .mtu_discovery_config(None)
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_BUFFER);
    Arc::new(transport)
}

fn certificate() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn Error>> {
    let certified = generate_simple_self_signed(vec![SERVER_NAME.to_owned()])?;
    Ok((
        CertificateDer::from(certified.cert),
        PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    ))
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
