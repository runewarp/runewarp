//! PROTOTYPE — throwaway Public QUIC CID/rebinding packet lab for #180.
//!
//! Question: can an opaque, multi-session Server route the first packet after a Visitor changes
//! address when the backend also rotates its QUIC Connection ID (CID)? This deliberately uses a
//! permissive one-session relay so the real QUIC connection can survive. Alongside forwarding, it
//! evaluates the stricter lookup an actual Server would need.
//!
//! Run: cargo run --example public_quic_cid_rebinding_prototype
//!
//! Standards read with the result: RFC 9000 §§5.1, 9, 17.3; RFC 8999 §§5.2–5.3;
//! RFC 9001 §5. Packet payload protection hides NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, and
//! stateless-reset tokens from the relay; the Destination Connection ID remains visible.

use std::collections::HashSet;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, watch};

const CID_LEN: usize = 8; // Quinn's default generator in the pinned 0.11 release.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Handshake,
    StablePath,
    ReboundPath,
    SyntheticProbe,
    Finished,
}

#[derive(Debug)]
struct Observation {
    phase: Phase,
    source: SocketAddr,
    destination_cid: Option<Vec<u8>>,
    known_before_packet: bool,
    route_basis: &'static str,
    bytes: usize,
}

#[derive(Debug, Default)]
struct RelayState {
    original_visitor: Option<SocketAddr>,
    current_visitor: Option<SocketAddr>,
    learned_cids: HashSet<Vec<u8>>,
    observations: Vec<Observation>,
    first_rebound_packet: Option<(SocketAddr, Option<Vec<u8>>, bool)>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("PROTOTYPE — Public QUIC CID rotation and same-Server rebinding packet lab");
    println!("Question: can an opaque edge map a new source address plus a newly rotated DCID?");
    println!("Scope: QUIC v1-shaped headers, Quinn 0.11 default 8-byte CIDs, one local session.\n");

    let (server_config, client_config) = configs()?;
    let backend = Endpoint::server(server_config, localhost(0))?;
    let backend_address = backend.local_addr()?;

    let relay_socket = Arc::new(UdpSocket::bind(localhost(0)).await?);
    let relay_address = relay_socket.local_addr()?;
    let state = Arc::new(Mutex::new(RelayState::default()));
    let (phase_tx, phase_rx) = watch::channel(Phase::Handshake);
    let rebound_seen = Arc::new(Notify::new());
    let relay_task = tokio::spawn(run_opaque_relay(
        relay_socket,
        backend_address,
        phase_rx,
        Arc::clone(&state),
        Arc::clone(&rebound_seen),
    ));

    let backend_task = tokio::spawn(async move {
        let connection = backend
            .accept()
            .await
            .ok_or("backend endpoint closed")?
            .await?;
        let stable_id = connection.stable_id();
        let initial_remote = connection.remote_address();

        // Make post-handshake packets flow before and after the Visitor socket change.
        let mut first = connection.open_uni().await?;
        first.write_all(b"stable-path").await?;
        first.finish()?;
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut second = connection.open_uni().await?;
        second.write_all(b"rebound-path").await?;
        second.finish()?;
        tokio::time::sleep(Duration::from_millis(300)).await;

        Ok::<_, Box<dyn Error + Send + Sync>>((
            stable_id,
            initial_remote,
            connection.remote_address(),
            connection.stats(),
        ))
    });

    let mut visitor = Endpoint::client(localhost(0))?;
    visitor.set_default_client_config(client_config);
    let connection = visitor.connect(relay_address, "localhost")?.await?;
    let visitor_stable_id = connection.stable_id();

    let mut first = connection.accept_uni().await?;
    let first_payload = first.read_to_end(64).await?;
    phase_tx.send_replace(Phase::StablePath);
    // Generate an address-stable packet, allowing the relay to learn any visible server CID.
    connection.force_key_update();
    tokio::time::sleep(Duration::from_millis(120)).await;

    let old_address = visitor.local_addr()?;
    phase_tx.send_replace(Phase::ReboundPath);
    visitor.rebind(StdUdpSocket::bind(localhost(0))?)?;
    let new_address = visitor.local_addr()?;
    let mut second = connection.accept_uni().await?;
    let second_payload = second.read_to_end(64).await?;
    tokio::time::timeout(Duration::from_secs(2), rebound_seen.notified()).await?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Two concrete edge inputs. An opaque edge can parse their DCIDs, but encrypted
    // RETIRE_CONNECTION_ID frames do not tell it which previously observed value is retired.
    phase_tx.send_replace(Phase::SyntheticProbe);
    let (known_cid, unknown_cid) = {
        let locked = state.lock().expect("relay state mutex poisoned");
        let known = locked
            .learned_cids
            .iter()
            .find(|cid| cid.len() == CID_LEN)
            .cloned()
            .unwrap_or_else(|| vec![0x11; CID_LEN]);
        (known, vec![0xee; CID_LEN])
    };
    let probe = StdUdpSocket::bind(localhost(0))?;
    probe.send_to(&short_header_packet(&known_cid), relay_address)?;
    probe.send_to(&short_header_packet(&unknown_cid), relay_address)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    phase_tx.send_replace(Phase::Finished);
    let backend_result = backend_task.await??;
    relay_task.abort();

    let visitor_stats = connection.stats();
    let locked = state.lock().expect("relay state mutex poisoned");
    print_report(
        &locked,
        old_address,
        new_address,
        visitor_stable_id,
        &first_payload,
        &second_payload,
        backend_result,
        visitor_stats,
    );
    Ok(())
}

async fn run_opaque_relay(
    socket: Arc<UdpSocket>,
    backend: SocketAddr,
    phase: watch::Receiver<Phase>,
    state: Arc<Mutex<RelayState>>,
    rebound_seen: Arc<Notify>,
) {
    let mut buffer = vec![0_u8; 65_535];
    while *phase.borrow() != Phase::Finished {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let current_phase = *phase.borrow();
        if source == backend {
            let visitor = state
                .lock()
                .expect("relay state mutex poisoned")
                .current_visitor;
            if let Some(visitor) = visitor {
                let _ = socket.send_to(&buffer[..length], visitor).await;
            }
            continue;
        }

        let destination_cid = visible_destination_cid(&buffer[..length]);
        let (known, route_basis, first_rebound) = {
            let mut locked = state.lock().expect("relay state mutex poisoned");
            let original = *locked.original_visitor.get_or_insert(source);
            let known = destination_cid
                .as_ref()
                .is_some_and(|cid| locked.learned_cids.contains(cid));
            let same_tuple = source == original;
            let route_basis = if known {
                "visible DCID"
            } else if same_tuple {
                "source tuple continuity"
            } else {
                "none in a multi-session relay"
            };
            if same_tuple && let Some(cid) = &destination_cid {
                locked.learned_cids.insert(cid.clone());
            }
            locked.current_visitor = Some(source);
            let first_rebound = current_phase == Phase::ReboundPath
                && source != original
                && locked.first_rebound_packet.is_none();
            if first_rebound {
                locked.first_rebound_packet = Some((source, destination_cid.clone(), known));
            }
            locked.observations.push(Observation {
                phase: current_phase,
                source,
                destination_cid,
                known_before_packet: known,
                route_basis,
                bytes: length,
            });
            (known, route_basis, first_rebound)
        };

        // Intentional cheat: a single-session relay can forward even when neither address nor
        // CID maps. A production multi-session Server cannot use this fallback safely.
        let _ = (known, route_basis);
        let _ = socket.send_to(&buffer[..length], backend).await;
        if first_rebound {
            rebound_seen.notify_one();
        }
    }
}

fn visible_destination_cid(packet: &[u8]) -> Option<Vec<u8>> {
    let first = *packet.first()?;
    if first & 0x80 != 0 {
        let cid_length = *packet.get(5)? as usize;
        let start = 6;
        return packet.get(start..start + cid_length).map(ToOwned::to_owned);
    }
    packet.get(1..1 + CID_LEN).map(ToOwned::to_owned)
}

fn short_header_packet(cid: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + cid.len() + 8);
    packet.push(0x40);
    packet.extend_from_slice(cid);
    packet.extend_from_slice(&[0x55; 8]);
    packet
}

fn configs() -> Result<(ServerConfig, ClientConfig), Box<dyn Error + Send + Sync>> {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let server = ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let client = ClientConfig::with_root_certificates(Arc::new(roots))?;
    Ok((server, client))
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

#[allow(clippy::too_many_arguments)]
fn print_report(
    state: &RelayState,
    old_address: SocketAddr,
    new_address: SocketAddr,
    visitor_stable_id: usize,
    first_payload: &[u8],
    second_payload: &[u8],
    backend: (usize, SocketAddr, SocketAddr, quinn::ConnectionStats),
    visitor_stats: quinn::ConnectionStats,
) {
    println!("MEASURED — real QUIC through an opaque UDP relay");
    println!("  Visitor address: {old_address} -> {new_address}");
    println!("  Visitor connection stable ID: {visitor_stable_id}");
    println!("  Backend connection stable ID: {}", backend.0);
    println!(
        "  Backend peer address: {} -> {} (the relay remains its peer)",
        backend.1, backend.2
    );
    println!(
        "  Payload before rebind: {:?}",
        String::from_utf8_lossy(first_payload)
    );
    println!(
        "  Payload after rebind:  {:?}",
        String::from_utf8_lossy(second_payload)
    );
    println!(
        "  Visitor frames: PATH_CHALLENGE={} PATH_RESPONSE={} NEW_CONNECTION_ID={} RETIRE_CONNECTION_ID={}",
        visitor_stats.frame_tx.path_challenge,
        visitor_stats.frame_tx.path_response,
        visitor_stats.frame_rx.new_connection_id,
        visitor_stats.frame_tx.retire_connection_id,
    );
    println!(
        "  Backend frames: PATH_CHALLENGE={} PATH_RESPONSE={} NEW_CONNECTION_ID={} RETIRE_CONNECTION_ID={}",
        backend.3.frame_tx.path_challenge,
        backend.3.frame_tx.path_response,
        backend.3.frame_tx.new_connection_id,
        backend.3.frame_rx.retire_connection_id,
    );

    println!("\nOPAQUE SERVER VIEW — every Visitor-to-backend UDP datagram");
    for (index, event) in state.observations.iter().enumerate() {
        println!(
            "  {:02} phase={:?} src={} bytes={} dcid={} known-before={} strict-route={}",
            index + 1,
            event.phase,
            event.source,
            event.bytes,
            event
                .destination_cid
                .as_deref()
                .map(hex)
                .unwrap_or_else(|| "unparseable".to_owned()),
            event.known_before_packet,
            event.route_basis,
        );
    }

    println!("\nVERDICT");
    match &state.first_rebound_packet {
        Some((source, cid, true)) => println!(
            "  Measured: first packet from {source} used already-known DCID {}. CID lookup can preserve same-Server rebinding in this run.",
            cid.as_deref().map(hex).unwrap_or_else(|| "none".to_owned())
        ),
        Some((source, cid, false)) => println!(
            "  Measured: first packet from {source} used unknown DCID {}. Source tuple and CID changed together; a strict multi-session opaque relay had no association key.",
            cid.as_deref().map(hex).unwrap_or_else(|| "none".to_owned())
        ),
        None => println!("  Inconclusive: no first packet from the rebound address was captured."),
    }
    println!(
        "  Measured: encrypted frame counters show CID issuance/retirement activity, but the relay cannot see the CID values in NEW_CONNECTION_ID or RETIRE_CONNECTION_ID."
    );
    println!(
        "  Measured: the QUIC endpoint survived only because this one-session relay deliberately forwarded packets that strict routing marked unmappable."
    );
    println!(
        "  Measured: the backend's peer tuple stayed equal to the relay and no PATH_CHALLENGE/PATH_RESPONSE was emitted; endpoint path validation therefore did not validate the Visitor-to-relay association."
    );
    println!(
        "  Inference: robust multi-session rebinding needs endpoint/load-balancer cooperation: edge-routable server-issued CIDs, an authenticated CID-registration signal, or an explicit non-goal for rotations that coincide with tuple change."
    );
    println!(
        "  Inference: an old visible CID cannot safely be labelled retired by the opaque relay, and an unknown CID must not be guessed across sessions. Stateless reset generation/validation remains endpoint-owned."
    );
    println!("\nLIMITS");
    println!(
        "  Loopback only; no NAT, load balancer, loss, Retry, stateless reset validation, or multiple concurrent sessions."
    );
    println!(
        "  Header parsing assumes Quinn's pinned 8-byte short-header CID convention; QUIC short headers do not encode CID length."
    );
    println!(
        "  Synthetic known/unknown packets exercise observable lookup inputs, not valid encrypted QUIC packets."
    );
    println!("  Standards: RFC 9000 §§5.1,9,17.3; RFC 8999 §§5.2-5.3; RFC 9001 §5.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
