//! Receive-slot carrier tests: assignment, replenishment, limits, abort, load, and shutdown.

use std::sync::Arc;
use std::time::Duration;

use h3::error::Code;
use http::{Method, Request, StatusCode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

use super::{
    Fixture, RawSendRequest, STEP, establish_pair, fast_timing, raw_client, server_hostname,
};
use crate::tunnel_h3::events::ServerRuntimeGeneration;
use crate::tunnel_h3::{
    ClientTunnelH3, MAX_IDLE_RECEIVE_SLOTS, OpenTunnelStreamError, ServerTunnelH3,
};

fn budget(permits: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(permits))
}

async fn slot_pair(permits: usize) -> (Fixture, ServerTunnelH3, ClientTunnelH3) {
    let fixture = Fixture::new().expect("fixture");
    let (server, client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        budget(permits),
    )
    .await;
    (fixture, server, client)
}

async fn wait_for_idle_slots(server: &ServerTunnelH3, count: usize) {
    timeout(STEP, async {
        while server.idle_receive_slots() < count {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the Client offers receive slots");
}

#[tokio::test]
async fn assignment_delivers_initial_bytes_without_a_client_round_trip_and_half_closes() {
    let (_fixture, server, mut client) = slot_pair(4).await;

    let mut server_stream = server
        .open_tunnel_stream(STEP)
        .await
        .expect("a slot is assigned");
    server_stream
        .write_all(b"framing+client-hello")
        .await
        .expect("initial bytes sent");
    server_stream.flush().await.expect("initial bytes flushed");
    let mut client_stream = timeout(STEP, client.accept_tunnel_stream())
        .await
        .expect("assignment arrives")
        .expect("connection open");

    let mut initial = [0_u8; 20];
    client_stream
        .read_exact(&mut initial)
        .await
        .expect("initial bytes arrive");
    assert_eq!(&initial, b"framing+client-hello");

    client_stream
        .write_all(b"server-hello")
        .await
        .expect("Client bytes sent");
    client_stream.shutdown().await.expect("Client FIN");
    let mut from_client = Vec::new();
    server_stream
        .read_to_end(&mut from_client)
        .await
        .expect("Server reads to Client FIN");
    assert_eq!(from_client, b"server-hello");

    // The Server direction stays open after the Client's FIN.
    server_stream
        .write_all(b"late")
        .await
        .expect("Server bytes after half-close");
    server_stream.shutdown().await.expect("Server FIN");
    let mut from_server = Vec::new();
    client_stream
        .read_to_end(&mut from_server)
        .await
        .expect("Client reads to Server FIN");
    assert_eq!(from_server, b"late");
}

#[tokio::test]
async fn the_client_budget_bounds_slots_and_released_streams_are_replenished() {
    let (_fixture, server, mut client) = slot_pair(2).await;

    let first = server.open_tunnel_stream(STEP).await.expect("first slot");
    let _second = server.open_tunnel_stream(STEP).await.expect("second slot");
    assert_eq!(
        server
            .open_tunnel_stream(Duration::from_millis(200))
            .await
            .err(),
        Some(OpenTunnelStreamError::TimedOut)
    );

    // Releasing one Tunnel stream on both sides returns its permit to the budget.
    let client_first = client.accept_tunnel_stream().await.expect("first stream");
    drop((first, client_first));

    server
        .open_tunnel_stream(STEP)
        .await
        .expect("a replenished slot is assigned");
}

#[tokio::test]
async fn two_tunnel_connections_share_receive_slot_budget() {
    timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new().expect("fixture");
        let budget = crate::client::ClientStreamBudget::new(crate::client::ClientStreamLimits {
            max_stream_handlers: 2,
            ..crate::client::ClientStreamLimits::default()
        });
        let (first_server, first_client) = establish_pair(
            &fixture,
            ServerRuntimeGeneration::generate(),
            budget.semaphore(),
        )
        .await;
        wait_for_idle_slots(&first_server, 2).await;

        let (second_server, mut second_client) = establish_pair(
            &fixture,
            ServerRuntimeGeneration::generate(),
            budget.semaphore(),
        )
        .await;
        assert_eq!(
            second_server
                .open_tunnel_stream(Duration::from_millis(200))
                .await
                .err(),
            Some(OpenTunnelStreamError::TimedOut),
            "the first connection holds every permit"
        );
        assert_eq!(second_server.idle_receive_slots(), 0);

        drop(first_client);
        wait_for_idle_slots(&second_server, 2).await;
        let _server_stream = second_server.open_tunnel_stream(STEP).await.expect("slot");
        let _client_stream = second_client
            .accept_tunnel_stream()
            .await
            .expect("assigned");
    })
    .await
    .expect("shared budget releases and replenishes promptly");
}

#[tokio::test]
async fn the_client_keeps_at_most_the_idle_slot_cap_open() {
    let (_fixture, server, _client) = slot_pair(MAX_IDLE_RECEIVE_SLOTS * 2).await;

    wait_for_idle_slots(&server, MAX_IDLE_RECEIVE_SLOTS).await;
    sleep(Duration::from_millis(50)).await;

    assert_eq!(server.idle_receive_slots(), MAX_IDLE_RECEIVE_SLOTS);
}

async fn open_raw_slot(send_request: &mut RawSendRequest) -> super::RawClientStream {
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("{}:443", super::SERVER_NAME))
        .body(())
        .expect("valid CONNECT request");
    send_request
        .send_request(request)
        .await
        .expect("slot request opens")
}

#[tokio::test]
async fn the_server_rejects_slots_beyond_the_idle_cap() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (server, (mut send_request, _driver)) = tokio::join!(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate(),
            fast_timing(),
        ),
        raw_client(client_connection),
    );
    let server = server.expect("server establishes");

    let mut slots = Vec::new();
    for _ in 0..MAX_IDLE_RECEIVE_SLOTS {
        slots.push(open_raw_slot(&mut send_request).await);
    }
    wait_for_idle_slots(&server, MAX_IDLE_RECEIVE_SLOTS).await;
    let mut extra = open_raw_slot(&mut send_request).await;

    let rejected = timeout(STEP, extra.recv_response())
        .await
        .expect("the extra slot resolves");
    assert!(
        matches!(
            rejected,
            Err(h3::error::StreamError::RemoteTerminate { code, .. })
                if code == Code::H3_REQUEST_REJECTED
        ),
        "{rejected:?}"
    );
    assert_eq!(server.idle_receive_slots(), MAX_IDLE_RECEIVE_SLOTS);
}

#[tokio::test]
async fn an_abandoned_idle_slot_is_skipped_for_the_next_one() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (server, (mut send_request, _driver)) = tokio::join!(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate(),
            fast_timing(),
        ),
        raw_client(client_connection),
    );
    let server = server.expect("server establishes");

    let mut abandoned = open_raw_slot(&mut send_request).await;
    let mut live = open_raw_slot(&mut send_request).await;
    wait_for_idle_slots(&server, 2).await;
    abandoned.stop_sending(Code::H3_REQUEST_CANCELLED);
    abandoned.stop_stream(Code::H3_REQUEST_CANCELLED);
    sleep(Duration::from_millis(100)).await;

    let mut server_stream = server.open_tunnel_stream(STEP).await.expect("live slot");
    server_stream.write_all(b"visitor").await.expect("sent");
    server_stream.flush().await.expect("flushed");

    let response = timeout(STEP, live.recv_response())
        .await
        .expect("the live slot is assigned")
        .expect("valid response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn dropping_a_half_without_shutdown_resets_only_that_stream() {
    let (_fixture, server, mut client) = slot_pair(4).await;

    let server_stream = server.open_tunnel_stream(STEP).await.expect("first slot");
    let mut client_stream = client.accept_tunnel_stream().await.expect("first stream");
    let (_server_read, mut server_write) = server_stream.into_split();
    server_write.write_all(b"partial").await.expect("sent");
    server_write.flush().await.expect("flushed");
    drop(server_write);

    let mut received = Vec::new();
    let result = timeout(STEP, client_stream.read_to_end(&mut received))
        .await
        .expect("the Client observes the end");
    assert!(
        result.is_err(),
        "an aborted Visitor must not look like a clean end; read {received:?}"
    );

    // Other slots and the connection are unaffected.
    let mut other = server.open_tunnel_stream(STEP).await.expect("next slot");
    other.write_all(b"ok").await.expect("sent");
    other.flush().await.expect("flushed");
    let mut other_client = client.accept_tunnel_stream().await.expect("next stream");
    let mut ok = [0_u8; 2];
    other_client.read_exact(&mut ok).await.expect("received");
    assert_eq!(&ok, b"ok");
}

#[tokio::test]
async fn large_transfers_survive_a_slow_reader_in_both_directions() {
    const SIZE: usize = 8 * 1024 * 1024;
    let (_fixture, server, mut client) = slot_pair(4).await;
    let payload: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
    let expected = Sha256::digest(&payload);

    let server_stream = server.open_tunnel_stream(STEP).await.expect("slot");
    let client_stream = client.accept_tunnel_stream().await.expect("stream");
    let (mut server_read, mut server_write) = server_stream.into_split();
    let (mut client_read, mut client_write) = client_stream.into_split();

    let to_client = payload.clone();
    let server_sends = tokio::spawn(async move {
        server_write
            .write_all(&to_client)
            .await
            .expect("Server sends");
        server_write.shutdown().await.expect("Server FIN");
    });
    let to_server = payload.clone();
    let client_sends = tokio::spawn(async move {
        client_write
            .write_all(&to_server)
            .await
            .expect("Client sends");
        client_write.shutdown().await.expect("Client FIN");
    });
    // The Client reads slowly, in small pieces.
    let client_reads = tokio::spawn(async move {
        let mut received = Vec::with_capacity(SIZE);
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = client_read.read(&mut buffer).await.expect("Client reads");
            if read == 0 {
                return received;
            }
            received.extend_from_slice(&buffer[..read]);
            if received.len() % (512 * 1024) < buffer.len() {
                sleep(Duration::from_millis(5)).await;
            }
        }
    });
    let mut server_received = Vec::with_capacity(SIZE);
    timeout(
        Duration::from_secs(30),
        server_read.read_to_end(&mut server_received),
    )
    .await
    .expect("Server receives everything")
    .expect("Server reads");

    let client_received = timeout(Duration::from_secs(30), client_reads)
        .await
        .expect("Client receives everything")
        .expect("Client reader task");
    timeout(STEP, server_sends)
        .await
        .expect("Server send finishes")
        .expect("Server send task");
    timeout(STEP, client_sends)
        .await
        .expect("Client send finishes")
        .expect("Client send task");
    assert_eq!(Sha256::digest(&client_received), expected);
    assert_eq!(Sha256::digest(&server_received), expected);
}

#[tokio::test]
async fn shutdown_rejects_idle_slots_and_lets_open_tunnel_streams_finish() {
    let (_fixture, server, mut client) = slot_pair(8).await;
    let mut server_stream = server.open_tunnel_stream(STEP).await.expect("slot");
    let mut client_stream = client.accept_tunnel_stream().await.expect("stream");

    let shutdown = tokio::spawn(async move { server.shutdown(STEP).await });

    // No further Visitors arrive once GOAWAY rejects the idle slots.
    assert!(
        timeout(STEP, client.accept_tunnel_stream())
            .await
            .expect("the slot pool winds down")
            .is_none()
    );

    // The already-placed Visitor still completes in both directions.
    client_stream.write_all(b"still").await.expect("sent");
    client_stream.shutdown().await.expect("Client FIN");
    let mut received = Vec::new();
    server_stream
        .read_to_end(&mut received)
        .await
        .expect("Server reads");
    assert_eq!(received, b"still");
    server_stream.shutdown().await.expect("Server FIN");
    let mut tail = Vec::new();
    client_stream
        .read_to_end(&mut tail)
        .await
        .expect("Client reads");
    drop((server_stream, client_stream));

    timeout(STEP, shutdown)
        .await
        .expect("shutdown finishes once the Tunnel stream ends")
        .expect("shutdown task");
}

#[tokio::test]
async fn a_closed_connection_opens_no_tunnel_streams() {
    let (_fixture, server, client) = slot_pair(4).await;
    drop(client);
    timeout(STEP, async {
        while server
            .open_tunnel_stream(Duration::from_millis(50))
            .await
            .err()
            != Some(OpenTunnelStreamError::Closed)
        {}
    })
    .await
    .expect("the Server observes the closed connection");
}

#[tokio::test]
async fn idle_slots_are_released_when_the_connection_ends() {
    // Remote disconnect with the Server handle still held: the queue empties.
    let (_fixture, server, client) = slot_pair(8).await;
    wait_for_idle_slots(&server, 8).await;
    drop(client);
    timeout(STEP, async {
        while server.idle_receive_slots() > 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("idle slots are released after a remote disconnect");

    // Dropping the Server handle frees all connection state, queued slots included.
    let (_fixture, server, _client) = slot_pair(8).await;
    wait_for_idle_slots(&server, 8).await;
    let shared = server.shared_state_for_test();
    drop(server);
    timeout(STEP, async {
        while shared.upgrade().is_some() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection state is freed after the handle drops");
}
