//! WebTransport Visitor carrier tests: assignment, replenishment, limits, abort, load, and shutdown.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

use super::{Fixture, STEP, establish_pair, fast_timing, server_hostname};
use crate::tunnel_h3::events::ServerRuntimeGeneration;
use crate::tunnel_h3::{ClientTunnelH3, OpenTunnelStreamError, ServerTunnelH3};

fn budget(permits: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(permits))
}

async fn stream_pair(permits: usize) -> (Fixture, ServerTunnelH3, ClientTunnelH3) {
    let fixture = Fixture::new().expect("fixture");
    let (server, client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        budget(permits),
    )
    .await;
    (fixture, server, client)
}

#[tokio::test]
async fn assignment_delivers_initial_bytes_without_a_client_round_trip_and_half_closes() {
    let (_fixture, server, mut client) = stream_pair(4).await;

    let mut server_stream = server
        .open_tunnel_stream(STEP)
        .await
        .expect("a stream is assigned");
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
async fn the_client_budget_bounds_streams_and_released_streams_are_replenished() {
    let (_fixture, server, mut client) = stream_pair(2).await;

    let first = server.open_tunnel_stream(STEP).await.expect("first stream");
    let _second = server
        .open_tunnel_stream(STEP)
        .await
        .expect("second stream");
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
        .expect("a replenished stream is assigned");
}

#[tokio::test]
async fn dropping_a_half_without_shutdown_resets_only_that_stream() {
    let (_fixture, server, mut client) = stream_pair(4).await;

    let server_stream = server.open_tunnel_stream(STEP).await.expect("first stream");
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

    // Other streams and the connection are unaffected.
    let mut other = server.open_tunnel_stream(STEP).await.expect("next stream");
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
    let (_fixture, server, mut client) = stream_pair(4).await;
    let payload: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
    let expected = Sha256::digest(&payload);

    let server_stream = server.open_tunnel_stream(STEP).await.expect("stream");
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
async fn shutdown_seals_placement_and_lets_open_tunnel_streams_finish() {
    let (_fixture, server, mut client) = stream_pair(8).await;
    let server = Arc::new(server);
    let mut server_stream = server.open_tunnel_stream(STEP).await.expect("stream");
    let mut client_stream = client.accept_tunnel_stream().await.expect("stream");

    let shutdown = tokio::spawn({
        let server = server.clone();
        async move { server.shutdown(STEP).await }
    });
    timeout(STEP, async {
        while server.open_tunnel_stream(STEP).await.err() != Some(OpenTunnelStreamError::Closed) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("GOAWAY seals new Visitor opens");

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
async fn graceful_shutdown_waits_for_the_client_to_consume_the_final_tail() {
    let (_fixture, server, mut client) = stream_pair(1).await;
    let mut remote = server.open_tunnel_stream(STEP).await.expect("Visitor");
    let mut local = client.accept_tunnel_stream().await.expect("handoff");
    local.shutdown().await.expect("Client half-close");
    remote
        .read_to_end(&mut Vec::new())
        .await
        .expect("Client FIN");
    remote.write_all(b"tail").await.expect("final bytes");
    remote.shutdown().await.expect("Server FIN enqueued");
    drop(remote);
    let shutdown = server.shutdown(STEP);
    tokio::pin!(shutdown);
    assert!(
        timeout(Duration::from_millis(20), &mut shutdown)
            .await
            .is_err(),
        "local completion must not terminate the Client's unread direction"
    );
    let mut tail = Vec::new();
    local
        .read_to_end(&mut tail)
        .await
        .expect("tail and FIN survive drain");
    assert_eq!(tail, b"tail");
    drop(local);
    timeout(STEP, shutdown)
        .await
        .expect("peer completion finishes shutdown");
}

#[tokio::test]
async fn graceful_shutdown_retains_visitors_queued_for_application_acceptance() {
    let (_fixture, server, mut client) = stream_pair(8).await;
    for index in 0..8 {
        let mut remote = server.open_tunnel_stream(STEP).await.expect("Visitor");
        remote.write_all(&[index]).await.expect("tail");
        remote.shutdown().await.expect("Server FIN");
    }
    // The intake task has reserved every handler, but the application has accepted none.
    wait_for_credit(&client, 8, 0).await;
    let shutdown = server.shutdown(STEP);
    tokio::pin!(shutdown);
    assert!(
        timeout(Duration::from_millis(20), &mut shutdown)
            .await
            .is_err()
    );
    let mut received = Vec::new();
    for _ in 0..8 {
        let mut stream = client.accept_tunnel_stream().await.expect("queued Visitor");
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.expect("tail and FIN");
        assert_eq!(tail.len(), 1);
        received.extend(tail);
    }
    received.sort_unstable();
    assert_eq!(received, (0..8).collect::<Vec<_>>());
    timeout(STEP, shutdown)
        .await
        .expect("queue drains without prolonging shutdown");
}

#[tokio::test]
async fn graceful_shutdown_deadline_still_resets_a_client_retaining_a_visitor() {
    let (_fixture, server, mut client) = stream_pair(1).await;
    let mut remote = server.open_tunnel_stream(STEP).await.expect("Visitor");
    let mut local = client.accept_tunnel_stream().await.expect("handoff");
    local.shutdown().await.expect("Client FIN");
    remote
        .read_to_end(&mut Vec::new())
        .await
        .expect("Server EOF");
    remote.shutdown().await.expect("Server FIN");
    drop(remote);
    timeout(STEP, server.shutdown(Duration::from_millis(20)))
        .await
        .expect("original deadline remains bounded");
    client.closed().await;
    assert!(local.read_to_end(&mut Vec::new()).await.is_err());
}

#[tokio::test]
async fn a_closed_connection_opens_no_tunnel_streams() {
    let (_fixture, server, client) = stream_pair(4).await;
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
async fn visitors_use_server_opened_webtransport_streams_with_permit_backed_credit() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let raw_server = server_connection.clone();
    let permits = budget(2);
    let hostname = server_hostname();
    let (server, client) = tokio::join!(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate(),
            fast_timing()
        ),
        ClientTunnelH3::establish_with_timing(
            client_connection,
            &hostname,
            permits.clone(),
            fast_timing()
        ),
    );
    let _server = server.expect("Server");
    let mut client = client.expect("Client");
    // Stream 4 is the mandatory session. A raw draft07 prefix proves the carrier independently
    // of the Server adapter and requires no new Client request for this Visitor.
    let (mut send, _recv) = timeout(STEP, raw_server.open_bi())
        .await
        .expect("permit-backed QUIC credit")
        .expect("open");
    send.write_all(&[0x40, 0x41, 4, b'v'])
        .await
        .expect("WT prefix and Visitor byte");
    let mut visitor = timeout(STEP, client.accept_tunnel_stream())
        .await
        .expect("delivery")
        .expect("Visitor");
    assert_eq!(visitor.read_u8().await.expect("Visitor byte"), b'v');
    assert_eq!(
        permits.available_permits(),
        0,
        "idle and active each reserve capacity"
    );
}

async fn wait_for_credit(client: &ClientTunnelH3, active: usize, idle: usize) {
    timeout(STEP, async {
        while client.visitor_credit_counts() != (active, idle) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("permit ownership converges");
}

#[tokio::test]
async fn a_full_idle_credit_burst_and_concurrency_up_to_the_aggregate_budget_have_no_resets() {
    use crate::tunnel_h3::MAX_IDLE_VISITOR_CREDIT;
    timeout(Duration::from_secs(10), async {
        let (_fixture, server, mut client) = stream_pair(1024).await;
        wait_for_credit(&client, 0, MAX_IDLE_VISITOR_CREDIT).await;
        let mut servers = Vec::new();
        // Deliberately leave application acceptance unpolled throughout the first T opens.
        for _ in 0..MAX_IDLE_VISITOR_CREDIT {
            let mut stream = server.open_tunnel_stream(STEP).await.expect("burst credit");
            stream.write_all(b"v").await.expect("Visitor byte");
            stream.flush().await.expect("flush");
            servers.push(stream);
        }
        let mut clients = Vec::new();
        for _ in 0..MAX_IDLE_VISITOR_CREDIT {
            let mut stream = client.accept_tunnel_stream().await.expect("burst Visitor");
            assert_eq!(stream.read_u8().await.expect("not reset"), b'v');
            clients.push(stream);
        }
        for index in MAX_IDLE_VISITOR_CREDIT..1024 {
            let stream = match server.open_tunnel_stream(STEP).await {
                Ok(stream) => stream,
                Err(error) => panic!(
                    "Visitor {}: {error:?}; Client active+idle={:?}, guard resets={}",
                    index + 1,
                    client.visitor_credit_counts(),
                    client.guard_rejections()
                ),
            };
            servers.push(stream);
            clients.push(
                client
                    .accept_tunnel_stream()
                    .await
                    .expect("Visitor beyond T"),
            );
        }
        wait_for_credit(&client, 1024, 0).await;
        assert_eq!(client.guard_rejections(), 0);
        assert_eq!(
            server
                .open_tunnel_stream(Duration::from_millis(20))
                .await
                .err(),
            Some(OpenTunnelStreamError::TimedOut)
        );
        drop((servers, clients));
        wait_for_credit(&client, 0, MAX_IDLE_VISITOR_CREDIT).await;
        assert_eq!(client.guard_rejections(), 0);
    })
    .await
    .expect("bounded burst and capacity test");
}

#[tokio::test]
async fn finished_visitors_release_handlers_before_replacement_work_under_normal_load() {
    let (_fixture, server, mut client) = stream_pair(2).await;
    // Complete both directions, retaining the read half after the write half finishes, as the
    // production proxy does. Its handler releases the completed stream before awaiting more work.
    for _ in 0..32 {
        let mut remote = server
            .open_tunnel_stream(STEP)
            .await
            .expect("Visitor credit");
        let stream = client.accept_tunnel_stream().await.expect("Visitor");
        let (mut read, mut write) = stream.into_split();
        remote.shutdown().await.expect("Server FIN");
        let mut bytes = Vec::new();
        read.read_to_end(&mut bytes).await.expect("Client EOF");
        write.shutdown().await.expect("Client FIN");
        drop(write);
        assert_eq!(
            client.visitor_credit_counts().0,
            1,
            "read half retains handler permit"
        );
        remote.read_to_end(&mut bytes).await.expect("Server EOF");
        drop((read, remote));
    }
    wait_for_credit(&client, 0, 2).await;
    assert_eq!(client.guard_rejections(), 0);
}

#[tokio::test]
async fn credit_exhaustion_waits_until_both_handler_halves_release_and_recovers() {
    let (_fixture, server, mut client) = stream_pair(1).await;
    let first = server.open_tunnel_stream(STEP).await.expect("first credit");
    let (read, write) = client
        .accept_tunnel_stream()
        .await
        .expect("first Visitor")
        .into_split();
    let next = server.open_tunnel_stream(STEP);
    tokio::pin!(next);
    assert!(
        timeout(Duration::from_millis(20), &mut next).await.is_err(),
        "waits at budget"
    );
    drop(read);
    assert!(
        timeout(Duration::from_millis(20), &mut next).await.is_err(),
        "one half still owns permit"
    );
    drop((write, first));
    let next = timeout(STEP, next)
        .await
        .expect("release wakes open")
        .expect("credit restored");
    let local = client
        .accept_tunnel_stream()
        .await
        .expect("replacement Visitor");
    wait_for_credit(&client, 1, 0).await;
    drop((next, local));
    wait_for_credit(&client, 0, 1).await;
    assert_eq!(client.guard_rejections(), 0);
}

#[tokio::test]
async fn two_connections_share_the_budget_and_quiet_connections_hold_at_most_t_permits() {
    use crate::tunnel_h3::MAX_IDLE_VISITOR_CREDIT;
    let fixture = Fixture::new().expect("fixture");
    let permits = budget(MAX_IDLE_VISITOR_CREDIT + 2);
    let (_first_server, first_client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        permits.clone(),
    )
    .await;
    wait_for_credit(&first_client, 0, MAX_IDLE_VISITOR_CREDIT).await;
    let (second_server, mut second_client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        permits.clone(),
    )
    .await;
    wait_for_credit(&second_client, 0, 2).await;
    assert_eq!(permits.available_permits(), 0);
    let first = second_server
        .open_tunnel_stream(STEP)
        .await
        .expect("second connection credit");
    let local = second_client.accept_tunnel_stream().await.expect("Visitor");
    wait_for_credit(&second_client, 1, 1).await;
    let second = second_server
        .open_tunnel_stream(STEP)
        .await
        .expect("remaining credit");
    assert_eq!(
        second_server
            .open_tunnel_stream(Duration::from_millis(20))
            .await
            .err(),
        Some(OpenTunnelStreamError::TimedOut)
    );
    drop(first_client);
    let second_local = second_client
        .accept_tunnel_stream()
        .await
        .expect("second Visitor");
    wait_for_credit(&second_client, 2, MAX_IDLE_VISITOR_CREDIT).await;
    assert_eq!(second_client.guard_rejections(), 0);
    drop((first, second, local, second_local));
}

#[tokio::test]
async fn explicit_reserved_credit_eight_to_nine_is_advertised_without_extra_capacity() {
    let fixture = Fixture::new().expect("fixture");
    let (server, client) = fixture.connect().await.expect("handshake");
    // No H3 driver: this isolates Quinn's explicit application credit updates.
    let credits = crate::tunnel_h3::credit::VisitorCredits::new(client, budget(9), None);
    for _ in 0..8 {
        credits.offer(
            credits
                .budget()
                .acquire_owned()
                .await
                .expect("reserved permit"),
        );
    }
    let mut streams = Vec::new();
    for _ in 0..8 {
        streams.push(
            timeout(STEP, server.open_bi())
                .await
                .expect("eight credits")
                .expect("stream"),
        );
    }
    credits.offer(
        credits
            .budget()
            .acquire_owned()
            .await
            .expect("ninth permit"),
    );
    streams.push(
        timeout(Duration::from_millis(200), server.open_bi())
            .await
            .expect("ninth reserved credit advertised")
            .expect("stream"),
    );
    assert!(
        timeout(Duration::from_millis(20), server.open_bi())
            .await
            .is_err(),
        "no tenth credit without a permit"
    );
}

#[tokio::test]
async fn finished_transport_credit_is_guarded_until_the_handler_releases_its_permit() {
    let (_fixture, server, mut client) = stream_pair(1).await;
    let mut remote = server.open_tunnel_stream(STEP).await.expect("first credit");
    let mut local = client.accept_tunnel_stream().await.expect("first Visitor");
    remote.shutdown().await.expect("Server FIN");
    local
        .read_to_end(&mut Vec::new())
        .await
        .expect("Client EOF");
    local.shutdown().await.expect("Client FIN");
    remote
        .read_to_end(&mut Vec::new())
        .await
        .expect("Server EOF");
    // Quinn can free FIN/ACK/EOF transport state while the handler retains both handles.
    let mut excess = server
        .open_tunnel_stream(STEP)
        .await
        .expect("irrevocable replacement credit");
    assert!(
        timeout(STEP, excess.read_u8())
            .await
            .expect("guard resets promptly")
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(20), client.accept_tunnel_stream())
            .await
            .is_err(),
        "guard never hands excess work to a handler"
    );
    assert_eq!(client.guard_rejections(), 1);
    assert_eq!(client.visitor_credit_counts(), (1, 0));
    drop((remote, local, excess));
    let next = server
        .open_tunnel_stream(STEP)
        .await
        .expect("credit recovers");
    let local = client.accept_tunnel_stream().await.expect("next Visitor");
    drop((next, local));
    wait_for_credit(&client, 0, 1).await;
}

#[tokio::test]
async fn wrong_stale_and_truncated_prefixes_never_reach_visitor_handlers() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let raw = server_connection.clone();
    let hostname = server_hostname();
    let (server, client) = tokio::join!(
        ServerTunnelH3::establish(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate()
        ),
        ClientTunnelH3::establish(client_connection, &hostname, budget(4)),
    );
    let server = server.expect("Server");
    let mut client = client.expect("Client");
    wait_for_credit(&client, 0, 4).await;
    // GET zero is not a session; twelve is unregistered; the final prefix truncates its ID.
    for prefix in [&[0x40, 0x41, 0][..], &[0x40, 0x41, 12], &[0x40, 0x41, 0x40]] {
        let (mut send, mut recv) = timeout(STEP, raw.open_bi())
            .await
            .expect("credit")
            .expect("stream");
        send.write_all(prefix).await.expect("prefix");
        let truncated = prefix.last() == Some(&0x40);
        if truncated {
            send.finish().expect("truncated prefix FIN");
        }
        assert!(
            timeout(STEP, recv.read_chunk(1, false))
                .await
                .expect("invalid prefix rejected")
                .is_err()
        );
        let stopped = timeout(STEP, send.stopped())
            .await
            .expect("send stopped")
            .expect("stop result");
        // A fully ACKed FIN may win the race with STOP_SENDING on the truncated prefix.
        assert!(truncated || stopped.is_some());
    }
    assert!(
        timeout(Duration::from_millis(20), client.accept_tunnel_stream())
            .await
            .is_err()
    );
    assert_eq!(client.visitor_credit_counts(), (0, 4));
    let _remote = server
        .open_tunnel_stream(STEP)
        .await
        .expect("valid session still works");
    let _local = client.accept_tunnel_stream().await.expect("valid Visitor");
    assert_eq!(client.guard_rejections(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_completion_drop_and_replenishment_preserve_capacity_without_resets() {
    // Normal load has handler headroom even while finished transports await application Drop.
    concurrent_completion(64, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_completion_replenishes_without_resets_after_handlers_release() {
    // Exhaust the budget, but release each round's handlers before replacement work starts.
    concurrent_completion(32, true).await;
}

async fn concurrent_completion(permits: usize, release_barrier: bool) {
    timeout(Duration::from_secs(20), async {
        let (_fixture, server, mut client) = stream_pair(permits).await;
        let barrier = release_barrier.then(|| Arc::new(tokio::sync::Barrier::new(64)));
        let server = Arc::new(server);
        let mut remote_tasks = tokio::task::JoinSet::new();
        for worker in 0..32 {
            let server = server.clone();
            let barrier = barrier.clone();
            remote_tasks.spawn(async move {
                for iteration in 0..32 {
                    let mut stream = server
                        .open_tunnel_stream(STEP)
                        .await
                        .expect("concurrent credit");
                    stream
                        .write_all(&[worker, iteration])
                        .await
                        .expect("request");
                    stream.shutdown().await.expect("Server FIN");
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await.expect("Server EOF");
                    assert_eq!(response, [worker, iteration]);
                    if let Some(barrier) = &barrier {
                        barrier.wait().await;
                    }
                    tokio::task::yield_now().await;
                }
            });
        }
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..1024 {
            let stream = loop {
                tokio::select! {
                    stream = client.accept_tunnel_stream() => break stream.expect("Visitor handoff"),
                    result = remote_tasks.join_next(), if !remote_tasks.is_empty() => {
                        if let Some(Err(error)) = result {
                            panic!("Server worker failed: {error}; active+idle={:?}, guard resets={}", client.visitor_credit_counts(), client.guard_rejections());
                        }
                    }
                }
            };
            let barrier = barrier.clone();
            handlers.spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let mut request = Vec::new();
                read.read_to_end(&mut request).await.expect("Client EOF");
                write.write_all(&request).await.expect("response");
                write.shutdown().await.expect("Client FIN");
                // Exercise both final-half orders while Quinn's driver runs on other threads.
                if request[0] % 2 == 0 {
                    drop(read);
                    tokio::task::yield_now().await;
                    drop(write);
                } else {
                    drop(write);
                    tokio::task::yield_now().await;
                    drop(read);
                }
                if let Some(barrier) = &barrier {
                    barrier.wait().await;
                }
            });
        }
        while let Some(result) = handlers.join_next().await {
            result.expect("handler");
        }
        while let Some(result) = remote_tasks.join_next().await {
            result.expect("Server worker");
        }
        wait_for_credit(&client, 0, permits).await;
        assert_eq!(client.guard_rejections(), 0);
    })
    .await
    .expect("bounded concurrent stress");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_loss_releases_idle_and_active_permits_across_shared_connections() {
    let fixture = Fixture::new().expect("fixture");
    let permits = budget(512);
    let (server, mut client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        permits.clone(),
    )
    .await;
    let (other_server, mut other_client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        permits.clone(),
    )
    .await;
    let mut remotes = Vec::new();
    let mut locals = Vec::new();
    for index in 0..64 {
        let (server, client) = if index % 2 == 0 {
            (&server, &mut client)
        } else {
            (&other_server, &mut other_client)
        };
        remotes.push(server.open_tunnel_stream(STEP).await.expect("credit"));
        locals.push(client.accept_tunnel_stream().await.expect("Visitor"));
    }
    server.close(b"connection loss");
    other_client.close();
    timeout(STEP, client.closed()).await.expect("remote loss");
    timeout(STEP, other_server.closed())
        .await
        .expect("local close");
    for local in &mut locals {
        assert!(
            timeout(STEP, local.read_u8())
                .await
                .expect("Visitor terminated")
                .is_err()
        );
    }
    drop((locals, remotes));
    timeout(STEP, async {
        while permits.available_permits() != 512 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all idle and active capacity returned with Client handles retained");
    assert_eq!(client.guard_rejections(), 0);
    assert_eq!(other_client.guard_rejections(), 0);
}
