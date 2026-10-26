//! Placement withdrawal: commit point, quiescence, duplicates, statuses, close and Client retries.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::*;
use crate::tunnel_h3::{
    OpenTunnelStreamError, ProtocolFailure, TUNNEL_WITHDRAWAL_PATH, UnconfirmedDrain,
    WithdrawalOutcome,
};

fn withdrawal_uri() -> String {
    format!("https://{SERVER_NAME}{TUNNEL_WITHDRAWAL_PATH}")
}

async fn pair(permits: usize) -> (Fixture, ServerTunnelH3, ClientTunnelH3) {
    let fixture = Fixture::new().expect("fixture");
    let (server, client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        Arc::new(Semaphore::new(permits)),
    )
    .await;
    (fixture, server, client)
}

/// Send a complete bodyless withdrawal request without waiting for its response.
async fn send_withdrawal(sender: &mut RawSendRequest) -> RawClientStream {
    let request = Request::put(withdrawal_uri()).body(()).expect("request");
    let mut stream = sender.send_request(request).await.expect("request opens");
    stream.finish().await.expect("request ends");
    stream
}

/// Wait for a bodyless `204` with response FIN.
async fn expect_confirmed(stream: &mut RawClientStream) {
    let response = timeout(STEP, stream.recv_response())
        .await
        .expect("204 arrives")
        .expect("valid response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        timeout(STEP, stream.recv_data())
            .await
            .expect("response FIN")
            .expect("valid response")
            .is_none()
    );
}

async fn wait_until_withdrawn(server: &ServerTunnelH3) {
    timeout(STEP, async {
        while server.accepts_visitors() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("withdrawal commits");
}

/// One open Visitor whose halves both peers still hold.
async fn active_visitor(
    server: &ServerTunnelH3,
    client: &mut ClientTunnelH3,
) -> (
    super::super::ServerTunnelStream,
    super::super::ClientTunnelStream,
) {
    let remote = server.open_tunnel_stream(STEP).await.expect("Visitor");
    let local = timeout(STEP, client.accept_tunnel_stream())
        .await
        .expect("assignment arrives")
        .expect("connection open");
    (remote, local)
}

/// Finish one Visitor in both directions and drop both peers' halves.
async fn finish_visitor(
    mut remote: super::super::ServerTunnelStream,
    mut local: super::super::ClientTunnelStream,
) {
    local.write_all(b"done").await.expect("Client bytes");
    local.shutdown().await.expect("Client FIN");
    let mut received = Vec::new();
    remote.read_to_end(&mut received).await.expect("Server EOF");
    assert_eq!(received, b"done");
    remote.shutdown().await.expect("Server FIN");
    local
        .read_to_end(&mut Vec::new())
        .await
        .expect("Client EOF");
    drop((remote, local));
}

#[tokio::test]
async fn incomplete_requests_do_not_commit_and_a_complete_request_does() {
    let (_fixture, server, client) = pair(4).await;
    let mut sender = client.send_request_for_test();

    // Headers without request FIN time out with 408 and leave placement eligibility intact.
    let request = Request::put(withdrawal_uri()).body(()).expect("request");
    let mut incomplete = sender.send_request(request).await.expect("request opens");
    let response = timeout(STEP, incomplete.recv_response())
        .await
        .expect("408 arrives")
        .expect("valid response");
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(server.accepts_visitors());
    drop(
        server
            .open_tunnel_stream(STEP)
            .await
            .expect("still eligible"),
    );

    // A cancelled request stream does not commit either.
    let request = Request::put(withdrawal_uri()).body(()).expect("request");
    let mut cancelled = sender.send_request(request).await.expect("request opens");
    cancelled.stop_stream(Code::H3_REQUEST_CANCELLED);
    cancelled.stop_sending(Code::H3_REQUEST_CANCELLED);
    sleep(Duration::from_millis(50)).await;
    assert!(server.accepts_visitors());

    let mut complete = send_withdrawal(&mut sender).await;
    expect_confirmed(&mut complete).await;
    assert!(!server.accepts_visitors());
    assert_eq!(
        server.open_tunnel_stream(STEP).await.err(),
        Some(OpenTunnelStreamError::Closed)
    );
}

#[tokio::test]
async fn cancelling_a_committed_request_never_restores_eligibility() {
    let (_fixture, server, mut client) = pair(4).await;
    let (remote, local) = active_visitor(&server, &mut client).await;
    let mut sender = client.send_request_for_test();

    let mut first = send_withdrawal(&mut sender).await;
    wait_until_withdrawn(&server).await;
    first.stop_sending(Code::H3_REQUEST_CANCELLED);
    drop(first);
    sleep(Duration::from_millis(50)).await;
    assert!(!server.accepts_visitors());

    // A later request joins the same quiescence point.
    let mut second = send_withdrawal(&mut sender).await;
    finish_visitor(remote, local).await;
    expect_confirmed(&mut second).await;
}

#[tokio::test]
async fn confirmation_waits_for_an_active_visitor_and_pending_opens_end() {
    let (_fixture, server, mut client) = pair(1).await;
    let (remote, local) = active_visitor(&server, &mut client).await;
    // With the only permit active, this open waits for credit and is not committed work.
    let pending = server.open_tunnel_stream(STEP);
    tokio::pin!(pending);
    assert!(
        timeout(Duration::from_millis(50), &mut pending)
            .await
            .is_err()
    );

    let mut sender = client.send_request_for_test();
    let mut withdrawal = send_withdrawal(&mut sender).await;
    assert_eq!(
        timeout(STEP, pending)
            .await
            .expect("pending open ends")
            .err(),
        Some(OpenTunnelStreamError::Closed)
    );
    assert!(
        timeout(Duration::from_millis(100), withdrawal.recv_response())
            .await
            .is_err(),
        "an active Visitor keeps the connection from quiescence"
    );

    finish_visitor(remote, local).await;
    expect_confirmed(&mut withdrawal).await;
}

#[tokio::test]
async fn duplicates_share_quiescence_and_never_extend_the_close_timeout() {
    let (_fixture, server, mut client) = pair(4).await;
    let (remote, local) = active_visitor(&server, &mut client).await;
    let mut sender = client.send_request_for_test();
    let mut first = send_withdrawal(&mut sender).await;
    let mut second = send_withdrawal(&mut sender).await;
    wait_until_withdrawn(&server).await;

    finish_visitor(remote, local).await;
    expect_confirmed(&mut first).await;
    let confirmed_at = Instant::now();
    expect_confirmed(&mut second).await;

    sleep(fast_timing().post_quiescence_close / 2).await;
    let mut late = send_withdrawal(&mut sender).await;
    expect_confirmed(&mut late).await;

    timeout(STEP, server.closed()).await.expect("Server closes");
    let elapsed = confirmed_at.elapsed();
    assert!(
        elapsed < fast_timing().post_quiescence_close + Duration::from_millis(150),
        "a late duplicate extended the close timeout: {elapsed:?}"
    );
}

#[tokio::test]
async fn server_closes_a_quiescent_connection_the_client_leaves_open() {
    let (_fixture, _server, client) = pair(4).await;
    let mut sender = client.send_request_for_test();
    let mut withdrawal = send_withdrawal(&mut sender).await;
    expect_confirmed(&mut withdrawal).await;
    let confirmed_at = Instant::now();

    let error = timeout(STEP, client.closed())
        .await
        .expect("Server enforces the close");
    let elapsed = confirmed_at.elapsed();
    assert!(
        elapsed >= fast_timing().post_quiescence_close - Duration::from_millis(20),
        "closed too early: {elapsed:?}"
    );
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
}

#[tokio::test]
async fn invalid_withdrawal_requests_get_bodyless_statuses_and_do_not_commit() {
    let (_fixture, server, client) = pair(4).await;
    let mut sender = client.send_request_for_test();

    let (response, _) = raw_request(&mut sender, Method::GET, &withdrawal_uri()).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::ALLOW], "PUT");

    let (response, _) = raw_request(
        &mut sender,
        Method::PUT,
        &format!("https://other.example.test{TUNNEL_WITHDRAWAL_PATH}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);

    let (response, _) = raw_request(
        &mut sender,
        Method::PUT,
        &format!("https://{SERVER_NAME}/v1/tunnel/withdrawals"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let request = Request::put(withdrawal_uri()).body(()).expect("request");
    let mut with_content = sender.send_request(request).await.expect("request opens");
    with_content
        .send_data(Bytes::from_static(b"x"))
        .await
        .expect("content sent");
    with_content.finish().await.expect("request ends");
    let response = timeout(STEP, with_content.recv_response())
        .await
        .expect("400 arrives")
        .expect("valid response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    sleep(Duration::from_millis(50)).await;
    assert!(server.accepts_visitors());
    drop(
        server
            .open_tunnel_stream(STEP)
            .await
            .expect("still eligible"),
    );
}

#[tokio::test]
async fn withdrawal_releases_idle_credit_and_confirms_after_local_visitors_finish() {
    let budget = Arc::new(Semaphore::new(8));
    let fixture = Fixture::new().expect("fixture");
    let (server, mut client) = establish_pair(
        &fixture,
        ServerRuntimeGeneration::generate(),
        budget.clone(),
    )
    .await;
    let (remote, local) = active_visitor(&server, &mut client).await;
    timeout(STEP, async {
        while client.visitor_credit_counts() != (1, 7) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("credit converges");

    // Withdrawal stops replenishment, but offered credit stays reserved until the Server
    // confirms: a Visitor it commits first must still find its permit, even if a sibling is
    // waiting on the budget and the withdrawal request has not been sent yet.
    let withdrawal = client.withdrawal();
    let mut sibling = Box::pin(budget.clone().acquire_owned());
    assert!(
        timeout(Duration::from_millis(50), &mut sibling)
            .await
            .is_err()
    );
    assert_eq!(client.visitor_credit_counts(), (1, 7));
    let (second_remote, second_local) = active_visitor(&server, &mut client).await;
    assert_eq!(client.guard_rejections(), 0);
    assert_eq!(client.visitor_credit_counts(), (2, 6));
    drop(sibling);

    let withdrawal = tokio::spawn(withdrawal);
    wait_until_withdrawn(&server).await;
    assert!(!withdrawal.is_finished());

    finish_visitor(second_remote, second_local).await;
    finish_visitor(remote, local).await;
    let outcome = timeout(STEP, withdrawal)
        .await
        .expect("withdrawal finishes")
        .expect("task");
    assert_eq!(outcome, WithdrawalOutcome::Confirmed);
    // The Client closes right after 204, well before the Server's post-quiescence close.
    timeout(fast_timing().post_quiescence_close / 2, server.closed())
        .await
        .expect("the Client closes the connection");
    assert_eq!(budget.available_permits(), 8);
}

#[tokio::test]
async fn a_received_confirmation_is_recorded_before_local_visitors_finish() {
    let (_fixture, server, mut client) = pair(4).await;
    let (mut remote, mut local) = active_visitor(&server, &mut client).await;
    // The Server-side Visitor ends while the Client handler still holds its lease.
    local.shutdown().await.expect("Client FIN");
    remote
        .read_to_end(&mut Vec::new())
        .await
        .expect("Server EOF");
    remote.shutdown().await.expect("Server FIN");
    drop(remote);

    let withdrawal = tokio::spawn(client.withdrawal());
    timeout(STEP, async {
        while !client.withdrawal_confirmed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("204 is recorded at once");
    assert!(
        !withdrawal.is_finished(),
        "the local lease is still draining"
    );

    local
        .read_to_end(&mut Vec::new())
        .await
        .expect("Client EOF");
    drop(local);
    assert_eq!(
        timeout(STEP, withdrawal)
            .await
            .expect("finishes")
            .expect("task"),
        WithdrawalOutcome::Confirmed
    );
}

#[tokio::test]
async fn revocation_during_withdrawal_leaves_the_drain_unconfirmed() {
    let (_fixture, server, mut client) = pair(4).await;
    let (_remote, _local) = active_visitor(&server, &mut client).await;
    let withdrawal = tokio::spawn(client.withdrawal());
    wait_until_withdrawn(&server).await;

    server.close(b"authorization revoked");
    let outcome = timeout(STEP, withdrawal)
        .await
        .expect("withdrawal finishes")
        .expect("task");
    assert_eq!(
        outcome,
        WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::ConnectionLost)
    );
}

#[tokio::test]
async fn server_goaway_leaves_a_later_withdrawal_unconfirmed() {
    let (_fixture, server, mut client) = pair(4).await;
    let (remote, local) = active_visitor(&server, &mut client).await;
    let server = Arc::new(server);
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
    .expect("GOAWAY sent");
    // Give the Client time to process GOAWAY before it withdraws.
    sleep(Duration::from_millis(50)).await;

    let outcome = timeout(STEP, client.withdrawal())
        .await
        .expect("withdrawal finishes");
    assert_eq!(
        outcome,
        WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::RequestsForbidden)
    );
    drop((remote, local));
    timeout(STEP, shutdown)
        .await
        .expect("shutdown")
        .expect("task");
}

/// Scripted response to one withdrawal request.
#[derive(Clone, Copy)]
enum Scripted {
    Status(StatusCode),
    /// Cancel the request without any response.
    Reset,
    /// A `204` that carries content.
    ConfirmationWithContent,
    /// A `204` with a prohibited nonzero `content-length` and no content.
    ConfirmationWithLength,
}

/// A raw Server that passes the gate, accepts the session and answers withdrawals from `script`.
async fn scripted_client(
    script: Vec<Scripted>,
) -> (ClientTunnelH3, Arc<AtomicUsize>, JoinHandle<()>) {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let withdrawals = Arc::new(AtomicUsize::new(0));
    let observed = withdrawals.clone();
    let task = tokio::spawn(async move {
        let _fixture = fixture;
        let core = raw_server(server_connection).await;
        let (mut driver, acceptor) = h3_webtransport::server::new(core, Default::default());
        let mut retained = Vec::new();
        let mut sessions = Vec::new();
        while let Ok(Some(resolver)) = driver.accept().await {
            let Ok((request, mut stream)) = resolver.resolve_request().await else {
                continue;
            };
            if request.method() == Method::GET {
                respond_events(
                    &mut stream,
                    &TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse(),
                )
                .await;
                retained.push(stream);
            } else if request.method() == Method::CONNECT {
                sessions.push(acceptor.accept(request, stream).await.expect("session"));
            } else {
                let index = observed.fetch_add(1, Ordering::SeqCst);
                let _ = stream.recv_data().await;
                match script[index] {
                    Scripted::Status(status) => {
                        let response = Response::builder()
                            .status(status)
                            .body(())
                            .expect("response");
                        stream.send_response(response).await.expect("response sent");
                        stream.finish().await.expect("response FIN");
                    }
                    Scripted::Reset => stream.stop_stream(Code::H3_REQUEST_CANCELLED),
                    Scripted::ConfirmationWithContent => {
                        let response = Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .body(())
                            .expect("response");
                        stream.send_response(response).await.expect("response sent");
                        let _ = stream.send_data(Bytes::from_static(b"x")).await;
                        let _ = stream.finish().await;
                    }
                    Scripted::ConfirmationWithLength => {
                        let response = Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .header(header::CONTENT_LENGTH, "1")
                            .body(())
                            .expect("response");
                        stream.send_response(response).await.expect("response sent");
                        let _ = stream.finish().await;
                    }
                }
                retained.push(stream);
            }
        }
    });
    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await
    .expect("Client establishes");
    (client, withdrawals, task)
}

#[tokio::test]
async fn client_retries_once_after_a_response_less_failure_or_408() {
    for (script, expected, attempts) in [
        (
            vec![Scripted::Reset, Scripted::Status(StatusCode::NO_CONTENT)],
            WithdrawalOutcome::Confirmed,
            2,
        ),
        (
            vec![
                Scripted::Status(StatusCode::REQUEST_TIMEOUT),
                Scripted::Status(StatusCode::NO_CONTENT),
            ],
            WithdrawalOutcome::Confirmed,
            2,
        ),
        (
            vec![Scripted::Reset, Scripted::Reset],
            WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::RetryExhausted),
            2,
        ),
        (
            vec![
                Scripted::Status(StatusCode::REQUEST_TIMEOUT),
                Scripted::Status(StatusCode::REQUEST_TIMEOUT),
            ],
            WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::RetryExhausted),
            2,
        ),
        (
            vec![
                Scripted::Reset,
                Scripted::Status(StatusCode::REQUEST_TIMEOUT),
            ],
            WithdrawalOutcome::Unconfirmed(UnconfirmedDrain::RetryExhausted),
            2,
        ),
    ] {
        let (client, withdrawals, task) = scripted_client(script).await;
        let outcome = timeout(STEP, client.withdrawal())
            .await
            .expect("withdrawal finishes");
        assert_eq!(outcome, expected);
        assert_eq!(withdrawals.load(Ordering::SeqCst), attempts);
        timeout(STEP, client.closed()).await.expect("Client closes");
        task.abort();
    }
}

#[tokio::test]
async fn client_maps_explicit_rejections_and_malformed_confirmations_to_protocol_failures() {
    for (scripted, expected) in [
        (
            Scripted::Status(StatusCode::BAD_REQUEST),
            ProtocolFailure::Status(400),
        ),
        (
            Scripted::Status(StatusCode::NOT_FOUND),
            ProtocolFailure::Status(404),
        ),
        (
            Scripted::Status(StatusCode::METHOD_NOT_ALLOWED),
            ProtocolFailure::Status(405),
        ),
        (
            Scripted::Status(StatusCode::MISDIRECTED_REQUEST),
            ProtocolFailure::Status(421),
        ),
        (
            Scripted::Status(StatusCode::OK),
            ProtocolFailure::Status(200),
        ),
        (
            Scripted::ConfirmationWithContent,
            ProtocolFailure::MalformedConfirmation,
        ),
        (
            Scripted::ConfirmationWithLength,
            ProtocolFailure::MalformedConfirmation,
        ),
    ] {
        let (client, withdrawals, task) = scripted_client(vec![scripted]).await;
        let outcome = timeout(STEP, client.withdrawal())
            .await
            .expect("withdrawal finishes");
        assert_eq!(outcome, WithdrawalOutcome::ProtocolFailure(expected));
        assert_eq!(withdrawals.load(Ordering::SeqCst), 1, "never retried");
        timeout(STEP, client.closed()).await.expect("Client closes");
        task.abort();
    }
}
