//! Candidate attempts and the replacement hint a Client follows on its primary connection.

use tokio::sync::oneshot;

use super::*;
use crate::tunnel::{ReplacementHint, ServerTunnelEvents};

fn hint_state(
    generation: Option<ServerRuntimeGeneration>,
    interruptions: u64,
    paused: bool,
) -> ReplacementHint {
    ReplacementHint {
        generation,
        interruptions,
        paused,
    }
}

fn hinted(server: ServerRuntimeGeneration, hint: ServerRuntimeGeneration) -> Bytes {
    TunnelEventState {
        server_generation: server,
        replacement_generation: Some(hint),
    }
    .encode_sse()
}

async fn establish_candidate(
    client_connection: quinn::Connection,
    budget: Arc<Semaphore>,
    expected: ServerRuntimeGeneration,
) -> Result<ClientTunnelH3, TunnelH3Error> {
    ClientTunnelH3::establish_candidate_with_timing(
        client_connection,
        &server_hostname(),
        budget,
        expected,
        fast_timing(),
    )
    .await
}

async fn wait_for_hint(
    hint: &mut tokio::sync::watch::Receiver<ReplacementHint>,
    expected: ReplacementHint,
) {
    timeout(STEP, hint.wait_for(|current| *current == expected))
        .await
        .expect("hint arrives")
        .expect("client follows events");
}

#[tokio::test]
async fn a_candidate_on_the_expected_generation_establishes_and_offers_credit() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let budget = Arc::new(Semaphore::new(4));
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (server, client) = tokio::join!(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            generation,
            fast_timing(),
        ),
        establish_candidate(client_connection, budget.clone(), generation),
    );
    let _server = server.expect("server establishes");
    let client = client.expect("candidate passes the generation check");

    assert_eq!(client.server_generation(), generation);
    timeout(STEP, async {
        while budget.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("candidate offers credit");
}

#[tokio::test]
async fn a_candidate_on_another_generation_closes_with_h3_no_error_before_the_session() {
    let fixture = Fixture::new().expect("fixture");
    let reached = ServerRuntimeGeneration::generate();
    let expected = ServerRuntimeGeneration::generate();
    let snapshot = TunnelEventState::current(reached).encode_sse();
    let budget = Arc::new(Semaphore::new(4));
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection.clone()).await;
        let (_, mut stream) = accept_raw_request(&mut connection).await;
        respond_events(&mut stream, &snapshot).await;
        // The Client must close instead of opening the WebTransport session.
        let next_request = connection.accept().await.unwrap_or(None).is_some();
        (next_request, server_connection.closed().await)
    });

    let error = establish_candidate(client_connection, budget.clone(), expected)
        .await
        .err()
        .expect("wrong generation fails the candidate");

    assert!(error.is_wrong_generation(), "{error:?}");
    let (next_request, closed) = timeout(STEP, fake_server)
        .await
        .expect("Client closes")
        .expect("fake server task");
    assert!(!next_request, "no request may follow a wrong generation");
    assert_eq!(
        application_close_code(&closed),
        Some(Code::H3_NO_ERROR.value())
    );
    assert_eq!(budget.available_permits(), 4, "no credit was reserved");
}

#[tokio::test]
async fn the_replacement_hint_follows_snapshots_and_ignores_the_own_generation() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection).await;
        let (_, mut stream) = accept_raw_request(&mut connection).await;
        respond_events(&mut stream, &hinted(generation, generation)).await;
        let session = accept_raw_session(&mut connection).await;
        let _ = release_rx.await;
        stream
            .send_data(hinted(generation, replacement))
            .await
            .expect("hint sent");
        (connection, stream, session)
    });

    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await
    .expect("gate passes");
    let mut hint = client.replacement_hint();
    assert_eq!(*hint.borrow(), ReplacementHint::default());

    release_tx.send(()).expect("fake server waits");
    wait_for_hint(&mut hint, hint_state(Some(replacement), 0, false)).await;
    let _server = fake_server.await.expect("fake server task");
}

#[tokio::test]
async fn an_interrupted_subscription_pauses_the_hint_until_resubscribed() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection).await;
        let (_, mut first) = accept_raw_request(&mut connection).await;
        respond_events(&mut first, &hinted(generation, replacement)).await;
        let session = accept_raw_session(&mut connection).await;
        first.finish().await.expect("first subscription ends");
        // Hold the resubscription until the test has observed the pause.
        let (_, mut second) = accept_raw_request(&mut connection).await;
        let _ = release_rx.await;
        respond_events(&mut second, &hinted(generation, replacement)).await;
        (connection, second, session)
    });

    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await
    .expect("gate passes");
    let mut hint = client.replacement_hint();
    wait_for_hint(&mut hint, hint_state(Some(replacement), 0, false)).await;

    wait_for_hint(&mut hint, hint_state(None, 1, true)).await;
    release_tx.send(()).expect("fake server waits");
    wait_for_hint(&mut hint, hint_state(Some(replacement), 1, false)).await;
    let _server = fake_server.await.expect("fake server task");
    assert!(
        timeout(Duration::from_millis(100), client.closed())
            .await
            .is_err(),
        "an interrupted subscription keeps the connection"
    );
}

#[tokio::test]
async fn goaway_keeps_the_last_hint_without_resubscribing() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection).await;
        let (_, mut stream) = accept_raw_request(&mut connection).await;
        respond_events(&mut stream, &hinted(generation, replacement)).await;
        let session = accept_raw_session(&mut connection).await;
        connection.shutdown(0).await.expect("GOAWAY sent");
        // Let GOAWAY arrive before the subscription ends.
        sleep(Duration::from_millis(50)).await;
        stream.finish().await.expect("subscription ends");
        let resubscribed = timeout(Duration::from_millis(300), connection.accept())
            .await
            .is_ok_and(|request| request.is_ok_and(|request| request.is_some()));
        (resubscribed, connection, session)
    });

    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await
    .expect("gate passes");
    let hint = client.replacement_hint();

    let (resubscribed, _connection, _session) = timeout(STEP, fake_server)
        .await
        .expect("fake server finishes")
        .expect("fake server task");
    assert!(!resubscribed, "GOAWAY forbids resubscription");
    assert_eq!(*hint.borrow(), hint_state(Some(replacement), 0, false));
}

#[tokio::test]
async fn a_published_hint_reaches_the_client_and_a_cleared_one_withdraws_it() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let events = ServerTunnelEvents::new(generation);
    let (_server, client) = establish_pair(&fixture, events.clone(), no_credit()).await;
    let mut hint = client.replacement_hint();

    events.set_replacement_generation(Some(replacement));
    wait_for_hint(&mut hint, hint_state(Some(replacement), 0, false)).await;
    events.set_replacement_generation(None);
    wait_for_hint(&mut hint, ReplacementHint::default()).await;
}

#[tokio::test]
async fn a_failed_subscription_pauses_replacement_before_the_resubscribe_delay() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection).await;
        let (_, mut stream) = accept_raw_request(&mut connection).await;
        respond_events(&mut stream, &hinted(generation, replacement)).await;
        let session = accept_raw_session(&mut connection).await;
        stream.finish().await.expect("subscription ends");
        (connection, stream, session)
    });

    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        TunnelH3Timing {
            resubscribe_delay: Duration::from_secs(30),
            ..fast_timing()
        },
    )
    .await
    .expect("gate passes");
    let mut hint = client.replacement_hint();

    // The hint stands, in case GOAWAY ended the subscription, but replacement pauses at once.
    wait_for_hint(&mut hint, hint_state(Some(replacement), 0, true)).await;
    let _server = fake_server.await.expect("fake server task");
}
