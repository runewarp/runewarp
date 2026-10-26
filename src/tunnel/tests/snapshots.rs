//! Tunnel event-stream snapshots: replacement hints, coalescing, and the `Accept` rule.

use crate::tunnel::ServerTunnelEvents;

use super::*;

fn events_uri() -> String {
    format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}")
}

fn snapshot_text(state: TunnelEventState) -> String {
    String::from_utf8(state.encode_sse().to_vec()).expect("UTF-8 snapshot")
}

fn hinted(server: ServerRuntimeGeneration, hint: ServerRuntimeGeneration) -> TunnelEventState {
    TunnelEventState {
        server_generation: server,
        replacement_generation: Some(hint),
    }
}

/// Next event block that is not a comment keepalive, or `None` at FIN.
async fn next_snapshot(stream: &mut RawClientStream) -> Option<String> {
    loop {
        let block = read_event_block(stream).await?;
        if block != ": keepalive\n\n" {
            return Some(block);
        }
    }
}

async fn server_with_raw_client(
    connection: (quinn::Connection, quinn::Connection),
    events: &ServerTunnelEvents,
    timing: TunnelTiming,
) -> (ServerTunnel, RawSendRequest, JoinHandle<()>) {
    let (server_connection, client_connection) = connection;
    let (server, (send_request, driver)) = tokio::join!(
        ServerTunnel::establish_with_timing(
            server_connection,
            server_hostname(),
            events.clone(),
            timing,
        ),
        raw_client(client_connection),
    );
    (server.expect("server establishes"), send_request, driver)
}

#[tokio::test]
async fn server_writes_a_new_full_snapshot_whenever_the_published_hint_changes() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let events = ServerTunnelEvents::new(generation);
    let connection = fixture.connect().await.expect("handshake");
    let (_server, mut send_request, _driver) =
        server_with_raw_client(connection, &events, fast_timing()).await;

    let (_, mut stream) = raw_request(&mut send_request, Method::GET, &events_uri()).await;
    assert_eq!(
        next_snapshot(&mut stream).await,
        Some(snapshot_text(TunnelEventState::current(generation)))
    );

    events.set_replacement_generation(Some(replacement));
    assert_eq!(
        next_snapshot(&mut stream).await,
        Some(snapshot_text(hinted(generation, replacement)))
    );

    // A newer subscription starts from the current snapshot, hint included.
    let (_, mut newer) = raw_request(&mut send_request, Method::GET, &events_uri()).await;
    assert_eq!(
        next_snapshot(&mut newer).await,
        Some(snapshot_text(hinted(generation, replacement)))
    );

    events.set_replacement_generation(None);
    assert_eq!(
        next_snapshot(&mut newer).await,
        Some(snapshot_text(TunnelEventState::current(generation)))
    );
}

#[tokio::test]
async fn a_blocked_subscription_receives_only_the_latest_snapshot() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let events = ServerTunnelEvents::new(generation);
    // A tiny Client stream receive window lets keepalives fill the subscription's flow control
    // while nothing reads it.
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(512_u32.into());
    let mut client_config = make_client_tunnel_h3_config(
        {
            let mut roots = RootCertStore::empty();
            roots
                .add(
                    certificate_chain_from_pem(fixture.server_certificate_pem.as_bytes())
                        .expect("server certificate")
                        .remove(0),
                )
                .expect("root");
            roots
        },
        certificate_chain_from_pem(fixture.client_certificate_pem.as_bytes()).expect("chain"),
        private_key_from_pem(fixture.client_key_pem.as_bytes()).expect("key"),
    )
    .expect("client config");
    client_config.transport_config(Arc::new(transport));
    let connection = fixture
        .connect_with(client_config)
        .await
        .expect("handshake");
    let timing = TunnelTiming {
        keepalive_comment_interval: Duration::from_millis(10),
        blocked_write_deadline: Duration::from_secs(30),
        ..fast_timing()
    };
    let (_server, mut send_request, _driver) =
        server_with_raw_client(connection, &events, timing).await;

    let (_, mut stream) = raw_request(&mut send_request, Method::GET, &events_uri()).await;
    // Leave the stream unread until keepalives exhaust its window and block the next write.
    sleep(Duration::from_millis(800)).await;
    let hints: Vec<_> = (0..3)
        .map(|_| ServerRuntimeGeneration::generate())
        .collect();
    for hint in &hints {
        events.set_replacement_generation(Some(*hint));
        sleep(Duration::from_millis(20)).await;
    }

    let mut snapshots = Vec::new();
    while let Ok(Some(block)) =
        timeout(Duration::from_millis(300), next_snapshot(&mut stream)).await
    {
        snapshots.push(block);
    }
    assert_eq!(
        snapshots,
        [
            snapshot_text(TunnelEventState::current(generation)),
            snapshot_text(hinted(generation, hints[2])),
        ]
    );
}

#[tokio::test]
async fn client_tolerates_hints_and_keeps_its_connection() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let replacement = ServerRuntimeGeneration::generate();
    let events = ServerTunnelEvents::new(generation);
    let (_server, client) = establish_pair(&fixture, events.clone(), no_credit()).await;
    let mut state = client.event_state();

    events.set_replacement_generation(Some(replacement));
    timeout(
        STEP,
        state.wait_for(|state| state.replacement_generation == Some(replacement)),
    )
    .await
    .expect("hint arrives")
    .expect("client follows events");

    assert_eq!(client.server_generation(), generation);
    assert!(
        timeout(Duration::from_millis(200), client.closed())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn client_requests_event_streams_with_accept_text_event_stream() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection).await;
        let (request, stream) = accept_raw_request(&mut connection).await;
        (request, stream, connection)
    });
    let client = tokio::spawn(async move {
        ClientTunnel::establish_with_timing(
            client_connection,
            &server_hostname(),
            no_credit(),
            fast_timing(),
        )
        .await
    });

    let (request, _stream, _connection) = timeout(STEP, fake_server)
        .await
        .expect("events request arrives")
        .expect("fake server task");
    assert_eq!(request.uri().path(), TUNNEL_EVENTS_PATH);
    assert_eq!(
        request
            .headers()
            .get(header::ACCEPT)
            .map(|value| value.as_bytes()),
        Some(b"text/event-stream".as_slice())
    );
    client.abort();
}

#[tokio::test]
async fn server_ignores_the_accept_header() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let events = ServerTunnelEvents::new(generation);
    let connection = fixture.connect().await.expect("handshake");
    let (_server, mut send_request, _driver) =
        server_with_raw_client(connection, &events, fast_timing()).await;

    for accept in [None, Some("application/json"), Some("text/event-stream")] {
        let mut request = Request::get(events_uri());
        if let Some(accept) = accept {
            request = request.header(header::ACCEPT, accept);
        }
        let mut stream = send_request
            .send_request(request.body(()).expect("valid request"))
            .await
            .expect("request opens");
        stream.finish().await.expect("request ends");
        let response = timeout(STEP, stream.recv_response())
            .await
            .expect("response arrives")
            .expect("valid response");
        assert_eq!(response.status(), StatusCode::OK, "{accept:?}");
        assert_eq!(
            next_snapshot(&mut stream).await,
            Some(snapshot_text(TunnelEventState::current(generation))),
            "{accept:?}"
        );
    }
}
