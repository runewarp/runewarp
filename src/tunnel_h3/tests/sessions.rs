//! WebTransport lifecycle alongside ordinary signaling and receive slots.

use super::*;

#[tokio::test]
async fn session_opens_only_after_the_gate_and_establishment_waits_for_connect() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let mut server = raw_server(server_connection).await;
    let client = tokio::spawn(async move {
        ClientTunnelH3::establish_with_timing(
            client_connection,
            &server_hostname(),
            no_slots(),
            fast_timing(),
        )
        .await
    });
    let (request, mut events) = accept_raw_request(&mut server).await;
    assert_eq!(request.method(), Method::GET);
    assert_eq!(events.id().into_inner(), 0);
    respond_events(&mut events, b": keepalive\n\n").await;
    assert!(
        timeout(Duration::from_millis(50), server.accept())
            .await
            .is_err()
    );
    assert!(!client.is_finished(), "comments do not pass the gate");

    events
        .send_data(TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse())
        .await
        .expect("valid state");
    let (request, mut session) = accept_raw_request(&mut server).await;
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.uri().path(), "/v1/tunnel/session");
    assert_eq!(
        request.uri().authority().expect("authority").host(),
        SERVER_NAME
    );
    assert_eq!(
        request.extensions().get::<h3::ext::Protocol>(),
        Some(&h3::ext::Protocol::WEB_TRANSPORT)
    );
    assert_eq!(
        session.id().into_inner(),
        4,
        "session uses the full CONNECT ID"
    );
    assert!(
        !client.is_finished(),
        "CONNECT response is part of establishment"
    );
    session
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("response"),
        )
        .await
        .expect("accept session");
    let client = timeout(STEP, client)
        .await
        .expect("established")
        .expect("task")
        .expect("session established");
    drop(client);
}

async fn session_request(sender: &mut RawSendRequest, path: &str) -> RawClientStream {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{SERVER_NAME}{path}"))
        .body(())
        .expect("session request");
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::WEB_TRANSPORT);
    sender.send_request(request).await.expect("CONNECT opens")
}

#[tokio::test]
async fn server_accepts_session_four_rejects_duplicate_and_wrong_path_and_keeps_serving() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = ServerTunnelH3::establish_with_timing(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
        fast_timing(),
    )
    .await
    .expect("Server");
    let (mut sender, driver) = raw_client(client_connection).await;
    let (_, mut events) = raw_request(
        &mut sender,
        Method::GET,
        &format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"),
    )
    .await;
    assert!(read_event_block(&mut events).await.is_some());
    let mut session = session_request(&mut sender, "/v1/tunnel/session").await;
    assert_eq!(session.id().into_inner(), 4);
    assert_eq!(
        session
            .recv_response()
            .await
            .expect("session response")
            .status(),
        StatusCode::OK
    );
    for (path, status) in [
        ("/v1/tunnel/session", StatusCode::TOO_MANY_REQUESTS),
        ("/wrong", StatusCode::NOT_FOUND),
    ] {
        let mut rejected = session_request(&mut sender, path).await;
        assert_eq!(
            rejected.recv_response().await.expect("rejection").status(),
            status
        );
        assert!(
            rejected
                .recv_data()
                .await
                .expect("bodyless response")
                .is_none()
        );
        let (response, _) = raw_request(
            &mut sender,
            Method::GET,
            &format!("https://{SERVER_NAME}/unknown"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    server.close(b"test complete");
    driver.abort();
}

// Draft07 CLOSE_WEBTRANSPORT_SESSION, a four-byte application code and an empty reason.
const CLOSE_CAPSULE: &[u8] = &[0x68, 0x43, 0x04, 0, 0, 0, 0];

#[tokio::test]
async fn client_session_close_capsule_closes_tunnel_even_if_fin_is_withheld() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let _server = ServerTunnelH3::establish_with_timing(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
        fast_timing(),
    )
    .await
    .expect("Server");
    let (mut sender, driver) = raw_client(client_connection.clone()).await;
    let mut session = session_request(&mut sender, "/v1/tunnel/session").await;
    assert_eq!(
        session.recv_response().await.expect("accepted").status(),
        StatusCode::OK
    );
    session
        .send_data(Bytes::from_static(CLOSE_CAPSULE))
        .await
        .expect("close capsule");
    let error = timeout(STEP, client_connection.closed())
        .await
        .expect("Server observes session close");
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
    driver.abort();
}

#[tokio::test]
async fn server_session_close_capsule_closes_tunnel_even_if_fin_is_withheld() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let mut server = raw_server(server_connection.clone()).await;
    let client = tokio::spawn(async move {
        ClientTunnelH3::establish_with_timing(
            client_connection,
            &server_hostname(),
            no_slots(),
            fast_timing(),
        )
        .await
    });
    let (_, mut events) = accept_raw_request(&mut server).await;
    respond_events(
        &mut events,
        &TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse(),
    )
    .await;
    let mut session = accept_raw_session(&mut server).await;
    let _client = timeout(STEP, client)
        .await
        .expect("established")
        .expect("task")
        .expect("Client");
    session
        .send_data(Bytes::from_static(CLOSE_CAPSULE))
        .await
        .expect("close capsule");
    let error = timeout(STEP, server_connection.closed())
        .await
        .expect("Client observes session close");
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
}

#[tokio::test]
async fn goaway_keeps_the_session_and_active_receive_slot_until_drain_finishes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = Arc::new(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate(),
            fast_timing(),
        )
        .await
        .expect("Server"),
    );
    let (mut sender, driver) = raw_client(client_connection.clone()).await;
    let (_, mut events) = raw_request(
        &mut sender,
        Method::GET,
        &format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"),
    )
    .await;
    read_event_block(&mut events).await.expect("gate");
    let mut session = session_request(&mut sender, "/v1/tunnel/session").await;
    assert_eq!(
        session.recv_response().await.expect("accepted").status(),
        StatusCode::OK
    );
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("{SERVER_NAME}:443"))
        .body(())
        .expect("slot");
    let mut slot = sender.send_request(request).await.expect("offer slot");
    let mut visitor = server
        .open_tunnel_stream(STEP)
        .await
        .expect("assign Visitor");
    assert_eq!(
        slot.recv_response().await.expect("assignment").status(),
        StatusCode::OK
    );
    let shutdown = tokio::spawn({
        let server = server.clone();
        async move { server.shutdown(STEP).await }
    });
    timeout(STEP, async {
        while events.recv_data().await.expect("events").is_some() {}
    })
    .await
    .expect("events end on GOAWAY");
    // GOAWAY forbids new signaling without terminating the existing CONNECT.
    assert!(matches!(
        sender
            .send_request(
                Request::get(format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"))
                    .body(())
                    .expect("GET")
            )
            .await,
        Err(h3::error::StreamError::RemoteClosing)
    ));
    assert!(
        timeout(Duration::from_millis(50), session.recv_data())
            .await
            .is_err()
    );
    assert!(client_connection.close_reason().is_none());
    slot.send_data(Bytes::from_static(b"draining"))
        .await
        .expect("Client data during drain");
    slot.finish().await.expect("Client FIN");
    let mut bytes = Vec::new();
    visitor.read_to_end(&mut bytes).await.expect("Visitor data");
    assert_eq!(bytes, b"draining");
    visitor
        .write_all(b"done")
        .await
        .expect("Server data during drain");
    visitor.shutdown().await.expect("Server FIN");
    let mut data = slot
        .recv_data()
        .await
        .expect("response data")
        .expect("bytes");
    assert_eq!(&data.copy_to_bytes(data.remaining())[..], b"done");
    drop(visitor);
    let error = timeout(STEP, client_connection.closed())
        .await
        .expect("drained connection closes");
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
    timeout(STEP, shutdown)
        .await
        .expect("shutdown")
        .expect("task");
    driver.abort();
}

#[tokio::test]
async fn stalled_classifiers_are_evicted_at_the_signaling_deadline_and_connection_keeps_serving() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let _server = ServerTunnelH3::establish_with_timing(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
        fast_timing(),
    )
    .await
    .expect("Server");
    let (mut sender, driver) = raw_client(client_connection.clone()).await;
    // One byte of a two-byte frame type is enough to leave a classifier waiting.
    let (mut send, mut recv) = client_connection.open_bi().await.expect("raw stream");
    send.write_all(&[0x40]).await.expect("incomplete prefix");
    assert!(
        timeout(STEP, send.stopped())
            .await
            .expect("prefix deadline")
            .expect("stop")
            .is_some()
    );
    assert!(
        timeout(STEP, recv.read_chunk(1, false))
            .await
            .expect("receive reset")
            .is_err()
    );
    let (response, _) = raw_request(
        &mut sender,
        Method::GET,
        &format!("https://{SERVER_NAME}/unknown"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    driver.abort();
}

#[tokio::test]
async fn a_request_below_goaway_can_finish_headers_after_a_classifier_gap() {
    use h3::proto::varint::VarInt;
    use h3::qpack::{HeaderField, encode_stateless};
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = Arc::new(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate(),
            fast_timing(),
        )
        .await
        .expect("Server"),
    );
    let (mut sender, driver) = raw_client(client_connection.clone()).await;
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("{SERVER_NAME}:443"))
        .body(())
        .expect("slot");
    let mut slot = sender.send_request(request).await.expect("slot zero");
    let visitor = server
        .open_tunnel_stream(STEP)
        .await
        .expect("active Visitor");
    slot.recv_response().await.expect("assigned");
    let (mut stalled, _stalled_recv) = client_connection.open_bi().await.expect("stream four");
    stalled
        .write_all(&[0x40])
        .await
        .expect("incomplete classifier");
    let (mut second_stalled, _second_recv) =
        client_connection.open_bi().await.expect("stream eight");
    second_stalled
        .write_all(&[0x40])
        .await
        .expect("second incomplete classifier");
    let (mut send, mut recv) = client_connection.open_bi().await.expect("request twelve");
    assert_eq!(send.id().index(), 3);
    let mut block = Vec::new();
    encode_stateless(
        &mut block,
        [
            HeaderField::new(":method", "GET"),
            HeaderField::new(":scheme", "https"),
            HeaderField::new(":authority", SERVER_NAME),
            HeaderField::new(":path", "/unknown"),
        ],
    )
    .expect("QPACK");
    let mut prefix = vec![1];
    VarInt::from_u32(u32::try_from(block.len()).expect("short headers")).encode(&mut prefix);
    prefix.extend_from_slice(&block[..block.len() - 1]);
    send.write_all(&prefix)
        .await
        .expect("HEADERS except final byte");
    // A later completed request proves intake progressed beyond stream twelve.
    let (response, _) = raw_request(
        &mut sender,
        Method::GET,
        &format!("https://{SERVER_NAME}/unknown"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let shutdown = tokio::spawn({
        let server = server.clone();
        async move { server.shutdown(STEP).await }
    });
    // Eviction observes shutdown without depending on a timer or task scheduling.
    timeout(STEP, stalled.stopped())
        .await
        .expect("shutdown eviction")
        .expect("stopped");
    send.write_all(&block[block.len() - 1..])
        .await
        .expect("finish HEADERS");
    send.finish().expect("request FIN");
    assert_eq!(
        timeout(STEP, read_varint(&mut recv))
            .await
            .expect("accepted request gets response HEADERS"),
        1
    );
    drop(visitor);
    shutdown.await.expect("shutdown");
    driver.abort();
}

type ClientSession =
    h3_webtransport::client::WebTransportSession<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn session_client(
    connection: quinn::Connection,
) -> (RawSendRequest, ClientSession, JoinHandle<()>) {
    let (core, sender) = h3::client::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .webtransport_drafts([h3::ext::WebTransportDraft::Draft07])
        .build(h3_quinn::Connection::new(connection))
        .await
        .expect("H3 Client");
    let (mut driver, mut client) = h3_webtransport::client::new(
        core,
        sender,
        h3_webtransport::client::Limits {
            sessions: std::num::NonZeroUsize::MIN,
            ..Default::default()
        },
    );
    let task = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    let mut sender = client.send_request();
    let (_, mut events) = raw_request(
        &mut sender,
        Method::GET,
        &format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"),
    )
    .await;
    read_event_block(&mut events).await.expect("gate");
    let session = client
        .connect(
            Request::builder()
                .method(Method::CONNECT)
                .uri(format!("https://{SERVER_NAME}/v1/tunnel/session"))
                .body(())
                .expect("CONNECT"),
        )
        .await
        .expect("session");
    assert_eq!(
        session.session_id(),
        h3_webtransport::SessionId::try_from(4_u64).expect("session four")
    );
    assert_eq!(session.draft(), h3::ext::WebTransportDraft::Draft07);
    (sender, session, task)
}

#[tokio::test]
async fn authorization_revocation_ends_the_session_and_connection() {
    use crate::RoleAdapter;
    let fixture = Fixture::new().expect("fixture");
    let server = crate::Server::bind(crate::ServerBindConfig {
        public_bind_addr: localhost(0),
        tunnel_connection_bind_addr: localhost(0),
        readiness_bind_addr: None,
        server_hostname: server_hostname(),
        authorization: crate::ServerAuthorization::empty_managed(),
        public_tls_config: None,
        quic_server_config: fixture.server_config.clone(),
        admission: crate::ServerAdmission::Managed,
    })
    .await
    .expect("bind Server");
    let address = server.tunnel_addr().expect("Tunnel address");
    let mut authorization = server.authorization_adapter();
    authorization
        .apply(crate::ServerManagedInput {
            tunnels: vec![crate::ServerTunnelConfig {
                id: Some(crate::TunnelId::parse("test").expect("Tunnel ID")),
                public_hostnames: vec![
                    crate::PublicHostname::try_from("app.example.test").expect("hostname"),
                ],
                authorized_client_identities: vec![fixture.client_identity.clone()],
            }],
        })
        .await
        .expect("authorize Client");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(server.run_until_shutdown(async {
        let _ = stopped.await;
        crate::ShutdownMode::Fast
    }));
    let connection = fixture
        .client_endpoint
        .connect(address, SERVER_NAME)
        .expect("connect")
        .await
        .expect("mTLS");
    let (_sender, session, driver) = session_client(connection.clone()).await;
    authorization
        .apply(crate::ServerManagedInput { tunnels: vec![] })
        .await
        .expect("revoke Client");
    let error = timeout(STEP, connection.closed())
        .await
        .expect("revocation closes connection");
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
    assert!(
        timeout(STEP, session.closed())
            .await
            .expect("revocation ends session")
            .is_err()
    );
    stop.send(()).expect("shutdown");
    timeout(STEP, server)
        .await
        .expect("Server shutdown")
        .expect("task")
        .expect("Server");
    driver.abort();
}

type ServerSession = h3_webtransport::server::Session<h3_quinn::Connection, Bytes>;

async fn session_server(connection: quinn::Connection) -> (ServerSession, JoinHandle<()>) {
    let core = raw_server(connection).await;
    let (mut driver, acceptor) = h3_webtransport::server::new(core, Default::default());
    let (send, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut send = Some(send);
        let mut events = Vec::new();
        while let Ok(Some(resolver)) = driver.accept().await {
            let (request, mut stream) = resolver.resolve_request().await.expect("request");
            if request.method() == Method::GET {
                respond_events(
                    &mut stream,
                    &TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse(),
                )
                .await;
                events.push(stream);
            } else {
                let session = acceptor.accept(request, stream).await.expect("session");
                send.take().expect("one session").send(session).ok();
            }
        }
    });
    (received.await.expect("Server session"), task)
}

#[tokio::test]
async fn connection_loss_ends_the_session_on_both_runewarp_peers() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = ServerTunnelH3::establish(
        server_connection.clone(),
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server");
    let (_sender, session, driver) = session_client(client_connection).await;
    server_connection.close(0x100_u32.into(), b"connection loss");
    timeout(STEP, server.closed())
        .await
        .expect("Server connection ends");
    assert!(
        timeout(STEP, session.closed())
            .await
            .expect("Client session ends")
            .is_err()
    );
    driver.abort();

    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let hostname = server_hostname();
    let (session, client) = tokio::join!(
        session_server(server_connection),
        ClientTunnelH3::establish(client_connection.clone(), &hostname, no_slots()),
    );
    let (session, driver) = session;
    let client = client.expect("Client");
    client_connection.close(0x100_u32.into(), b"connection loss");
    timeout(STEP, client.closed())
        .await
        .expect("Client connection ends");
    assert!(
        timeout(STEP, session.closed())
            .await
            .expect("Server session ends")
            .is_err()
    );
    driver.abort();
}

#[tokio::test]
async fn production_address_worker_reconnects_after_session_close_or_connect_fin() {
    use crate::client::{
        AddressController, ClientTunnelAttempt, FixedBackoff, SilentAddressWorkerHooks,
        run_address_worker,
    };
    for capsule in [true, false] {
        timeout(Duration::from_secs(8), async {
            let fixture = Fixture::new().expect("fixture");
            // Match the production resolver's first localhost address, including its family.
            let bind = tokio::net::lookup_host(("localhost", 0))
                .await
                .expect("localhost resolves")
                .next()
                .expect("localhost address");
            let endpoint = Endpoint::server(fixture.server_config.clone(), bind)
                .expect("runtime Server endpoint");
            let target = format!(
                "localhost:{}",
                endpoint.local_addr().expect("address").port()
            );
            let directory = tempfile::tempdir().expect("material directory");
            for (name, contents) in [
                ("ca.pem", fixture.server_certificate_pem.as_str()),
                ("client.crt", fixture.client_certificate_pem.as_str()),
                ("client.key", fixture.client_key_pem.as_str()),
            ] {
                std::fs::write(directory.path().join(name), contents).expect("test material");
            }
            std::fs::write(
                directory.path().join("client-identity.txt"),
                fixture.client_identity.to_string(),
            )
            .expect("identity");
            std::fs::write(
                directory.path().join("config.toml"),
                format!(
                    r#"
[client]
server-address = "{target}"
server-trust = "ca-file"
server-ca-file = "ca.pem"
identity-dir = "."
[[client.services]]
backend-address = "127.0.0.1:443"
"#
                ),
            )
            .expect("Client config");
            let settings = Arc::new(
                crate::load_client_config(&directory.path().join("config.toml")).expect("config"),
            );
            let instance = crate::ClientInstancePrep::prepare(&settings)
                .await
                .expect("Client preparation");
            let dial = Arc::new(ClientTunnelAttempt::new(settings, instance, bind));
            let mut controller = AddressController::new();
            controller.add(
                crate::ServerAddress::parse(&target).expect("Server address"),
                move |address, control| {
                    run_address_worker(
                        address,
                        control,
                        dial,
                        Arc::new(SilentAddressWorkerHooks),
                        FixedBackoff(Duration::from_millis(10)),
                    )
                },
            );
            let connection = endpoint
                .accept()
                .await
                .expect("first dial")
                .await
                .expect("mTLS");
            let mut core = raw_server(connection.clone()).await;
            let (_, mut events) = accept_raw_request(&mut core).await;
            respond_events(
                &mut events,
                &TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse(),
            )
            .await;
            let mut session = accept_raw_session(&mut core).await;
            // Availability proves production establishment completed before the close.
            let (request, _slot) = accept_raw_request(&mut core).await;
            assert_eq!(request.method(), Method::CONNECT);
            assert!(request.extensions().get::<h3::ext::Protocol>().is_none());
            if capsule {
                session
                    .send_data(Bytes::from_static(CLOSE_CAPSULE))
                    .await
                    .expect("session close");
            } else {
                session.finish().await.expect("CONNECT FIN");
            }
            let error = connection.closed().await;
            assert_eq!(
                application_close_code(&error),
                Some(Code::H3_NO_ERROR.value())
            );
            let replacement = endpoint
                .accept()
                .await
                .expect("normal worker redials")
                .await
                .expect("replacement mTLS");
            let replacement = ServerTunnelH3::establish(
                replacement,
                crate::ServerHostname::try_from("localhost").expect("hostname"),
                ServerRuntimeGeneration::generate(),
            )
            .await
            .expect("replacement H3");
            let _visitor = replacement
                .open_tunnel_stream(STEP)
                .await
                .expect("replacement session establishes and offers receive slots");
            controller.request_shutdown();
            controller
                .run_until_idle()
                .await
                .expect("worker shuts down");
        })
        .await
        .expect("session close reconnects through production attempt and worker");
    }
}

#[tokio::test]
async fn rejected_session_fails_establishment_without_offering_receive_slots() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let mut server = raw_server(server_connection.clone()).await;
    let client = tokio::spawn(async move {
        ClientTunnelH3::establish_with_timing(
            client_connection,
            &server_hostname(),
            Arc::new(Semaphore::new(1)),
            fast_timing(),
        )
        .await
    });
    let (_, mut events) = accept_raw_request(&mut server).await;
    respond_events(
        &mut events,
        &TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse(),
    )
    .await;
    let (request, mut session) = accept_raw_request(&mut server).await;
    assert_eq!(request.uri().path(), "/v1/tunnel/session");
    session
        .send_response(
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(())
                .expect("rejection"),
        )
        .await
        .expect("response");
    session.finish().await.expect("bodyless");
    let result = timeout(STEP, client)
        .await
        .expect("attempt fails")
        .expect("task");
    assert!(matches!(
        result,
        Err(TunnelH3Error::SessionConnect(
            h3_webtransport::client::ConnectError::Rejected(StatusCode::TOO_MANY_REQUESTS)
        ))
    ));
    let error = timeout(STEP, server_connection.closed())
        .await
        .expect("attempt closes connection");
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
    assert!(
        server.accept().await.unwrap_or(None).is_none(),
        "failed establishment offers no slot"
    );
}

#[tokio::test]
async fn both_peers_advertise_only_draft07_and_one_session() {
    fn assert_profile(settings: std::collections::BTreeMap<u64, u64>) {
        for (id, value) in [(0x8, 1), (0x33, 1), (0xc671706a, 1), (0x6, 16_384)] {
            assert_eq!(settings.get(&id), Some(&value), "setting {id:#x}");
        }
        for other_draft in [0x2b603742, 0x2b603743, 0x14e9cd29, 0x2c7cf000] {
            assert!(
                !settings.contains_key(&other_draft),
                "other draft {other_draft:#x}"
            );
        }
    }
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = ServerTunnelH3::establish(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server");
    assert_profile(advertised_settings(&client_connection).await);
    drop(server);
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let client = tokio::spawn(async move {
        ClientTunnelH3::establish(client_connection, &server_hostname(), no_slots()).await
    });
    assert_profile(advertised_settings(&server_connection).await);
    client.abort();
}

#[tokio::test]
async fn invalid_session_requests_are_bodyless_and_do_not_reserve_a_session() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let _server = ServerTunnelH3::establish(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server");
    let (mut sender, driver) = raw_client(client_connection).await;
    for (uri, subprotocol, status) in [
        (
            format!("https://{SERVER_NAME}/wrong"),
            false,
            StatusCode::NOT_FOUND,
        ),
        (
            "https://other.example.test/v1/tunnel/session".to_owned(),
            false,
            StatusCode::MISDIRECTED_REQUEST,
        ),
        (
            format!("https://{SERVER_NAME}/v1/tunnel/session"),
            true,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .body(())
            .expect("CONNECT");
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEB_TRANSPORT);
        if subprotocol {
            request.headers_mut().insert(
                "sec-webtransport-protocol",
                "unsupported".parse().expect("header"),
            );
        }
        let mut stream = sender.send_request(request).await.expect("open request");
        assert_eq!(
            stream.recv_response().await.expect("response").status(),
            status
        );
        assert!(stream.recv_data().await.expect("bodyless").is_none());
    }
    let mut session = session_request(&mut sender, "/v1/tunnel/session").await;
    assert_eq!(
        session
            .recv_response()
            .await
            .expect("session still available")
            .status(),
        StatusCode::OK
    );
    driver.abort();
}

#[tokio::test]
async fn client_connect_fin_closes_the_whole_tunnel_without_error() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let _server = ServerTunnelH3::establish(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server");
    let (mut sender, driver) = raw_client(client_connection.clone()).await;
    let mut session = session_request(&mut sender, "/v1/tunnel/session").await;
    assert_eq!(
        session.recv_response().await.expect("accepted").status(),
        StatusCode::OK
    );
    session.finish().await.expect("Client CONNECT FIN");
    let error = timeout(STEP, client_connection.closed())
        .await
        .expect("Server observes CONNECT end");
    assert_eq!(
        application_close_code(&error),
        Some(Code::H3_NO_ERROR.value())
    );
    driver.abort();
}
