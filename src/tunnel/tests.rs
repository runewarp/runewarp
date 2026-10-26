//! Loopback tests for HTTP/3 Tunnel connections.
//!
//! Each test runs a real Quinn/rustls connection with required mTLS. Raw `h3` peers stand in for
//! the other side where a test needs to observe or violate the wire contract.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use h3::error::Code;
use http::{Method, Request, Response, StatusCode, header};
use quinn::{ConnectionError, Endpoint};
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::events::{ServerRuntimeGeneration, TunnelEventState};
use super::{
    ClientTunnelH3, ServerTunnelH3, TUNNEL_EVENTS_PATH, TunnelH3Error, TunnelH3Timing,
    make_client_tunnel_h3_config, make_server_tunnel_h3_config,
};
use crate::quic::StaticClientIdentityAdmission;
use crate::tls_material::{certificate_chain_from_pem, private_key_from_pem};
use crate::{ClientIdentity, ServerHostname, generate_client_identity};

mod candidates;
mod sessions;
mod snapshots;
mod streams;
mod withdrawal;

const SERVER_NAME: &str = "tunnel.example.test";
const STEP: Duration = Duration::from_secs(2);

type RawServerConnection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type RawServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type RawSendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type RawClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

fn fast_timing() -> TunnelH3Timing {
    TunnelH3Timing {
        request_deadline: Duration::from_secs(1),
        keepalive_comment_interval: Duration::from_millis(50),
        blocked_write_deadline: Duration::from_secs(1),
        initial_state_deadline: Duration::from_millis(300),
        silence_deadline: Duration::from_millis(300),
        resubscribe_delay: Duration::from_millis(20),
        post_quiescence_close: Duration::from_millis(300),
    }
}

/// A Client stream budget with no permits: the Client offers no Visitor credit.
fn no_credit() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(0))
}

fn server_hostname() -> ServerHostname {
    ServerHostname::try_from(SERVER_NAME).expect("valid Server hostname")
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Server and Client material plus endpoints for authenticated loopback connections.
struct Fixture {
    server_endpoint: Endpoint,
    client_endpoint: Endpoint,
    client_identity: ClientIdentity,
    server_config: quinn::ServerConfig,
    server_certificate_pem: String,
    client_certificate_pem: String,
    client_key_pem: String,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        Self::with_admitted(None)
    }

    /// Admit only `admitted`, or the fixture's own Client identity when `None`.
    fn with_admitted(admitted: Option<ClientIdentity>) -> io::Result<Self> {
        let server =
            generate_simple_self_signed(vec![SERVER_NAME.to_owned(), "localhost".to_owned()])
                .map_err(io::Error::other)?;
        let server_certificate_pem = server.cert.pem();
        let server_certificate = CertificateDer::from(server.cert);
        let server_key: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(server.signing_key.serialize_der()).into();

        let generated = generate_client_identity().map_err(io::Error::other)?;
        let client_chain = certificate_chain_from_pem(generated.certificate_pem.as_bytes())
            .map_err(io::Error::other)?;
        let client_key =
            private_key_from_pem(generated.private_key_pem.as_bytes()).map_err(io::Error::other)?;
        let admitted = admitted.unwrap_or_else(|| generated.client_identity.clone());

        let server_config = make_server_tunnel_h3_config(
            vec![server_certificate.clone()],
            server_key,
            Arc::new(StaticClientIdentityAdmission::from_identities(&[admitted])),
        )
        .map_err(io::Error::other)?;
        let server_endpoint = Endpoint::server(server_config.clone(), localhost(0))?;

        let mut roots = RootCertStore::empty();
        roots.add(server_certificate).map_err(io::Error::other)?;
        let mut client_endpoint = Endpoint::client(localhost(0))?;
        client_endpoint.set_default_client_config(
            make_client_tunnel_h3_config(roots, client_chain, client_key)
                .map_err(io::Error::other)?,
        );

        Ok(Self {
            server_endpoint,
            client_endpoint,
            client_identity: generated.client_identity,
            server_config,
            server_certificate_pem,
            client_certificate_pem: generated.certificate_pem,
            client_key_pem: generated.private_key_pem,
        })
    }

    /// Complete one authenticated QUIC handshake: `(server side, client side)`.
    async fn connect(&self) -> io::Result<(quinn::Connection, quinn::Connection)> {
        self.connect_inner(None).await
    }

    /// Like [`Self::connect`], with a test-specific Client QUIC configuration.
    async fn connect_with(
        &self,
        client_config: quinn::ClientConfig,
    ) -> io::Result<(quinn::Connection, quinn::Connection)> {
        self.connect_inner(Some(client_config)).await
    }

    async fn connect_inner(
        &self,
        client_config: Option<quinn::ClientConfig>,
    ) -> io::Result<(quinn::Connection, quinn::Connection)> {
        let server_addr = self.server_endpoint.local_addr()?;
        let accept = async {
            let incoming = self
                .server_endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::other("server endpoint closed"))?;
            incoming.await.map_err(io::Error::other)
        };
        let connect = async {
            match client_config {
                Some(config) => self
                    .client_endpoint
                    .connect_with(config, server_addr, SERVER_NAME),
                None => self.client_endpoint.connect(server_addr, SERVER_NAME),
            }
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)
        };
        timeout(STEP, async { tokio::try_join!(accept, connect) })
            .await
            .map_err(|_| io::Error::other("QUIC handshake timed out"))?
    }
}

async fn establish_pair(
    fixture: &Fixture,
    generation: impl Into<super::ServerTunnelEvents>,
    budget: Arc<Semaphore>,
) -> (ServerTunnelH3, ClientTunnelH3) {
    let (server_connection, client_connection) =
        fixture.connect().await.expect("authenticated handshake");
    let hostname = server_hostname();
    let (server, client) = timeout(STEP, async {
        tokio::join!(
            ServerTunnelH3::establish_with_timing(
                server_connection,
                server_hostname(),
                generation,
                fast_timing(),
            ),
            ClientTunnelH3::establish_with_timing(
                client_connection,
                &hostname,
                budget,
                fast_timing(),
            ),
        )
    })
    .await
    .expect("establishment finishes");
    (
        server.expect("server establishes"),
        client.expect("client passes the gate"),
    )
}

/// HTTP/3 application close code of a closed connection.
fn application_close_code(error: &ConnectionError) -> Option<u64> {
    match error {
        ConnectionError::ApplicationClosed(close) => Some(close.error_code.into_inner()),
        _ => None,
    }
}

async fn raw_client(connection: quinn::Connection) -> (RawSendRequest, JoinHandle<()>) {
    let (mut driver, send_request) = h3::client::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .webtransport_drafts([h3::ext::WebTransportDraft::Draft07])
        .build(h3_quinn::Connection::new(connection))
        .await
        .expect("raw h3 client");
    let driver = tokio::spawn(async move {
        let _ = poll_fn(|context| driver.poll_close(context)).await;
    });
    (send_request, driver)
}

async fn raw_server(connection: quinn::Connection) -> RawServerConnection {
    h3::server::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .webtransport_drafts([h3::ext::WebTransportDraft::Draft07])
        .build(h3_quinn::Connection::new(connection))
        .await
        .expect("raw h3 server")
}

async fn raw_request(
    send_request: &mut RawSendRequest,
    method: Method,
    uri: &str,
) -> (Response<()>, RawClientStream) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .expect("valid request");
    let mut stream = send_request
        .send_request(request)
        .await
        .expect("request opens");
    stream.finish().await.expect("request ends");
    let response = timeout(STEP, stream.recv_response())
        .await
        .expect("response arrives")
        .expect("valid response");
    (response, stream)
}

/// Read DATA until the next blank-line event boundary, or `None` at FIN.
async fn read_event_block(stream: &mut RawClientStream) -> Option<String> {
    let mut block = String::new();
    while !block.ends_with("\n\n") {
        let mut chunk = timeout(STEP, stream.recv_data())
            .await
            .expect("event data arrives")
            .expect("event stream stays valid")?;
        block.push_str(
            std::str::from_utf8(&chunk.copy_to_bytes(chunk.remaining())).expect("UTF-8 events"),
        );
    }
    Some(block)
}

async fn accept_raw_request(
    connection: &mut RawServerConnection,
) -> (Request<()>, RawServerStream) {
    let resolver = timeout(STEP, connection.accept())
        .await
        .expect("request arrives")
        .expect("connection stays open")
        .expect("request stream");
    resolver.resolve_request().await.expect("valid request")
}

async fn respond_events(stream: &mut RawServerStream, body: &[u8]) {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(())
        .expect("valid response");
    stream.send_response(response).await.expect("response sent");
    if !body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(body))
            .await
            .expect("event data sent");
    }
}

#[tokio::test]
async fn client_passes_the_gate_with_the_server_generation() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();

    let (server, client) = establish_pair(&fixture, generation, no_credit()).await;

    assert_eq!(client.server_generation(), generation);
    assert_eq!(server.client_identity(), &fixture.client_identity);
}

#[tokio::test]
async fn server_refuses_a_client_identity_it_does_not_admit() {
    let other = generate_client_identity()
        .expect("identity")
        .client_identity;
    let fixture = Fixture::with_admitted(Some(other)).expect("fixture");

    assert!(fixture.connect().await.is_err());
}

#[tokio::test]
async fn resumed_connections_never_send_application_early_data() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("first");
    // Wait for the resumption ticket, then close the first connection.
    sleep(Duration::from_millis(50)).await;
    client_connection.close(0_u8.into(), b"");
    drop(server_connection);

    let server_addr = fixture.server_endpoint.local_addr().expect("address");
    let connecting = fixture
        .client_endpoint
        .connect(server_addr, SERVER_NAME)
        .expect("second connection starts");

    assert!(connecting.into_0rtt().is_err());
}

#[tokio::test]
async fn client_rejects_an_incompatible_event_stream_and_closes_the_connection() {
    let generation = ServerRuntimeGeneration::generate();
    let legacy_state = format!("event: state\ndata: {{\"generation\":\"{generation}\"}}\n\n");
    let null_hint = format!(
        "event: snapshot\ndata: {{\"generation\":\"{generation}\",\"replacement_generation\":null}}\n\n"
    );
    for (body, reason) in [
        (legacy_state.into_bytes(), "unexpected-event-type"),
        (null_hint.into_bytes(), "malformed-state"),
        (
            b"event: other\ndata: {}\n\n".to_vec(),
            "unexpected-event-type",
        ),
        (b"data: \xff\n\n".to_vec(), "invalid-sse-framing"),
    ] {
        let fixture = Fixture::new().expect("fixture");
        let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
        let fake_server = tokio::spawn(async move {
            let mut connection = raw_server(server_connection.clone()).await;
            let (_, mut stream) = accept_raw_request(&mut connection).await;
            respond_events(&mut stream, &body).await;
            let closed = server_connection.closed().await;
            drop((stream, connection));
            closed
        });

        let result = ClientTunnelH3::establish_with_timing(
            client_connection,
            &server_hostname(),
            no_credit(),
            fast_timing(),
        )
        .await;

        assert!(
            matches!(result, Err(TunnelH3Error::Incompatible(actual)) if actual == reason),
            "{reason}: {:?}",
            result.err()
        );
        let closed = timeout(STEP, fake_server)
            .await
            .expect("server sees close")
            .expect("fake server task");
        assert_eq!(
            application_close_code(&closed),
            Some(Code::H3_GENERAL_PROTOCOL_ERROR.value()),
            "{reason}"
        );
    }
}

#[tokio::test]
async fn client_rejects_a_non_event_stream_response() {
    for (status, content_type, reason) in [
        (
            StatusCode::NOT_FOUND,
            "text/event-stream",
            "unexpected-status",
        ),
        (
            StatusCode::OK,
            "application/json",
            "unexpected-content-type",
        ),
    ] {
        let fixture = Fixture::new().expect("fixture");
        let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
        let fake_server = tokio::spawn(async move {
            let mut connection = raw_server(server_connection.clone()).await;
            let (_, mut stream) = accept_raw_request(&mut connection).await;
            let response = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .body(())
                .expect("valid response");
            stream.send_response(response).await.expect("response sent");
            let _ = stream.finish().await;
            let _ = server_connection.closed().await;
            drop(connection);
        });

        let result = ClientTunnelH3::establish_with_timing(
            client_connection,
            &server_hostname(),
            no_credit(),
            fast_timing(),
        )
        .await;

        assert!(
            matches!(result, Err(TunnelH3Error::Incompatible(actual)) if actual == reason),
            "{reason}: {:?}",
            result.err()
        );
        fake_server.abort();
    }
}

#[tokio::test]
async fn comment_keepalives_do_not_satisfy_the_gate() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection.clone()).await;
        let (_, mut stream) = accept_raw_request(&mut connection).await;
        respond_events(&mut stream, b": keepalive\n\n").await;
        loop {
            sleep(Duration::from_millis(50)).await;
            if stream
                .send_data(Bytes::from_static(b": keepalive\n\n"))
                .await
                .is_err()
            {
                return;
            }
        }
    });

    let result = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await;

    assert!(
        matches!(result, Err(TunnelH3Error::InitialStateTimeout)),
        "{:?}",
        result.err()
    );
    fake_server.abort();
}

#[tokio::test]
async fn client_resubscribes_after_an_end_or_silence_and_keeps_the_connection() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let state = TunnelEventState::current(generation).encode_sse();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection).await;
        // First subscription ends with FIN after its state.
        let (_, mut first) = accept_raw_request(&mut connection).await;
        respond_events(&mut first, &state).await;
        first.finish().await.expect("first subscription ends");
        let session = accept_raw_session(&mut connection).await;
        // Second subscription goes silent after its state.
        let (_, mut second) = accept_raw_request(&mut connection).await;
        respond_events(&mut second, &state).await;
        // Third subscription proves the Client resubscribed after silence.
        let (request, mut third) = accept_raw_request(&mut connection).await;
        respond_events(&mut third, &state).await;
        (request, connection, second, third, session)
    });

    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await
    .expect("gate passes");

    let (request, _connection, _second, _third, _session) =
        timeout(Duration::from_secs(3), fake_server)
            .await
            .expect("Client resubscribes twice")
            .expect("fake server task");
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().path(), TUNNEL_EVENTS_PATH);
    assert_eq!(client.server_generation(), generation);
    assert!(
        timeout(Duration::from_millis(100), client.closed())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn client_closes_when_the_generation_changes_on_one_connection() {
    let fixture = Fixture::new().expect("fixture");
    let first_state = TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse();
    let second_state = TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let fake_server = tokio::spawn(async move {
        let mut connection = raw_server(server_connection.clone()).await;
        let (_, mut stream) = accept_raw_request(&mut connection).await;
        respond_events(&mut stream, &first_state).await;
        let session = accept_raw_session(&mut connection).await;
        stream
            .send_data(second_state)
            .await
            .expect("changed state sent");
        let closed = server_connection.closed().await;
        drop((stream, session, connection));
        closed
    });

    let client = ClientTunnelH3::establish_with_timing(
        client_connection,
        &server_hostname(),
        no_credit(),
        fast_timing(),
    )
    .await
    .expect("gate passes");

    let closed = timeout(STEP, fake_server)
        .await
        .expect("Client closes")
        .expect("fake server task");
    assert_eq!(
        application_close_code(&closed),
        Some(Code::H3_GENERAL_PROTOCOL_ERROR.value())
    );
    drop(client);
}

#[tokio::test]
async fn server_sends_state_first_then_keepalives_and_supersedes_older_subscriptions() {
    let fixture = Fixture::new().expect("fixture");
    let generation = ServerRuntimeGeneration::generate();
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (server, (mut send_request, _driver)) = tokio::join!(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            generation,
            fast_timing(),
        ),
        raw_client(client_connection),
    );
    let _server = server.expect("server establishes");
    let uri = format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}");

    let (response, mut first) = raw_request(&mut send_request, Method::GET, &uri).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.as_bytes()),
        Some(b"text/event-stream".as_slice())
    );
    let expected_state =
        String::from_utf8(TunnelEventState::current(generation).encode_sse().to_vec())
            .expect("UTF-8 state");
    assert_eq!(
        read_event_block(&mut first).await,
        Some(expected_state.clone())
    );
    assert_eq!(
        read_event_block(&mut first).await.as_deref(),
        Some(": keepalive\n\n")
    );

    let (_, mut second) = raw_request(&mut send_request, Method::GET, &uri).await;
    assert_eq!(read_event_block(&mut second).await, Some(expected_state));
    // The superseded subscription ends with FIN after any in-flight keepalive.
    let mut ended = false;
    for _ in 0..4 {
        if read_event_block(&mut first).await.is_none() {
            ended = true;
            break;
        }
    }
    assert!(ended, "the older subscription should end");
}

#[tokio::test]
async fn server_answers_other_requests_with_bodyless_statuses() {
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
    let _server = server.expect("server establishes");

    for (method, uri, status, allow) in [
        (
            Method::GET,
            "https://other.example.test/v1/tunnel/events",
            StatusCode::MISDIRECTED_REQUEST,
            None,
        ),
        (
            Method::GET,
            "https://tunnel.example.test/v1/unknown",
            StatusCode::NOT_FOUND,
            None,
        ),
        (
            Method::PUT,
            "https://tunnel.example.test/v1/tunnel/events",
            StatusCode::METHOD_NOT_ALLOWED,
            Some("GET"),
        ),
    ] {
        let (response, mut stream) = raw_request(&mut send_request, method, uri).await;

        assert_eq!(response.status(), status, "{uri}");
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .and_then(|value| value.to_str().ok()),
            allow
        );
        let body = timeout(STEP, stream.recv_data())
            .await
            .expect("response ends")
            .expect("valid response stream");
        assert!(body.is_none(), "{uri} must be bodyless");
    }
}

#[tokio::test]
async fn shutdown_sends_goaway_ends_the_event_stream_and_closes_cleanly() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let (server, (mut send_request, _driver)) = tokio::join!(
        ServerTunnelH3::establish_with_timing(
            server_connection,
            server_hostname(),
            ServerRuntimeGeneration::generate(),
            fast_timing(),
        ),
        raw_client(client_connection.clone()),
    );
    let server = server.expect("server establishes");
    let uri = format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}");
    let (_, mut events) = raw_request(&mut send_request, Method::GET, &uri).await;
    assert!(read_event_block(&mut events).await.is_some());

    let shutdown = tokio::spawn(async move { server.shutdown(STEP).await });
    let mut ended = false;
    for _ in 0..4 {
        if read_event_block(&mut events).await.is_none() {
            ended = true;
            break;
        }
    }
    assert!(ended, "GOAWAY should end the event stream with FIN");

    let after_goaway = Request::get(&uri).body(()).expect("valid request");
    assert!(send_request.send_request(after_goaway).await.is_err());

    timeout(STEP, shutdown)
        .await
        .expect("shutdown finishes")
        .expect("shutdown task");
    let closed = timeout(STEP, client_connection.closed())
        .await
        .expect("connection closes");
    assert_eq!(
        application_close_code(&closed),
        Some(Code::H3_NO_ERROR.value())
    );
}

#[tokio::test]
async fn dropping_either_handle_closes_the_connection_without_error() {
    let fixture = Fixture::new().expect("fixture");
    let (server, client) =
        establish_pair(&fixture, ServerRuntimeGeneration::generate(), no_credit()).await;

    drop(server);

    let closed = timeout(STEP, client.closed())
        .await
        .expect("connection closes");
    assert_eq!(
        application_close_code(&closed),
        Some(Code::H3_NO_ERROR.value())
    );
}

/// How a raw client sends one event-stream request after its HEADERS.
struct RequestShape {
    content_length: Option<&'static str>,
    data: Option<&'static [u8]>,
    trailers: bool,
    finish: bool,
}

/// The Server's answer: a final status, or a stream reset with its H3 code.
#[derive(Debug, PartialEq)]
enum RequestOutcome {
    Status(StatusCode),
    Reset(Code),
}

async fn send_shaped_events_request(
    send_request: &mut RawSendRequest,
    shape: &RequestShape,
) -> RequestOutcome {
    let mut request = Request::get(format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"));
    if let Some(length) = shape.content_length {
        request = request.header(header::CONTENT_LENGTH, length);
    }
    let mut stream = send_request
        .send_request(request.body(()).expect("valid request"))
        .await
        .expect("request opens");
    if let Some(data) = shape.data {
        stream
            .send_data(Bytes::from_static(data))
            .await
            .expect("request data sent");
    }
    if shape.trailers {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trailer", "1".parse().expect("valid header"));
        stream.send_trailers(trailers).await.expect("trailers sent");
    }
    if shape.finish {
        stream.finish().await.expect("request ends");
    }
    match timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("the Server answers")
    {
        Ok(response) => RequestOutcome::Status(response.status()),
        Err(h3::error::StreamError::RemoteTerminate { code, .. }) => RequestOutcome::Reset(code),
        Err(error) => panic!("unexpected stream error: {error:?}"),
    }
}

#[tokio::test]
async fn event_stream_requests_must_be_complete_and_bodyless() {
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
    let _server = server.expect("server establishes");
    let shape = |content_length, data, trailers, finish| RequestShape {
        content_length,
        data,
        trailers,
        finish,
    };

    for (label, request, expected) in [
        (
            "zero padded length",
            shape(Some("00"), None, false, true),
            RequestOutcome::Status(StatusCode::OK),
        ),
        (
            "content without a length",
            shape(None, Some(b"body"), false, true),
            RequestOutcome::Status(StatusCode::BAD_REQUEST),
        ),
        (
            "trailers",
            shape(None, None, true, true),
            RequestOutcome::Status(StatusCode::BAD_REQUEST),
        ),
        (
            "positive declared length",
            shape(Some("4"), Some(b"body"), false, true),
            RequestOutcome::Status(StatusCode::BAD_REQUEST),
        ),
        (
            "malformed length",
            shape(Some("abc"), None, false, true),
            RequestOutcome::Reset(Code::H3_MESSAGE_ERROR),
        ),
        (
            "conflicting length lists",
            shape(Some("0, 1"), None, false, true),
            RequestOutcome::Reset(Code::H3_MESSAGE_ERROR),
        ),
        (
            "content beyond a zero length",
            shape(Some("0"), Some(b"body"), false, true),
            RequestOutcome::Reset(Code::H3_MESSAGE_ERROR),
        ),
        (
            "request never ends",
            shape(None, None, false, false),
            RequestOutcome::Status(StatusCode::REQUEST_TIMEOUT),
        ),
    ] {
        assert_eq!(
            send_shaped_events_request(&mut send_request, &request).await,
            expected,
            "{label}"
        );
    }
}

/// Read a QUIC varint without pulling bytes from the next HTTP/3 field.
async fn read_varint(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> u64 {
    use tokio::io::AsyncReadExt;
    let mut first = [0];
    stream.read_exact(&mut first).await.expect("varint starts");
    let width = 1_usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    for _ in 1..width {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.expect("varint ends");
        value = (value << 8) | u64::from(byte[0]);
    }
    value
}

async fn advertised_settings(
    connection: &quinn::Connection,
) -> std::collections::BTreeMap<u64, u64> {
    timeout(STEP, async {
        loop {
            let mut stream = connection.accept_uni().await.expect("H3 uni stream");
            if read_varint(&mut stream).await != 0 {
                continue;
            }
            assert_eq!(read_varint(&mut stream).await, 4, "SETTINGS is first");
            let length = read_varint(&mut stream).await;
            assert!(length <= 1024, "bounded test SETTINGS payload");
            let mut payload = vec![0; usize::try_from(length).expect("small length")];
            stream
                .read_exact(&mut payload)
                .await
                .expect("SETTINGS payload");
            let mut payload = payload.as_slice();
            let mut settings = std::collections::BTreeMap::new();
            while !payload.is_empty() {
                let id = read_varint(&mut payload).await;
                let value = read_varint(&mut payload).await;
                assert!(settings.insert(id, value).is_none(), "no duplicate setting");
            }
            return settings;
        }
    })
    .await
    .expect("SETTINGS arrive")
}

async fn advertised_header_bound(connection: &quinn::Connection) -> u64 {
    *advertised_settings(connection)
        .await
        .get(&6)
        .expect("header bound")
}

#[tokio::test]
async fn both_peers_advertise_a_16_kib_header_section_bound() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = ServerTunnelH3::establish(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server establishes");
    assert_eq!(advertised_header_bound(&client_connection).await, 16_384);
    drop(server);

    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let client = tokio::spawn(async move {
        ClientTunnelH3::establish(client_connection, &server_hostname(), no_credit()).await
    });
    assert_eq!(advertised_header_bound(&server_connection).await, 16_384);
    client.abort();
}

#[tokio::test]
async fn oversized_request_headers_are_bodyless_rejections_before_handler_spawn_and_allow_reuse() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = ServerTunnelH3::establish(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server establishes");
    // Send before polling the raw Client driver, so its cached SETTINGS cannot prevent this
    // deliberately over-limit request from reaching the Server.
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(client_connection))
        .await
        .expect("raw Client");
    let request = Request::get(format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"))
        .header("x-padding", "a".repeat(16_384))
        .body(())
        .expect("valid request");
    let mut stream = timeout(STEP, sender.send_request(request))
        .await
        .expect("request opens promptly")
        .expect("raw Client has not received SETTINGS");
    stream.finish().await.expect("request FIN");
    let driver = tokio::spawn(async move {
        let _ = poll_fn(|context| driver.poll_close(context)).await;
    });
    let response = timeout(STEP, stream.recv_response())
        .await
        .expect("rejection arrives")
        .expect("bodyless rejection response");
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert!(
        timeout(STEP, stream.recv_data())
            .await
            .expect("response ends")
            .expect("valid body")
            .is_none()
    );
    assert_eq!(server.handlers_spawned(), 0);

    let (response, mut events) = raw_request(
        &mut sender,
        Method::GET,
        &format!("https://{SERVER_NAME}{TUNNEL_EVENTS_PATH}"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        read_event_block(&mut events)
            .await
            .expect("snapshot event")
            .contains("event: snapshot")
    );
    assert_eq!(server.handlers_spawned(), 1);
    driver.abort();
}

#[tokio::test]
async fn a_stalled_header_section_does_not_block_other_requests() {
    let fixture = Fixture::new().expect("fixture");
    let (server_connection, client_connection) = fixture.connect().await.expect("handshake");
    let server = ServerTunnelH3::establish(
        server_connection,
        server_hostname(),
        ServerRuntimeGeneration::generate(),
    )
    .await
    .expect("Server establishes");
    let (mut stalled_send, _stalled_recv) = client_connection.open_bi().await.expect("raw stream");
    // HEADERS type with no length or payload, kept open beyond the valid request's deadline.
    stalled_send.write_all(&[1]).await.expect("partial HEADERS");
    let (mut sender, driver) = raw_client(client_connection).await;
    let (response, _) = timeout(
        STEP,
        raw_request(
            &mut sender,
            Method::GET,
            &format!("https://{SERVER_NAME}/unknown"),
        ),
    )
    .await
    .expect("valid request finishes before the stalled header's five-second deadline");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(server.handlers_spawned(), 1);
    driver.abort();
}

/// Accept the mandatory session while a fake Server exercises event-stream behavior.
async fn accept_raw_session(connection: &mut RawServerConnection) -> RawServerStream {
    let (request, mut stream) = accept_raw_request(connection).await;
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.uri().path(), super::TUNNEL_SESSION_PATH);
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .body(())
                .expect("response"),
        )
        .await
        .expect("session accepted");
    stream
}
