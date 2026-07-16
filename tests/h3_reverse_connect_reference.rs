// THROWAWAY PROTOTYPE for #173. This test-only reference must not be wired into
// Runewarp's production Tunnel runtime.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3_quinn::Connection as H3QuinnConnection;
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const H3_ALPN: &[u8] = b"h3";
const CONNECTION_REQUEST: &[u8] = b"CONNECTION_REQUEST:1";
const VISITOR_INITIAL_BYTES: &[u8] = b"ping";
const BACKEND_RESPONSE: &[u8] = b"pong";

#[derive(Debug)]
struct ReferenceTrace {
    alpn: Vec<u8>,
    events: Vec<&'static str>,
}

#[tokio::test]
async fn strict_reverse_connect_reference_forwards_visitor_initial_bytes_through_mtls_h3() {
    let trace = tokio::time::timeout(Duration::from_secs(5), strict_reverse_connect_reference())
        .await
        .map_err(|_| "strict Reverse CONNECT reference timed out".to_owned())
        .and_then(|result| result)
        .expect("the reference must prove the listen, request, accept, and proxied-byte sequence");

    assert_eq!(trace.alpn, H3_ALPN);
    assert_eq!(
        trace.events,
        vec![
            "tunnel-mtls-established",
            "h3-connect-listen-accepted",
            "visitor-initial-bytes-buffered",
            "connection-request-sent",
            "connect-accept-received",
            "connect-accept-confirmed",
            "visitor-bytes-forwarded-to-backend",
            "backend-bytes-forwarded-to-visitor",
        ]
    );
}

async fn strict_reverse_connect_reference() -> Result<ReferenceTrace, String> {
    let (server_certificate, server_key) = self_signed_certificate("tunnel.example.test")?;
    let (client_certificate, client_key) = self_signed_certificate("client.example.test")?;
    let server_config = h3_server_config(
        server_certificate.clone(),
        server_key,
        client_certificate.clone(),
    )?;
    let client_config = h3_client_config(server_certificate, client_certificate, client_key)?;

    let backend_listener = TcpListener::bind(localhost(0)).await.map_err(display)?;
    let backend_address = backend_listener.local_addr().map_err(display)?;
    let backend_task = tokio::spawn(async move {
        let (mut backend, _) = backend_listener.accept().await.map_err(display)?;
        let mut received = [0_u8; VISITOR_INITIAL_BYTES.len()];
        backend.read_exact(&mut received).await.map_err(display)?;
        if received != VISITOR_INITIAL_BYTES {
            return Err("backend received unexpected initial bytes".to_owned());
        }
        backend.write_all(BACKEND_RESPONSE).await.map_err(display)?;
        Ok::<_, String>(())
    });

    let visitor_listener = TcpListener::bind(localhost(0)).await.map_err(display)?;
    let visitor_address = visitor_listener.local_addr().map_err(display)?;
    let server_endpoint = quinn::Endpoint::server(server_config, localhost(0)).map_err(display)?;
    let server_address = server_endpoint.local_addr().map_err(display)?;
    let (listener_ready, listener_ready_rx) = oneshot::channel();
    let (server_completed, server_completed_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        run_h3_server_reference(
            server_endpoint,
            visitor_listener,
            listener_ready,
            server_completed,
        )
        .await
    });

    let mut client_endpoint = quinn::Endpoint::client(localhost(0)).map_err(display)?;
    client_endpoint.set_default_client_config(client_config);
    let client_connection = client_endpoint
        .connect(server_address, "tunnel.example.test")
        .map_err(display)?
        .await
        .map_err(|error| format!("connect mTLS H3 Client: {error}"))?;
    let alpn = negotiated_alpn(&client_connection)?;
    let client_task = tokio::spawn(run_h3_client_reference(
        client_connection,
        backend_address,
        server_completed_rx,
    ));

    listener_ready_rx.await.map_err(display)?;
    let mut visitor = TcpStream::connect(visitor_address).await.map_err(display)?;
    visitor
        .write_all(VISITOR_INITIAL_BYTES)
        .await
        .map_err(display)?;
    let mut visitor_response = [0_u8; BACKEND_RESPONSE.len()];
    visitor
        .read_exact(&mut visitor_response)
        .await
        .map_err(display)?;
    if visitor_response != BACKEND_RESPONSE {
        return Err("Visitor did not receive the backend response".to_owned());
    }

    let mut events = server_task.await.map_err(display)??;
    client_task.await.map_err(display)??;
    backend_task.await.map_err(display)??;
    events.push("visitor-bytes-forwarded-to-backend");
    events.push("backend-bytes-forwarded-to-visitor");

    Ok(ReferenceTrace { alpn, events })
}

async fn run_h3_server_reference(
    endpoint: quinn::Endpoint,
    visitor_listener: TcpListener,
    listener_ready: oneshot::Sender<()>,
    server_completed: oneshot::Sender<()>,
) -> Result<Vec<&'static str>, String> {
    let connection = endpoint
        .accept()
        .await
        .ok_or_else(|| "H3 server endpoint closed before a Client connected".to_owned())?
        .await
        .map_err(display)?;
    if negotiated_alpn(&connection)? != H3_ALPN {
        return Err("Client did not negotiate H3 ALPN".to_owned());
    }

    let mut h3_server = h3::server::builder()
        .enable_extended_connect(true)
        .build(H3QuinnConnection::new(connection))
        .await
        .map_err(|error| format!("build H3 server: {error}"))?;
    let listener_request = h3_server
        .accept()
        .await
        .map_err(|error| format!("accept connect-listen: {error}"))?
        .ok_or_else(|| "Client closed before connect-listen".to_owned())?;
    let (listener_headers, mut listener_stream) = listener_request
        .resolve_request()
        .await
        .map_err(|error| format!("resolve connect-listen: {error}"))?;
    if listener_headers.method() != http::Method::POST
        || listener_headers.uri().path() != "/connect-listen"
    {
        return Err("reference expected the H3 connect-listen request".to_owned());
    }
    listener_stream
        .send_response(ok_response())
        .await
        .map_err(|error| format!("respond to connect-listen: {error}"))?;
    listener_ready
        .send(())
        .map_err(|_| "Visitor was not waiting for connect-listen".to_owned())?;

    let (mut visitor, _) = visitor_listener.accept().await.map_err(display)?;
    let mut visitor_initial_bytes = [0_u8; VISITOR_INITIAL_BYTES.len()];
    visitor
        .read_exact(&mut visitor_initial_bytes)
        .await
        .map_err(|error| format!("read Visitor initial bytes: {error}"))?;
    if visitor_initial_bytes != VISITOR_INITIAL_BYTES {
        return Err("Server buffered unexpected Visitor initial bytes".to_owned());
    }
    listener_stream
        .send_data(Bytes::from_static(CONNECTION_REQUEST))
        .await
        .map_err(|error| format!("send connection request: {error}"))?;

    let accept_request = h3_server
        .accept()
        .await
        .map_err(|error| format!("accept connect-accept: {error}"))?
        .ok_or_else(|| "Client closed before connect-accept".to_owned())?;
    let (accept_headers, mut accept_stream) = accept_request
        .resolve_request()
        .await
        .map_err(|error| format!("resolve connect-accept: {error}"))?;
    if accept_headers.method() != http::Method::POST
        || accept_headers.uri().path() != "/connect-accept/1"
    {
        return Err("reference expected the H3 connect-accept request".to_owned());
    }
    accept_stream
        .send_response(ok_response())
        .await
        .map_err(|error| format!("confirm connect-accept: {error}"))?;
    accept_stream
        .send_data(Bytes::copy_from_slice(&visitor_initial_bytes))
        .await
        .map_err(|error| format!("send Visitor bytes: {error}"))?;
    let mut backend_response = accept_stream
        .recv_data()
        .await
        .map_err(|error| format!("receive backend response: {error}"))?
        .ok_or_else(|| "Client closed connect-accept before backend response".to_owned())?;
    let backend_response = backend_response.copy_to_bytes(backend_response.remaining());
    if backend_response != BACKEND_RESPONSE {
        return Err("connect-accept did not carry the backend response".to_owned());
    }
    visitor
        .write_all(&backend_response)
        .await
        .map_err(display)?;
    server_completed
        .send(())
        .map_err(|_| "Client stopped before the Server completed the reference flow".to_owned())?;

    Ok(vec![
        "tunnel-mtls-established",
        "h3-connect-listen-accepted",
        "visitor-initial-bytes-buffered",
        "connection-request-sent",
        "connect-accept-received",
        "connect-accept-confirmed",
    ])
}

async fn run_h3_client_reference(
    connection: quinn::Connection,
    backend_address: SocketAddr,
    server_completed: oneshot::Receiver<()>,
) -> Result<(), String> {
    let (_h3_connection, mut sender) = h3::client::builder()
        .enable_extended_connect(true)
        .build(H3QuinnConnection::new(connection))
        .await
        .map_err(|error| format!("build H3 client: {error}"))?;
    let mut listener_stream = sender
        .send_request(post_request("/connect-listen")?)
        .await
        .map_err(|error| format!("send connect-listen: {error}"))?;
    if listener_stream
        .recv_response()
        .await
        .map_err(|error| format!("receive connect-listen confirmation: {error}"))?
        .status()
        != http::StatusCode::OK
    {
        return Err("Server rejected connect-listen".to_owned());
    }
    let mut connection_request = listener_stream
        .recv_data()
        .await
        .map_err(|error| format!("receive connection request: {error}"))?
        .ok_or_else(|| "Server closed connect-listen before a request".to_owned())?;
    let connection_request = connection_request.copy_to_bytes(connection_request.remaining());
    if connection_request != CONNECTION_REQUEST {
        return Err("Client received an unexpected connection request".to_owned());
    }

    let mut accept_stream = sender
        .send_request(post_request("/connect-accept/1")?)
        .await
        .map_err(|error| format!("send connect-accept: {error}"))?;
    if accept_stream
        .recv_response()
        .await
        .map_err(|error| format!("receive connect-accept confirmation: {error}"))?
        .status()
        != http::StatusCode::OK
    {
        return Err("Server rejected connect-accept".to_owned());
    }
    let mut visitor_initial_bytes = accept_stream
        .recv_data()
        .await
        .map_err(|error| format!("receive Visitor bytes: {error}"))?
        .ok_or_else(|| "Server closed connect-accept before Visitor bytes".to_owned())?;
    let visitor_initial_bytes =
        visitor_initial_bytes.copy_to_bytes(visitor_initial_bytes.remaining());

    let mut backend = TcpStream::connect(backend_address).await.map_err(display)?;
    backend
        .write_all(&visitor_initial_bytes)
        .await
        .map_err(display)?;
    let mut backend_response = [0_u8; BACKEND_RESPONSE.len()];
    backend
        .read_exact(&mut backend_response)
        .await
        .map_err(display)?;
    accept_stream
        .send_data(Bytes::copy_from_slice(&backend_response))
        .await
        .map_err(|error| format!("send backend response: {error}"))?;
    accept_stream
        .finish()
        .await
        .map_err(|error| format!("finish connect-accept: {error}"))?;
    server_completed
        .await
        .map_err(|_| "Server stopped before completing the reference flow".to_owned())
}

fn h3_server_config(
    server_certificate: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
    client_certificate: CertificateDer<'static>,
) -> Result<quinn::ServerConfig, String> {
    let mut client_roots = RootCertStore::empty();
    client_roots.add(client_certificate).map_err(display)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(display)?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_certificate], server_key)
        .map_err(display)?;
    crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map(|crypto| quinn::ServerConfig::with_crypto(Arc::new(crypto)))
        .map_err(display)
}

fn h3_client_config(
    server_certificate: CertificateDer<'static>,
    client_certificate: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
) -> Result<quinn::ClientConfig, String> {
    let mut server_roots = RootCertStore::empty();
    server_roots.add(server_certificate).map_err(display)?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(server_roots)
        .with_client_auth_cert(vec![client_certificate], client_key)
        .map_err(display)?;
    crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map(|crypto| quinn::ClientConfig::new(Arc::new(crypto)))
        .map_err(display)
}

fn post_request(path: &str) -> Result<http::Request<()>, String> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://tunnel.example.test{path}"))
        .body(())
        .map_err(display)
}

fn ok_response() -> http::Response<()> {
    http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .expect("an empty 200 response is always valid")
}

fn negotiated_alpn(connection: &quinn::Connection) -> Result<Vec<u8>, String> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol.clone())
        .ok_or_else(|| "QUIC handshake did not expose a negotiated ALPN".to_owned())
}

fn self_signed_certificate(
    server_name: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let certified_key =
        generate_simple_self_signed(vec![server_name.to_owned()]).map_err(display)?;
    let certificate = CertificateDer::from(certified_key.cert);
    let private_key = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der()).into();
    Ok((certificate, private_key))
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
