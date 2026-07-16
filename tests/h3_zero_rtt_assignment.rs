//! Rough, test-only HTTP/3 receive-slot prototype for Wayfinder issue #223.
//!
//! It deliberately does not enter the production `runewarp/1` runtime. The
//! black-box seam is an authenticated Client--Server H3 association: Client
//! preopens receive/start slots, Server consumes one only after a Visitor
//! arrives, and the buffered ClientHello arrives with that assignment.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::{Request, Response, StatusCode};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const H3_ALPN: &[u8] = b"h3";
const RECEIVE_SLOT_PATH: &str = "/.well-known/runewarp/receive-slot";
const DRAIN_PATH: &str = "/.well-known/runewarp/drain";
const ASSIGNMENT: &[u8] = b"runewarp-assignment\0app.example.test\0";
const CLIENT_HELLO: &[u8] = b"\x16\x03\x01buffered-client-hello";

enum ServerEvent {
    Slot(Box<RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>>),
    Drain(oneshot::Sender<()>),
}

/// The receive-slot carrier delivers the assignment and initial Visitor bytes
/// without a per-Visitor Client-to-Server acceptance exchange.
#[tokio::test]
async fn preopened_receive_slot_delivers_assignment_and_clienthello_immediately() {
    let (server_config, client_config, server_name) = h3_configs();
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let (events_tx, mut events_rx) = mpsc::channel(4);

    let server_task = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let mut h3_connection = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        while let Some(resolver) = h3_connection.accept().await.unwrap() {
            let (request, stream) = resolver.resolve_request().await.unwrap();
            match request.uri().path() {
                RECEIVE_SLOT_PATH => events_tx
                    .send(ServerEvent::Slot(Box::new(stream)))
                    .await
                    .unwrap(),
                DRAIN_PATH => {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    events_tx.send(ServerEvent::Drain(ack_tx)).await.unwrap();
                    ack_rx.await.unwrap();
                }
                path => panic!("unexpected H3 request path {path}"),
            }
        }
    });

    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connection = client_endpoint
        .connect(server_addr, server_name.as_str())
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let mut receive_slot = send_request
        .send_request(receive_slot_request(RECEIVE_SLOT_PATH))
        .await
        .unwrap();

    let ServerEvent::Slot(mut server_slot) = timeout(Duration::from_secs(1), events_rx.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("first Client advertisement must be a receive slot");
    };

    server_slot
        .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
        .await
        .unwrap();
    server_slot
        .send_data(Bytes::from_static(ASSIGNMENT))
        .await
        .unwrap();
    server_slot
        .send_data(Bytes::from_static(CLIENT_HELLO))
        .await
        .unwrap();
    server_slot.finish().await.unwrap();

    assert_eq!(
        receive_slot.recv_response().await.unwrap().status(),
        StatusCode::OK
    );
    let assignment = receive_slot
        .recv_data()
        .await
        .unwrap()
        .unwrap()
        .copy_to_bytes(ASSIGNMENT.len());
    let client_hello = receive_slot
        .recv_data()
        .await
        .unwrap()
        .unwrap()
        .copy_to_bytes(CLIENT_HELLO.len());
    assert_eq!(assignment, ASSIGNMENT);
    assert_eq!(client_hello, CLIENT_HELLO);

    drop(send_request);
    driver_task.abort();
    server_task.abort();
}

/// A Client can withdraw unused receive capacity before Server assigns it; the
/// drain acknowledgement is a placement-withdrawal barrier, not stream completion.
#[tokio::test]
async fn drain_withdraws_unassigned_receive_capacity_before_server_assignment() {
    let (server_config, client_config, server_name) = h3_configs();
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let (events_tx, mut events_rx) = mpsc::channel(4);

    let server_task = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let mut h3_connection = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        while let Some(resolver) = h3_connection.accept().await.unwrap() {
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            match request.uri().path() {
                RECEIVE_SLOT_PATH => events_tx
                    .send(ServerEvent::Slot(Box::new(stream)))
                    .await
                    .unwrap(),
                DRAIN_PATH => {
                    let (ack_tx, ack_rx) = oneshot::channel();
                    events_tx.send(ServerEvent::Drain(ack_tx)).await.unwrap();
                    ack_rx.await.unwrap();
                    stream
                        .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }
                path => panic!("unexpected H3 request path {path}"),
            }
        }
    });

    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connection = client_endpoint
        .connect(server_addr, server_name.as_str())
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let _slot = send_request
        .send_request(receive_slot_request(RECEIVE_SLOT_PATH))
        .await
        .unwrap();
    let ServerEvent::Slot(_unassigned_slot) = timeout(Duration::from_secs(1), events_rx.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("Client must advertise capacity before drain");
    };

    let mut drain = send_request
        .send_request(receive_slot_request(DRAIN_PATH))
        .await
        .unwrap();
    let ServerEvent::Drain(ack) = timeout(Duration::from_secs(1), events_rx.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("Client drain must use the association control request");
    };
    ack.send(()).unwrap();
    assert_eq!(
        drain.recv_response().await.unwrap().status(),
        StatusCode::OK
    );

    drop(send_request);
    driver_task.abort();
    server_task.abort();
}

fn receive_slot_request(path: &str) -> Request<()> {
    Request::builder()
        .method("CONNECT")
        .uri(format!("https://tunnel.example.test{path}"))
        .body(())
        .unwrap()
}

fn h3_configs() -> (ServerConfig, ClientConfig, String) {
    let server_certificate =
        generate_simple_self_signed(vec!["tunnel.example.test".to_owned()]).unwrap();
    let server_certificate_der = CertificateDer::from(server_certificate.cert);
    let server_private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        server_certificate.signing_key.serialize_der(),
    ));
    let client_certificate =
        generate_simple_self_signed(vec!["client.example.test".to_owned()]).unwrap();
    let client_certificate_der = CertificateDer::from(client_certificate.cert);
    let client_private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        client_certificate.signing_key.serialize_der(),
    ));

    let mut client_identity_roots = RootCertStore::empty();
    client_identity_roots
        .add(client_certificate_der.clone())
        .unwrap();
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_identity_roots))
        .build()
        .unwrap();

    let mut server_crypto = RustlsServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_certificate_der.clone()], server_private_key)
        .unwrap();
    server_crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_bidi_streams(16_u8.into());
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(16_u8.into());

    let mut roots = RootCertStore::empty();
    roots.add(server_certificate_der).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![client_certificate_der], client_private_key)
        .unwrap();
    client_crypto.alpn_protocols = vec![H3_ALPN.to_vec()];
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(16_u8.into());
    transport.max_concurrent_uni_streams(16_u8.into());
    client_config.transport_config(Arc::new(transport));

    (
        server_config,
        client_config,
        "tunnel.example.test".to_owned(),
    )
}
