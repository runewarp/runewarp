use super::{Result, STEP, client::Client, fixture::Fixture, server::Server};
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) async fn pair(credit: u32) -> Result<(Fixture, Server, Client)> {
    let fixture = Fixture::new(credit, true)?;
    let (server, client) = fixture.connect().await?;
    let mut client = Client::new(client).await?;
    let (server, setup) =
        tokio::join!(Server::establish(server, fixture.identity.clone()), async {
            client.gate().await?;
            let id = client.open_session().await?;
            assert_eq!(id.into_inner(), 4, "the GET gate precedes Extended CONNECT");
            Ok::<_, super::Error>(())
        });
    setup?;
    let server = server?;
    assert_eq!(server.session_id.into_inner(), 4);
    Ok((fixture, server, client))
}
async fn visitor() -> Result<()> {
    let (_fixture, server, mut client) = pair(8).await?;
    let mut server_stream = server.open().await?;
    server_stream.write_all(b"PROXYv2+ClientHello").await?;
    server_stream.flush().await?;
    let mut stream = client.accept().await?;
    let mut bytes = [0u8; 19];
    stream.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"PROXYv2+ClientHello");
    stream.write_all(b"reply").await?;
    stream.shutdown().await?;
    let mut reply = Vec::new();
    server_stream.read_to_end(&mut reply).await?;
    assert_eq!(reply, b"reply");
    server_stream.write_all(b"after-client-FIN").await?;
    server_stream.shutdown().await?;
    let mut tail = Vec::new();
    stream.read_to_end(&mut tail).await?;
    assert_eq!(tail, b"after-client-FIN");
    client.put().await?;
    client.close_session().await?;
    assert!(server.registry.closed.load(Ordering::SeqCst) || server.open().await.is_err());
    Ok(())
}
/// Run the throwaway experiment with a hard deadline.
pub async fn run() -> Result<()> {
    tokio::time::timeout(STEP, visitor()).await??;
    println!("PASS: GET gate, immediate Visitor bytes, PUT, client CLOSE");
    tokio::time::timeout(STEP, reverse_half_close()).await??;
    println!("PASS: FIN half-close in both orders");
    tokio::time::timeout(STEP, resets()).await??;
    println!("PASS: reset on abort both directions, connection survives");
    tokio::time::timeout(STEP, credit()).await??;
    println!("PASS: QUIC stream credit blocks excess opens and recovers");
    tokio::time::timeout(STEP, close_and_goaway()).await??;
    println!("PASS: session CLOSE both ways, active resets, GET/PUT survive; GOAWAY drains");
    tokio::time::timeout(STEP, connection_drop()).await??;
    println!("PASS: connection drop ends active and pending streams");
    tokio::time::timeout(STEP, rejection()).await??;
    println!("PASS: session limit and wrong Session ID rejection");
    tokio::time::timeout(STEP, authentication_and_negotiation()).await??;
    println!("PASS: unauthorized mTLS rejected; unnegotiated bidi closes H3");
    tokio::time::timeout(STEP, datagrams()).await??;
    println!("PASS: bidirectional H3 Datagrams on Session ID 4 while a Visitor stream is active");
    super::measure::run().await?;
    Ok(())
}

async fn reverse_half_close() -> Result<()> {
    let (_fixture, server, mut client) = pair(8).await?;
    let mut sent = server.open().await?;
    sent.write_all(b"PROXYv2+ClientHello").await?;
    sent.shutdown().await?;
    let mut received = client.accept().await?;
    let mut initial = Vec::new();
    received.read_to_end(&mut initial).await?;
    assert_eq!(initial, b"PROXYv2+ClientHello");
    received.write_all(b"after-server-FIN").await?;
    received.shutdown().await?;
    let mut reply = Vec::new();
    sent.read_to_end(&mut reply).await?;
    assert_eq!(reply, b"after-server-FIN");
    Ok(())
}

fn assert_wt_abort(error: &std::io::Error) {
    use crate::vendor::h3::{error::StreamError, quic::StreamErrorIncoming};
    let outer = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<StreamError>())
        .expect("TunnelStream error");
    let StreamError::Undefined(inner) = outer else {
        panic!("unexpected adapter error: {outer:?}");
    };
    assert!(
        matches!(inner.downcast_ref::<StreamErrorIncoming>(), Some(StreamErrorIncoming::StreamTerminated { error_code }) if *error_code == 0x52e4a40fa8db),
        "{inner:?}"
    );
}

async fn resets() -> Result<()> {
    let (_fixture, server, mut client) = pair(8).await?;
    for server_aborts in [true, false] {
        let mut sent = server.open().await?;
        sent.write_all(b"initial").await?;
        sent.flush().await?;
        let mut received = client.accept().await?;
        let mut bytes = [0u8; 7];
        received.read_exact(&mut bytes).await?;
        if server_aborts {
            drop(sent);
            let error = received
                .read_u8()
                .await
                .expect_err("abort must be RESET, not FIN");
            assert_wt_abort(&error);
        } else {
            drop(received);
            let error = sent
                .read_u8()
                .await
                .expect_err("Client abort must be RESET, not FIN");
            assert_wt_abort(&error);
        }
    }
    let mut stream = server.open().await?;
    stream.write_all(b"survives").await?;
    stream.shutdown().await?;
    let mut received = client.accept().await?;
    let mut bytes = Vec::new();
    received.read_to_end(&mut bytes).await?;
    assert_eq!(bytes, b"survives");
    Ok(())
}

async fn credit() -> Result<()> {
    let (_fixture, server, mut client) = pair(2).await?;
    let first = server.open().await?;
    let first_client = client.accept().await?;
    let second = server.open().await?;
    let second_client = client.accept().await?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), server.open())
            .await
            .is_err(),
        "third open must wait for MAX_STREAMS"
    );
    drop((first, first_client));
    let third = tokio::time::timeout(STEP, server.open()).await??;
    let third_client = client.accept().await?;
    drop((second, second_client, third, third_client));
    Ok(())
}

async fn close_and_goaway() -> Result<()> {
    for server_closes in [true, false] {
        let (_fixture, server, mut client) = pair(8).await?;
        let mut stream = server.open().await?;
        let mut received = client.accept().await?;
        if server_closes {
            server.close_session().await?;
            client.closed.wait_for(|closed| *closed).await?;
        } else {
            client.close_session().await?;
        }
        assert!(received.read_u8().await.is_err());
        assert!(stream.read_u8().await.is_err());
        assert!(server.open().await.is_err());
        client.put().await?; // Closing the session did not close the H3 connection.
    }
    let (_fixture, server, mut client) = pair(8).await?;
    let mut stream = server.open().await?;
    let mut received = client.accept().await?;
    server.goaway().await?;
    let mut events = client.events.take().ok_or("events missing")?;
    assert!(events.recv_data().await?.is_none());
    assert!(
        client.put().await.is_err(),
        "Client sends no request after GOAWAY"
    );
    assert!(
        server.open().await.is_err(),
        "Server seals placement before GOAWAY"
    );
    // GOAWAY affects requests; the established session's data streams still drain.
    stream.write_all(b"draining").await?;
    stream.shutdown().await?;
    let mut tail = Vec::new();
    received.read_to_end(&mut tail).await?;
    assert_eq!(tail, b"draining");
    received.shutdown().await?;
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await?;
    drop((stream, received));
    server.close_session().await?;
    client.closed.wait_for(|closed| *closed).await?;
    server.connection.close(0x100u32.into(), b"");
    let error = client.connection.closed().await;
    assert!(
        matches!(error, quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0x100)
    );
    Ok(())
}

async fn connection_drop() -> Result<()> {
    let (_fixture, server, mut client) = pair(8).await?;
    let _stream = server.open().await?;
    let mut received = client.accept().await?;
    server
        .connection
        .close(0x102u32.into(), b"prototype disconnect");
    client.connection.closed().await;
    assert!(received.read_u8().await.is_err());
    assert!(client.accept().await.is_err());
    Ok(())
}

async fn rejection() -> Result<()> {
    use crate::vendor::h3;
    use http::{Method, Request};
    let (_fixture, server, mut client) = pair(8).await?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{}{}", super::SERVER, super::SESSION_PATH))
        .body(())?;
    request
        .extensions_mut()
        .insert(h3::ext::Protocol::WEB_TRANSPORT);
    let mut duplicate = client.sender.send_request(request).await?;
    assert_eq!(duplicate.recv_response().await?.status(), 429);
    let mut raw = server.connection.open_bi().await?;
    raw.0.write_all(&[0x40, 0x41, 0]).await?; // Valid WT signal, nonexistent Session ID 0.
    assert!(client.accept().await.is_err());
    let mut next = server.open().await?;
    next.write_all(b"valid").await?;
    next.shutdown().await?;
    let mut valid = client.accept().await?;
    let mut bytes = Vec::new();
    valid.read_to_end(&mut bytes).await?;
    assert_eq!(bytes, b"valid");
    Ok(())
}

async fn authentication_and_negotiation() -> Result<()> {
    use crate::vendor::{h3, h3_quinn};
    let mut missing = Fixture::new(8, true)?;
    missing.remove_client_certificate()?;
    assert!(missing.connect().await.is_err());
    let refused = Fixture::new(8, false)?;
    assert!(refused.connect().await.is_err());
    let fixture = Fixture::new(8, true)?;
    let (server, client) = fixture.connect().await?;
    assert!(client.max_datagram_size().is_some());
    let handshake = client
        .handshake_data()
        .ok_or("missing handshake data")?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| "wrong TLS backend")?;
    assert_eq!(handshake.protocol.as_deref(), Some(b"h3".as_slice()));
    assert!(
        fixture
            .client
            .connect(fixture.server.local_addr()?, super::SERVER)?
            .into_0rtt()
            .is_err()
    );
    let _client = Client::new(client.clone()).await?;
    let _driver: h3::server::Connection<_, bytes::Bytes> = h3::server::builder()
        .build(h3_quinn::Connection::new(server.clone()))
        .await?;
    let (mut send, _recv) = server.open_bi().await?;
    send.write_all(&[0x40, 0x41, 0]).await?;
    let error = client.closed().await;
    assert!(matches!(error, quinn::ConnectionError::LocallyClosed));
    let error = server.closed().await;
    assert!(
        matches!(error, quinn::ConnectionError::ApplicationClosed(ref close) if close.error_code.into_inner() == h3::error::Code::H3_STREAM_CREATION_ERROR.value()),
        "{error:?}"
    );
    Ok(())
}

async fn datagrams() -> Result<()> {
    use crate::vendor::{h3, h3_datagram::datagram::Datagram};
    use bytes::{Buf, Bytes};
    let (_fixture, server, mut client) = pair(8).await?;
    let _visitor = server.open().await?;
    let _peer = client.accept().await?;
    let id = h3::quic::StreamId::try_from(server.session_id.into_inner()).expect("CONNECT ID");
    for (send, receive) in [
        (&server.connection, &client.connection),
        (&client.connection, &server.connection),
    ] {
        let mut encoded = Datagram::new(id, Bytes::from_static(b"prototype-packet")).encode();
        send.send_datagram(encoded.copy_to_bytes(encoded.remaining()))?;
        let bytes = receive.read_datagram().await?;
        assert_eq!(
            bytes.first(),
            Some(&1),
            "RFC 9297 uses quarter stream ID 4/4"
        );
        let packet = Datagram::decode(bytes).map_err(|e| format!("datagram decode: {e:?}"))?;
        assert_eq!(packet.stream_id().into_inner(), 4);
        assert_eq!(packet.payload().as_ref(), b"prototype-packet");
    }
    client.put().await?;
    client.close_session().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    macro_rules! scenario {
        ($name:ident) => {
            #[tokio::test]
            async fn $name() {
                tokio::time::timeout(super::STEP, super::$name())
                    .await
                    .expect("experiment deadline")
                    .expect(stringify!($name));
            }
        };
    }
    scenario!(visitor);
    scenario!(reverse_half_close);
    scenario!(resets);
    scenario!(credit);
    scenario!(close_and_goaway);
    scenario!(connection_drop);
    scenario!(rejection);
    scenario!(datagrams);
    scenario!(authentication_and_negotiation);
}
