//! Shared H3 peers for runtime tests. Every fixture uses the production gate and slot carrier.

use super::{
    ClientTunnelH3, ClientTunnelStream, ServerRuntimeGeneration, ServerTunnelH3, TunnelReadHalf,
    TunnelWriteHalf,
};
use std::{io, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Semaphore};

pub(crate) type ServerRead =
    TunnelReadHalf<h3::server::RequestStream<h3_quinn::RecvStream, bytes::Bytes>>;
pub(crate) type ServerWrite =
    TunnelWriteHalf<h3::server::RequestStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>>;
pub(crate) type ClientRead =
    TunnelReadHalf<h3::client::RequestStream<h3_quinn::RecvStream, bytes::Bytes>>;
pub(crate) type ClientWrite =
    TunnelWriteHalf<h3::client::RequestStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>>;

pub(crate) fn test_server_h3_config(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    identities: &[crate::ClientIdentity],
) -> Result<quinn::ServerConfig, crate::QuicConfigError> {
    super::make_server_tunnel_h3_config(
        chain,
        key,
        Arc::new(crate::quic::StaticClientIdentityAdmission::from_identities(
            identities,
        )),
    )
}

#[derive(Clone)]
pub(crate) struct ClientPeer {
    client: Arc<Mutex<ClientTunnelH3>>,
    // Hold a Server peer for tests that return only the Client peer from their setup.
    _server: Arc<ServerTunnelH3>,
}

impl ClientPeer {
    pub(crate) async fn accept_stream(&self) -> io::Result<(ClientWrite, ClientRead)> {
        let stream = self
            .client
            .lock()
            .await
            .accept_tunnel_stream()
            .await
            .ok_or_else(|| io::Error::other("tunnel ended"))?;
        let (recv, send) = stream.into_split();
        Ok((send, recv))
    }
}

pub(crate) async fn establish_peers(
    server: quinn::Connection,
    client: quinn::Connection,
    permits: usize,
) -> io::Result<(Arc<ServerTunnelH3>, ClientPeer)> {
    let hostname = crate::ServerHostname::try_from("tunnel.example.test").expect("test hostname");
    let (server, client) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            ServerTunnelH3::establish(
                server,
                hostname.clone(),
                ServerRuntimeGeneration::generate()
            ),
            ClientTunnelH3::establish(client, &hostname, Arc::new(Semaphore::new(permits))),
        )
    })
    .await
    .map_err(|_| io::Error::other("H3 peers timed out"))?;
    let server = Arc::new(server.map_err(io::Error::other)?);
    let client = client.map_err(io::Error::other)?;
    Ok((
        server.clone(),
        ClientPeer {
            client: Arc::new(Mutex::new(client)),
            _server: server,
        },
    ))
}

pub(crate) trait ServerStreams {
    async fn open_stream(&self) -> io::Result<(ServerWrite, ServerRead)>;
}

impl ServerStreams for Arc<ServerTunnelH3> {
    async fn open_stream(&self) -> io::Result<(ServerWrite, ServerRead)> {
        let (recv, send) = self
            .open_tunnel_stream(Duration::from_secs(1))
            .await
            .map_err(io::Error::other)?
            .into_split();
        Ok((send, recv))
    }
}

pub(crate) fn client_stream(send: ClientWrite, recv: ClientRead) -> ClientTunnelStream {
    ClientTunnelStream::from_split(recv, send)
}

pub(crate) async fn read_to_end<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(io::Error::other("stream exceeded test byte limit"));
    }
    Ok(bytes)
}
