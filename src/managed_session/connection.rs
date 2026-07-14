//! One authenticated HTTP/2 Control connection carrying the SSE downlink and
//! concurrent applied-state acknowledgments.

use std::fmt;

use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2::{self, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::role::{ManagedSessionRole, events_path, state_path};
use super::status::{
    SseResponseClass, StateResponseClass, classify_sse_response, classify_state_incoming,
};
use super::tls::{CONTROL_ALPN_H2, ControlTlsMaterial};
use crate::ControlAddress;

/// Error establishing or using a Managed-session connection.
#[derive(Debug)]
pub enum ConnectionError {
    Dns(std::io::Error),
    Connect(std::io::Error),
    Tls(std::io::Error),
    Alpn,
    ServerName(String),
    Http(hyper::Error),
    SseRejected,
    StateRejected,
    Body(hyper::Error),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(error) => write!(formatter, "control DNS lookup failed: {error}"),
            Self::Connect(error) => write!(formatter, "control TCP connect failed: {error}"),
            Self::Tls(error) => write!(formatter, "control TLS handshake failed: {error}"),
            Self::Alpn => formatter.write_str("control TLS did not negotiate HTTP/2 ALPN"),
            Self::ServerName(name) => write!(formatter, "invalid control server name `{name}`"),
            Self::Http(error) => write!(formatter, "control HTTP/2 error: {error}"),
            Self::SseRejected => {
                formatter.write_str("control SSE response was not status 200 event-stream")
            }
            Self::StateRejected => {
                formatter.write_str("control state response was not status 204 with an empty body")
            }
            Self::Body(error) => write!(formatter, "control SSE body error: {error}"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dns(error) | Self::Connect(error) | Self::Tls(error) => Some(error),
            Self::Http(error) | Self::Body(error) => Some(error),
            Self::Alpn | Self::ServerName(_) | Self::SseRejected | Self::StateRejected => None,
        }
    }
}

/// Authenticated HTTP/2 connection with an open SSE downlink.
///
/// The sender half remains available so applied-state acknowledgments can open concurrent
/// streams on the same connection. Dropping this value closes the connection.
pub struct ManagedSessionConnection {
    sender: SendRequest<Full<Bytes>>,
    // Keep the connection driver alive for the lifetime of the session.
    conn: Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>,
    body: Incoming,
    authority: String,
    role: ManagedSessionRole,
}

impl Drop for ManagedSessionConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.abort();
        }
    }
}

impl ManagedSessionConnection {
    /// Dial Control, enforce HTTP/2 ALPN, and open exactly one role SSE stream.
    pub async fn connect(
        address: &ControlAddress,
        tls: &ControlTlsMaterial,
        role: ManagedSessionRole,
    ) -> Result<Self, ConnectionError> {
        let host = address.hostname().as_str();
        let port = address.port();
        let socket_addrs: Vec<_> = tokio::net::lookup_host((host, port))
            .await
            .map_err(ConnectionError::Dns)?
            .collect();
        if socket_addrs.is_empty() {
            return Err(ConnectionError::Dns(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "control hostname resolved to no addresses",
            )));
        }

        // Try every resolved address. Linux commonly returns `::1` before
        // `127.0.0.1`; one refused family must not discard a reachable peer.
        let tcp = TcpStream::connect(socket_addrs.as_slice())
            .await
            .map_err(ConnectionError::Connect)?;
        tcp.set_nodelay(true).map_err(ConnectionError::Connect)?;

        let server_name = ServerName::try_from(tls.server_name.as_str())
            .map_err(|_| ConnectionError::ServerName(tls.server_name.clone()))?
            .to_owned();
        let connector = TlsConnector::from(tls.client_config.clone());
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(ConnectionError::Tls)?;

        let negotiated = tls_stream.get_ref().1.alpn_protocol();
        if negotiated != Some(CONTROL_ALPN_H2) {
            return Err(ConnectionError::Alpn);
        }

        handshake_and_open_sse(tls_stream, host, port, role).await
    }

    /// Read the next body chunk from the SSE stream.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, ConnectionError> {
        match self.body.frame().await {
            None => Ok(None),
            Some(Ok(frame)) => Ok(frame.into_data().ok()),
            Some(Err(error)) => Err(ConnectionError::Body(error)),
        }
    }

    /// Whether another request can still be sent on this HTTP/2 connection.
    pub fn can_send_additional_request(&self) -> bool {
        !self.sender.is_closed()
    }

    /// Acknowledge the applied revision on a concurrent stream of this connection.
    ///
    /// State writes are valid only after the matching SSE downlink is active,
    /// which is true for any constructed [`ManagedSessionConnection`].
    pub async fn put_applied_revision(&mut self, revision: &str) -> Result<(), ConnectionError> {
        let uri = Uri::builder()
            .scheme("https")
            .authority(self.authority.clone())
            .path_and_query(state_path(self.role))
            .build()
            .expect("control state URI is valid by construction");
        let payload = serde_json::json!({ "revision": revision });
        let body = Full::new(Bytes::from(
            serde_json::to_vec(&payload).expect("revision payload serializes"),
        ));
        let request = Request::builder()
            .method("PUT")
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .expect("state request is valid by construction");

        let response = self
            .sender
            .send_request(request)
            .await
            .map_err(ConnectionError::Http)?;
        let status = response.status();
        let class = classify_state_incoming(status, response.into_body())
            .await
            .map_err(ConnectionError::Http)?;
        if class != StateResponseClass::Success {
            return Err(ConnectionError::StateRejected);
        }
        Ok(())
    }
}

async fn handshake_and_open_sse<S>(
    stream: S,
    host: &str,
    port: u16,
    role: ManagedSessionRole,
) -> Result<ManagedSessionConnection, ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .map_err(ConnectionError::Http)?;

    let conn_handle = tokio::spawn(conn);

    let path = events_path(role);
    let authority = if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.clone())
        .path_and_query(path)
        .build()
        .expect("control SSE URI is valid by construction");

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(http::header::ACCEPT, "text/event-stream")
        .body(Full::new(Bytes::new()))
        .expect("SSE request is valid by construction");

    let response = sender
        .send_request(request)
        .await
        .map_err(ConnectionError::Http)?;

    if classify_sse_response(response.status(), response.headers()) != SseResponseClass::Success {
        // Aborting the connection driver closes the entire HTTP/2 session.
        conn_handle.abort();
        return Err(ConnectionError::SseRejected);
    }

    Ok(ManagedSessionConnection {
        sender,
        conn: Some(conn_handle),
        body: response.into_body(),
        authority,
        role,
    })
}
