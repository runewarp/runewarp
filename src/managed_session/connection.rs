//! One authenticated HTTP/2 Control connection carrying the SSE downlink.

use std::fmt;

use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http2::{self, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::role::{ManagedSessionRole, events_path};
use super::status::{SseResponseClass, classify_sse_response};
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
            Self::Body(error) => write!(formatter, "control SSE body error: {error}"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dns(error) | Self::Connect(error) | Self::Tls(error) => Some(error),
            Self::Http(error) | Self::Body(error) => Some(error),
            Self::Alpn | Self::ServerName(_) | Self::SseRejected => None,
        }
    }
}

/// Authenticated HTTP/2 connection with an open SSE downlink.
///
/// The sender half remains available so later work can open state-report
/// streams on the same connection. Dropping this value closes the connection.
pub struct ManagedSessionConnection {
    sender: SendRequest<Empty<Bytes>>,
    // Keep the connection driver alive for the lifetime of the session.
    conn: Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>,
    body: Incoming,
    /// True while the HTTP/2 sender can still open additional streams.
    pub connection_ready_for_additional_streams: bool,
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
        let socket_addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(ConnectionError::Dns)?
            .next()
            .ok_or_else(|| {
                ConnectionError::Dns(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "control hostname resolved to no addresses",
                ))
            })?;

        let tcp = TcpStream::connect(socket_addr)
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
        .authority(authority)
        .path_and_query(path)
        .build()
        .expect("control SSE URI is valid by construction");

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(http::header::ACCEPT, "text/event-stream")
        .body(Empty::<Bytes>::new())
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

    let ready_for_more = !sender.is_closed();
    Ok(ManagedSessionConnection {
        sender,
        conn: Some(conn_handle),
        body: response.into_body(),
        connection_ready_for_additional_streams: ready_for_more,
    })
}
