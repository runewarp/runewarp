use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::acme::ACME_TLS_ALPN;
use crate::client_hello::read_client_hello;
use crate::proxy::proxy_tcp_over_quic;
use crate::runtime_log::{emit_stderr, server_route_line};

use super::tunnel_registry::TunnelRegistry;

pub(crate) async fn handle_visitor_connection(
    mut visitor_stream: TcpStream,
    tunnel_registry: TunnelRegistry,
    server_hostname: String,
    logs: bool,
    public_tls_config: Option<Arc<rustls::ServerConfig>>,
) -> io::Result<()> {
    let parsed_client_hello = match read_client_hello(&mut visitor_stream).await {
        Ok(parsed_client_hello) => parsed_client_hello,
        Err(_) => return Ok(()),
    };
    let is_acme_tls_alpn_challenge = parsed_client_hello.offers_alpn_protocol(ACME_TLS_ALPN);
    let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();
    if public_hostname == server_hostname {
        if is_acme_tls_alpn_challenge && let Some(public_tls_config) = public_tls_config {
            emit_stderr(logs, &server_route_line(&public_hostname, "acme challenge"));
            let acceptor = TlsAcceptor::from(public_tls_config);
            if let Ok(mut tls_stream) = acceptor
                .accept(PrefixedStream::new(buffered_bytes, visitor_stream))
                .await
            {
                let _ = tls_stream.shutdown().await;
            }
        } else {
            emit_stderr(logs, &server_route_line(&public_hostname, "dropped (server hostname)"));
        }
        return Ok(());
    }
    if !tunnel_registry.contains_public_hostname(&public_hostname) {
        emit_stderr(logs, &server_route_line(&public_hostname, "dropped (unauthorized)"));
        return Ok(());
    }
    let Some(active_connection) = tunnel_registry.current_connection(&public_hostname).await else {
        emit_stderr(
            logs,
            &server_route_line(&public_hostname, "dropped (no active tunnel connection)"),
        );
        return Ok(());
    };
    emit_stderr(logs, &server_route_line(&public_hostname, "forwarded"));

    let (send, recv) = match active_connection.open_bi().await {
        Ok(stream) => stream,
        Err(_) => return Ok(()),
    };

    proxy_tcp_over_quic(visitor_stream, buffered_bytes, send, recv).await
}

struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let prefix_len = self.prefix.get_ref().len() as u64;
        if self.prefix.position() < prefix_len {
            let offset = self.prefix.position() as usize;
            let remaining = &self.prefix.get_ref()[offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            let position = self.prefix.position();
            self.prefix.set_position(position + to_copy as u64);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
