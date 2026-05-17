use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::proxy::proxy_tcp_over_quic;
use crate::runtime_log::{emit_stderr, server_route_line};

use super::visitor_decision::{VisitorDecision, VisitorDecisionModule, VisitorRejection};

pub(crate) async fn handle_visitor_connection(
    mut visitor_stream: TcpStream,
    visitor_decision: VisitorDecisionModule,
    logs: bool,
    public_tls_config: Option<Arc<rustls::ServerConfig>>,
) -> io::Result<()> {
    match visitor_decision.decide(&mut visitor_stream).await {
        VisitorDecision::Reject(rejection) => {
            log_rejection(logs, &rejection);
            Ok(())
        }
        VisitorDecision::ServeAcmeTlsAlpn01(acme_decision) => {
            if let Some(public_tls_config) = public_tls_config {
                emit_stderr(
                    logs,
                    &server_route_line(&acme_decision.server_hostname, "acme challenge"),
                );
                let acceptor = TlsAcceptor::from(public_tls_config);
                if let Ok(mut tls_stream) = acceptor
                    .accept(PrefixedStream::new(
                        acme_decision.buffered_bytes,
                        visitor_stream,
                    ))
                    .await
                {
                    let _ = tls_stream.shutdown().await;
                }
            } else {
                emit_stderr(
                    logs,
                    &server_route_line(&acme_decision.server_hostname, "dropped (server hostname)"),
                );
            }
            Ok(())
        }
        VisitorDecision::Forward(forward_decision) => {
            let public_hostname = forward_decision.public_hostname;
            let buffered_bytes = forward_decision.buffered_bytes;
            let (send, recv) = match forward_decision.tunnel_connection.open_bi().await {
                Ok(stream) => stream,
                Err(_) => {
                    emit_stderr(
                        logs,
                        &server_route_line(
                            &public_hostname,
                            "dropped (no active tunnel connection)",
                        ),
                    );
                    return Ok(());
                }
            };
            emit_stderr(logs, &server_route_line(&public_hostname, "forwarded"));

            proxy_tcp_over_quic(visitor_stream, buffered_bytes, send, recv).await
        }
    }
}

fn log_rejection(logs: bool, rejection: &VisitorRejection) {
    match rejection {
        VisitorRejection::InvalidTls
        | VisitorRejection::MissingSni
        | VisitorRejection::InvalidSni
        | VisitorRejection::IncompleteClientHello => {}
        VisitorRejection::ClientHelloTooLong { limit } => {
            let _ = limit;
        }
        VisitorRejection::ReadFailure { kind } => {
            let _ = kind;
        }
        VisitorRejection::ServerHostname { server_hostname } => {
            emit_stderr(
                logs,
                &server_route_line(server_hostname, "dropped (server hostname)"),
            );
        }
        VisitorRejection::UnauthorizedPublicHostname { public_hostname } => {
            emit_stderr(
                logs,
                &server_route_line(public_hostname, "dropped (unauthorized)"),
            );
        }
        VisitorRejection::NoActiveTunnelConnection { public_hostname } => {
            emit_stderr(
                logs,
                &server_route_line(public_hostname, "dropped (no active tunnel connection)"),
            );
        }
    }
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
