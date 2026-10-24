//! Byte-stream adapters over one assigned receive slot.
//!
//! An assigned slot carries one Visitor's bytes as HTTP/3 DATA in each direction. The halves
//! implement Tokio's `AsyncRead` and `AsyncWrite` so proxy and TLS code stay transport-neutral:
//!
//! - each write starts its DATA frame immediately; like a buffered writer, the frame may still be
//!   in flight until the next write, `poll_flush`, or `poll_shutdown` completes it;
//! - `poll_shutdown` on the write half ends that direction with FIN;
//! - a read half returns end-of-file at the peer's FIN;
//! - dropping a write half before `poll_shutdown` completes resets the stream. Quinn would
//!   otherwise finish a dropped send stream implicitly, making an aborted Visitor look like a
//!   clean end.
//!
//! `h3` exposes only async sends, so each write moves the send half into one boxed future. The
//! future always runs to completion before the next write or FIN; cancelling an `h3` write midway
//! would corrupt the stream (hyperium/h3#360).

use crate::vendor::{h3, h3_quinn};

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use h3::quic::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest single DATA frame written from one `poll_write` call.
const MAX_WRITE_CHUNK: usize = 64 * 1024;

type ServerRequestStream<S> = h3::server::RequestStream<S, Bytes>;
type ClientRequestStream<S> = h3::client::RequestStream<S, Bytes>;

/// Server half types of one assigned slot.
pub type ServerTunnelStream = TunnelStream<
    ServerRequestStream<h3_quinn::RecvStream>,
    ServerRequestStream<h3_quinn::SendStream<Bytes>>,
>;

/// Client half types of one assigned slot.
pub type ClientTunnelStream = TunnelStream<
    ClientRequestStream<h3_quinn::RecvStream>,
    ClientRequestStream<h3_quinn::SendStream<Bytes>>,
>;

/// Resources released only after both halves of a Tunnel stream drop: Server in-flight request
/// accounting or a Client stream-handler permit.
pub(crate) type StreamLease = Arc<dyn Send + Sync>;

/// Send half of an HTTP/3 request stream, on either side.
pub trait SendHalf: Send + Sized + Unpin + 'static {
    fn send_data(&mut self, data: Bytes) -> impl Future<Output = Result<(), StreamError>> + Send;
    fn finish(&mut self) -> impl Future<Output = Result<(), StreamError>> + Send;
    fn reset(&mut self);
}

/// Receive half of an HTTP/3 request stream, on either side.
pub trait RecvHalf: Send + Unpin + 'static {
    fn poll_recv(&mut self, context: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>>;
}

impl<S> SendHalf for ServerRequestStream<S>
where
    S: SendStream<Bytes> + Send + Unpin + 'static,
{
    fn send_data(&mut self, data: Bytes) -> impl Future<Output = Result<(), StreamError>> + Send {
        h3::server::RequestStream::send_data(self, data)
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), StreamError>> + Send {
        h3::server::RequestStream::finish(self)
    }

    fn reset(&mut self) {
        self.stop_stream(Code::H3_REQUEST_CANCELLED);
    }
}

impl<S> SendHalf for ClientRequestStream<S>
where
    S: SendStream<Bytes> + Send + Unpin + 'static,
{
    fn send_data(&mut self, data: Bytes) -> impl Future<Output = Result<(), StreamError>> + Send {
        h3::client::RequestStream::send_data(self, data)
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), StreamError>> + Send {
        h3::client::RequestStream::finish(self)
    }

    fn reset(&mut self) {
        self.stop_stream(Code::H3_REQUEST_CANCELLED);
    }
}

impl<S> RecvHalf for ServerRequestStream<S>
where
    S: RecvStream + Send + Unpin + 'static,
{
    fn poll_recv(&mut self, context: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.poll_recv_data(context)
            .map_ok(|chunk| chunk.map(|mut chunk| chunk.copy_to_bytes(chunk.remaining())))
    }
}

impl<S> RecvHalf for ClientRequestStream<S>
where
    S: RecvStream + Send + Unpin + 'static,
{
    fn poll_recv(&mut self, context: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.poll_recv_data(context)
            .map_ok(|chunk| chunk.map(|mut chunk| chunk.copy_to_bytes(chunk.remaining())))
    }
}

/// Send half that resets its stream when dropped without a completed FIN.
struct ResetOnDrop<S: SendHalf> {
    half: Option<S>,
}

impl<S: SendHalf> ResetOnDrop<S> {
    fn half(&mut self) -> &mut S {
        self.half
            .as_mut()
            .expect("the send half is present until a completed FIN disarms it")
    }

    /// The stream ended with FIN; dropping it no longer needs a reset.
    fn disarm(&mut self) {
        self.half = None;
    }
}

impl<S: SendHalf> Drop for ResetOnDrop<S> {
    fn drop(&mut self) {
        if let Some(half) = self.half.as_mut() {
            half.reset();
        }
    }
}

type PendingWrite<S> =
    Pin<Box<dyn Future<Output = (ResetOnDrop<S>, Result<(), StreamError>)> + Send>>;

enum WriteState<S: SendHalf> {
    Idle(ResetOnDrop<S>),
    Writing(PendingWrite<S>),
    Finishing(PendingWrite<S>),
    Finished,
    Failed,
}

/// `AsyncWrite` over the send half of one assigned slot.
pub struct TunnelWriteHalf<S: SendHalf> {
    state: WriteState<S>,
    _lease: StreamLease,
}

impl<S: SendHalf> TunnelWriteHalf<S> {
    fn new(half: S, lease: StreamLease) -> Self {
        Self {
            state: WriteState::Idle(ResetOnDrop { half: Some(half) }),
            _lease: lease,
        }
    }

    /// Drive an in-flight DATA write to completion.
    fn poll_pending_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let WriteState::Writing(write) = &mut self.state else {
            return Poll::Ready(Ok(()));
        };
        let (half, result) = ready!(write.as_mut().poll(context));
        match result {
            Ok(()) => {
                self.state = WriteState::Idle(half);
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                self.state = WriteState::Failed;
                Poll::Ready(Err(stream_io_error(error)))
            }
        }
    }
}

impl<S: SendHalf> AsyncWrite for TunnelWriteHalf<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_pending_write(context))?;
        match std::mem::replace(&mut this.state, WriteState::Failed) {
            WriteState::Idle(mut half) => {
                let length = buffer.len().min(MAX_WRITE_CHUNK);
                let data = Bytes::copy_from_slice(&buffer[..length]);
                this.state = WriteState::Writing(Box::pin(async move {
                    let result = half.half().send_data(data).await;
                    (half, result)
                }));
                // Start the send now so data reaches the transport without waiting for the next
                // write or flush; a pending send finishes on the next write, flush, or shutdown.
                if let Poll::Ready(Err(error)) = this.poll_pending_write(context) {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(length))
            }
            state => {
                this.state = state;
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_pending_write(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending_write(context))?;
        loop {
            match std::mem::replace(&mut this.state, WriteState::Failed) {
                WriteState::Idle(mut half) => {
                    this.state = WriteState::Finishing(Box::pin(async move {
                        let result = half.half().finish().await;
                        if result.is_ok() {
                            half.disarm();
                        }
                        (half, result)
                    }));
                }
                WriteState::Finishing(mut finish) => {
                    return match finish.as_mut().poll(context) {
                        Poll::Pending => {
                            this.state = WriteState::Finishing(finish);
                            Poll::Pending
                        }
                        Poll::Ready((_, Ok(()))) => {
                            this.state = WriteState::Finished;
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready((_, Err(error))) => Poll::Ready(Err(stream_io_error(error))),
                    };
                }
                WriteState::Finished => {
                    this.state = WriteState::Finished;
                    return Poll::Ready(Ok(()));
                }
                WriteState::Writing(_) | WriteState::Failed => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
            }
        }
    }
}

/// `AsyncRead` over the receive half of one assigned slot.
pub struct TunnelReadHalf<R: RecvHalf> {
    half: R,
    buffered: Bytes,
    ended: bool,
    _lease: StreamLease,
}

impl<R: RecvHalf> TunnelReadHalf<R> {
    fn new(half: R, lease: StreamLease) -> Self {
        Self {
            half,
            buffered: Bytes::new(),
            ended: false,
            _lease: lease,
        }
    }
}

impl<R: RecvHalf> AsyncRead for TunnelReadHalf<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.buffered.is_empty() && !this.ended {
            match ready!(this.half.poll_recv(context)) {
                Ok(Some(chunk)) => this.buffered = chunk,
                Ok(None) => this.ended = true,
                Err(error) => return Poll::Ready(Err(stream_io_error(error))),
            }
        }
        let length = this.buffered.len().min(buffer.remaining());
        buffer.put_slice(&this.buffered.split_to(length));
        Poll::Ready(Ok(()))
    }
}

/// One Visitor's bidirectional byte stream over an assigned receive slot.
pub struct TunnelStream<R: RecvHalf, S: SendHalf> {
    read: TunnelReadHalf<R>,
    write: TunnelWriteHalf<S>,
}

impl<R: RecvHalf, S: SendHalf> TunnelStream<R, S> {
    pub(crate) fn new(recv: R, send: S, lease: StreamLease) -> Self {
        Self {
            read: TunnelReadHalf::new(recv, lease.clone()),
            write: TunnelWriteHalf::new(send, lease),
        }
    }

    /// Separate halves for concurrent reading and writing.
    pub fn into_split(self) -> (TunnelReadHalf<R>, TunnelWriteHalf<S>) {
        (self.read, self.write)
    }
}

impl<R: RecvHalf, S: SendHalf> AsyncRead for TunnelStream<R, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(context, buffer)
    }
}

impl<R: RecvHalf, S: SendHalf> AsyncWrite for TunnelStream<R, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(context)
    }
}

fn stream_io_error(error: StreamError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, error)
}
