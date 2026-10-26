//! Byte-stream adapters over one WebTransport Visitor stream.
//!
//! A WebTransport stream carries one Visitor's raw bytes in each direction. The halves
//! implement Tokio's `AsyncRead` and `AsyncWrite` so proxy and TLS code stay transport-neutral:
//!
//! - each write starts its byte chunk immediately; like a buffered writer, the chunk may still be
//!   in flight until the next write, `poll_flush`, or `poll_shutdown` completes it;
//! - `poll_shutdown` on the write half ends that direction with FIN;
//! - a read half returns end-of-file at the peer's FIN;
//! - dropping a write half before `poll_shutdown` completes resets the stream. Quinn would
//!   otherwise finish a dropped send stream implicitly, making an aborted Visitor look like a
//!   clean end.
//!
//! Each write moves the send half into one boxed future. It finishes the whole byte chunk before
//! the next write or FIN. Dropping that future resets its unfinished send half.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use h3::quic::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest single byte chunk written from one `poll_write` call.
const MAX_WRITE_CHUNK: usize = 64 * 1024;

/// Raw WebTransport halves retain the fork's session-termination guards.
pub type VisitorRecv = h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>;
pub type VisitorSend = h3_webtransport::stream::SendStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub type ServerTunnelStream = TunnelStream<VisitorRecv, VisitorSend>;
pub type ClientTunnelStream = TunnelStream<VisitorRecv, VisitorSend>;

/// Resources held until both application halves drop. The last half calls `before_drop`
/// before releasing its transport handles, then releases this resource after those handles.
pub(crate) trait StreamResource: Send + Sync {
    fn before_drop(&self) {}
}
impl StreamResource for () {}

// Each application half calls dropping_half before its fields drop. The lease field must stay
// after the transport fields in both half structs, retaining the resource through their drops.
// The counter also covers concurrent half Drops, where Arc::strong_count is not a finalizer.
struct StreamLease {
    halves: std::sync::atomic::AtomicUsize,
    resource: Arc<dyn StreamResource>,
}
impl StreamLease {
    fn dropping_half(&self) {
        if self
            .halves
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.resource.before_drop();
        }
    }
}

/// Send half of a Visitor stream.
pub trait SendHalf: Send + Sized + Unpin + 'static {
    fn send_data(&mut self, data: Bytes) -> impl Future<Output = Result<(), StreamError>> + Send;
    fn finish(&mut self) -> impl Future<Output = Result<(), StreamError>> + Send;
    fn reset(&mut self);
}

/// Receive half of a Visitor stream.
pub trait RecvHalf: Send + Unpin + 'static {
    fn poll_recv(&mut self, context: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>>;
}

impl SendHalf for VisitorSend {
    async fn send_data(&mut self, mut data: Bytes) -> Result<(), StreamError> {
        use h3::quic::SendStreamUnframed;
        while data.has_remaining() {
            std::future::poll_fn(|cx| self.poll_send(cx, &mut data))
                .await
                .map_err(|error| StreamError::Undefined(Box::new(error)))?;
        }
        Ok(())
    }
    async fn finish(&mut self) -> Result<(), StreamError> {
        std::future::poll_fn(|cx| self.poll_finish(cx))
            .await
            .map_err(|error| StreamError::Undefined(Box::new(error)))
    }
    fn reset(&mut self) {
        SendStream::reset(self, Code::H3_REQUEST_CANCELLED.value());
    }
}

impl RecvHalf for VisitorRecv {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.poll_data(cx)
            .map_err(|error| StreamError::Undefined(Box::new(error)))
    }
}

/// Send half that resets its stream when dropped without a completed FIN.
struct ResetOnDrop<S: SendHalf> {
    half: S,
    finished: bool,
}

impl<S: SendHalf> ResetOnDrop<S> {
    fn half(&mut self) -> &mut S {
        &mut self.half
    }

    /// The stream ended with FIN; dropping it no longer needs a reset.
    fn disarm(&mut self) {
        self.finished = true;
    }
}

impl<S: SendHalf> Drop for ResetOnDrop<S> {
    fn drop(&mut self) {
        if !self.finished {
            self.half.reset();
        }
    }
}

type PendingWrite<S> =
    Pin<Box<dyn Future<Output = (ResetOnDrop<S>, Result<(), StreamError>)> + Send>>;

enum WriteState<S: SendHalf> {
    Idle(ResetOnDrop<S>),
    Writing(PendingWrite<S>),
    Finishing(PendingWrite<S>),
    Finished(ResetOnDrop<S>),
    Failed(Option<ResetOnDrop<S>>),
}

/// `AsyncWrite` over the send half of one Visitor stream.
pub struct TunnelWriteHalf<S: SendHalf> {
    state: WriteState<S>,
    lease: Arc<StreamLease>,
}

impl<S: SendHalf> TunnelWriteHalf<S> {
    fn new(half: S, lease: Arc<StreamLease>) -> Self {
        Self {
            state: WriteState::Idle(ResetOnDrop {
                half,
                finished: false,
            }),
            lease,
        }
    }

    /// Drive an in-flight byte write to completion.
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
                self.state = WriteState::Failed(Some(half));
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
        match std::mem::replace(&mut this.state, WriteState::Failed(None)) {
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
            match std::mem::replace(&mut this.state, WriteState::Failed(None)) {
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
                        Poll::Ready((half, Ok(()))) => {
                            this.state = WriteState::Finished(half);
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready((half, Err(error))) => {
                            this.state = WriteState::Failed(Some(half));
                            Poll::Ready(Err(stream_io_error(error)))
                        }
                    };
                }
                WriteState::Finished(half) => {
                    this.state = WriteState::Finished(half);
                    return Poll::Ready(Ok(()));
                }
                state @ (WriteState::Writing(_) | WriteState::Failed(_)) => {
                    this.state = state;
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
            }
        }
    }
}

/// `AsyncRead` over the receive half of one Visitor stream.
pub struct TunnelReadHalf<R: RecvHalf> {
    half: R,
    buffered: Bytes,
    ended: bool,
    lease: Arc<StreamLease>,
}

impl<R: RecvHalf> TunnelReadHalf<R> {
    fn new(half: R, lease: Arc<StreamLease>) -> Self {
        Self {
            half,
            buffered: Bytes::new(),
            ended: false,
            lease,
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

/// One Visitor's bidirectional byte stream over a WebTransport Visitor stream.
pub struct TunnelStream<R: RecvHalf, S: SendHalf> {
    read: TunnelReadHalf<R>,
    write: TunnelWriteHalf<S>,
}

impl<R: RecvHalf, S: SendHalf> TunnelStream<R, S> {
    pub(crate) fn new(recv: R, send: S, resource: Arc<dyn StreamResource>) -> Self {
        let lease = Arc::new(StreamLease {
            halves: std::sync::atomic::AtomicUsize::new(2),
            resource,
        });
        Self {
            read: TunnelReadHalf::new(recv, lease.clone()),
            write: TunnelWriteHalf::new(send, lease),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_split(read: TunnelReadHalf<R>, write: TunnelWriteHalf<S>) -> Self {
        Self { read, write }
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

impl<S: SendHalf> Drop for TunnelWriteHalf<S> {
    fn drop(&mut self) {
        self.lease.dropping_half();
    }
}
impl<R: RecvHalf> Drop for TunnelReadHalf<R> {
    fn drop(&mut self) {
        self.lease.dropping_half();
    }
}
