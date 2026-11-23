//! Byte counting at an I/O boundary for bandwidth metrics.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use prometheus_client::metrics::counter::Counter;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Counts bytes the inner stream reports as read or written. A direction without a counter
/// costs nothing.
///
/// A write adds only the length the inner writer accepted, so partial writes count exactly what
/// reached the destination. Each count lands as soon as the call returns, so bytes moved before
/// a cancellation or a failed later write stay counted.
pub(crate) struct CountedIo<S> {
    inner: S,
    read: Option<Counter>,
    written: Option<Counter>,
    /// Leading written bytes left uncounted, such as framing ahead of Visitor bytes.
    uncounted_prefix: usize,
}

impl<S> CountedIo<S> {
    pub(crate) fn new(inner: S, read: Option<Counter>, written: Option<Counter>) -> Self {
        Self {
            inner,
            read,
            written,
            uncounted_prefix: 0,
        }
    }

    /// Count only written bytes.
    pub(crate) fn writer(inner: S, written: Counter) -> Self {
        Self::new(inner, None, Some(written))
    }

    /// Leave the first `len` written bytes uncounted.
    pub(crate) fn skipping_written_prefix(mut self, len: usize) -> Self {
        self.uncounted_prefix = len;
        self
    }

    fn count_written(&mut self, len: usize) {
        let skipped = len.min(self.uncounted_prefix);
        self.uncounted_prefix -= skipped;
        if len > skipped
            && let Some(written) = &self.written
        {
            written.inc_by((len - skipped) as u64);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(counter)) = (&result, &self.read) {
            let read = buf.filled().len() - before;
            if read > 0 {
                counter.inc_by(read as u64);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            self.count_written(written);
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(written)) = result {
            self.count_written(written);
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    /// Accepts at most `chunk` bytes per write, then fails once `fail_after` bytes are taken.
    struct PartialWriter {
        chunk: usize,
        accepted: usize,
        fail_after: usize,
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.accepted >= self.fail_after {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let taken = buf.len().min(self.chunk);
            self.accepted += taken;
            Poll::Ready(Ok(taken))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn partial_writes_count_only_accepted_bytes_and_survive_a_later_failure() {
        let written = Counter::default();
        let mut writer = CountedIo::writer(
            PartialWriter {
                chunk: 3,
                accepted: 0,
                fail_after: 7,
            },
            written.clone(),
        );
        assert_eq!(writer.write(b"abcdefgh").await.expect("partial write"), 3);
        assert_eq!(written.get(), 3);
        assert!(writer.write_all(b"abcdefgh").await.is_err());
        // 3 more, then 3 more (9 accepted in total) before the failure.
        assert_eq!(written.get(), 9);
    }

    #[tokio::test]
    async fn written_prefix_is_skipped_across_write_boundaries() {
        let written = Counter::default();
        let mut writer = CountedIo::writer(
            PartialWriter {
                chunk: 4,
                accepted: 0,
                fail_after: usize::MAX,
            },
            written.clone(),
        )
        .skipping_written_prefix(6);
        writer.write_all(b"FRAMEDhello").await.expect("write");
        assert_eq!(written.get(), 5);
    }

    #[tokio::test]
    async fn reads_count_filled_bytes_and_eof_counts_nothing() {
        let read = Counter::default();
        let (mut peer, inner) = duplex(64);
        let mut reader = CountedIo::new(inner, Some(read.clone()), None);
        peer.write_all(b"response").await.expect("peer write");
        drop(peer);
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.expect("read");
        assert_eq!(received, b"response");
        assert_eq!(read.get(), 8);
    }

    #[tokio::test]
    async fn bytes_moved_before_cancellation_stay_counted() {
        let written = Counter::default();
        let (inner, mut peer) = duplex(4);
        let mut writer = CountedIo::writer(inner, written.clone());
        // The duplex buffer holds 4 bytes, so the rest blocks until the future is cancelled.
        let cancelled =
            tokio::time::timeout(Duration::from_millis(20), writer.write_all(b"abcdefgh")).await;
        assert!(cancelled.is_err());
        assert_eq!(written.get(), 4);
        let mut buffered = [0_u8; 4];
        peer.read_exact(&mut buffered).await.expect("peer read");
        assert_eq!(&buffered, b"abcd");
    }
}
