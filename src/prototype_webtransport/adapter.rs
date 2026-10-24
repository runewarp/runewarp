use super::WtStream;
use crate::{
    tunnel_h3::{
        TunnelStream,
        stream::{RecvHalf, SendHalf},
    },
    vendor::{
        h3::{
            error::{Code, StreamError},
            quic::{BidiStream, RecvStream, SendStream, SendStreamUnframed},
        },
        h3_quinn, h3_webtransport,
    },
};
use bytes::{Buf, Bytes};
use futures_util::{future::poll_fn, task::AtomicWaker};
use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

type RawSend = h3_webtransport::stream::SendStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RawRecv = h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>;
struct State {
    send: Mutex<RawSend>,
    recv: Mutex<RawRecv>,
    closed: AtomicBool,
    reader: AtomicWaker,
    writer: AtomicWaker,
}
impl State {
    fn cancel(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.send
            .lock()
            .expect("prototype send mutex")
            .reset(0x170d7b68);
        self.recv
            .lock()
            .expect("prototype recv mutex")
            .stop_sending(0x170d7b68);
        self.reader.wake();
        self.writer.wake();
    }
}
#[derive(Default)]
pub(super) struct Registry {
    streams: Mutex<Vec<Weak<State>>>,
    pub closed: AtomicBool,
    pub draining: AtomicBool,
}
impl Registry {
    pub fn close(&self) {
        let streams = self.streams.lock().expect("prototype registry mutex");
        self.closed.store(true, Ordering::SeqCst);
        for state in streams.iter().filter_map(Weak::upgrade) {
            state.cancel();
        }
    }
    pub fn adapt(&self, stream: WtStream) -> Stream {
        let (send, recv) = stream.split();
        let state = Arc::new(State {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            closed: AtomicBool::new(false),
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
        });
        let mut streams = self.streams.lock().expect("prototype registry mutex");
        streams.retain(|item| item.strong_count() > 0);
        streams.push(Arc::downgrade(&state));
        if self.closed.load(Ordering::SeqCst) {
            state.cancel();
        }
        TunnelStream::new(Recv(state.clone()), Send(state), Arc::new(()))
    }
}
pub(super) struct Send(Arc<State>);
pub(super) struct Recv(Arc<State>);
pub(super) type Stream = TunnelStream<Recv, Send>;
fn closed_error() -> StreamError {
    StreamError::StreamError {
        code: Code::H3_REQUEST_CANCELLED,
        reason: "prototype session closed".into(),
    }
}
impl SendHalf for Send {
    async fn send_data(&mut self, mut data: Bytes) -> std::result::Result<(), StreamError> {
        while data.has_remaining() {
            poll_fn(|cx| {
                self.0.writer.register(cx.waker());
                if self.0.closed.load(Ordering::SeqCst) {
                    return Poll::Ready(Err(closed_error()));
                }
                self.0
                    .send
                    .lock()
                    .expect("prototype send mutex")
                    .poll_send(cx, &mut data)
                    .map_err(|e| StreamError::Undefined(Box::new(e)))
            })
            .await?;
        }
        Ok(())
    }
    async fn finish(&mut self) -> std::result::Result<(), StreamError> {
        poll_fn(|cx| {
            self.0.writer.register(cx.waker());
            if self.0.closed.load(Ordering::SeqCst) {
                return Poll::Ready(Err(closed_error()));
            }
            self.0
                .send
                .lock()
                .expect("prototype send mutex")
                .poll_finish(cx)
                .map_err(|e| StreamError::Undefined(Box::new(e)))
        })
        .await
    }
    fn reset(&mut self) {
        self.0
            .send
            .lock()
            .expect("prototype send mutex")
            .reset(0x52e4a40fa8db);
    }
}
impl RecvHalf for Recv {
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<Option<Bytes>, StreamError>> {
        self.0.reader.register(cx.waker());
        if self.0.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_error()));
        }
        self.0
            .recv
            .lock()
            .expect("prototype recv mutex")
            .poll_data(cx)
            .map_err(|e| StreamError::Undefined(Box::new(e)))
    }
}
impl Drop for Recv {
    fn drop(&mut self) {
        self.0
            .recv
            .lock()
            .expect("prototype recv mutex")
            .stop_sending(0x52e4a40fa8db);
    }
}
