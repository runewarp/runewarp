//! Server connection correlation, allocated at accept and retained across owned tasks.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::tunnel::ServerRuntimeGeneration;

static LAST_CONNECTION_ID: AtomicU64 = AtomicU64::new(0);

tokio::task_local! {
    pub(crate) static CONNECTION_LOG: ConnectionLogContext;
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectionLogContext {
    pub(crate) generation: ServerRuntimeGeneration,
    pub(crate) connection_id: u64,
}

impl ConnectionLogContext {
    pub(crate) fn allocate(generation: ServerRuntimeGeneration) -> io::Result<Self> {
        // One process-wide sequence covers both protocols, every listener and runtime restart.
        // On exhaustion the checked update leaves MAX unchanged, so no ID can wrap or be reused.
        let mut previous = LAST_CONNECTION_ID.load(Ordering::Relaxed);
        let connection_id = loop {
            let next = previous
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Server connection IDs exhausted"))?;
            match LAST_CONNECTION_ID.compare_exchange_weak(
                previous,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break next,
                Err(actual) => previous = actual,
            }
        };
        Ok(Self {
            generation,
            connection_id,
        })
    }
}

pub(crate) fn current() -> Option<ConnectionLogContext> {
    CONNECTION_LOG.try_with(|context| *context).ok()
}

/// Tokio spawns do not inherit task locals. Capture the accepted connection before spawning.
pub(crate) fn inherit<F: Future>(future: F) -> impl Future<Output = F::Output> {
    in_context(current(), future)
}

pub(crate) async fn in_context<F: Future>(
    context: Option<ConnectionLogContext>,
    future: F,
) -> F::Output {
    match context {
        Some(context) => CONNECTION_LOG.scope(context, future).await,
        None => future.await,
    }
}

pub(crate) fn sync_in_context<T>(
    context: Option<ConnectionLogContext>,
    action: impl FnOnce() -> T,
) -> T {
    match context {
        Some(context) => CONNECTION_LOG.sync_scope(context, action),
        None => action(),
    }
}

/// Quinn spawns its TLS connection driver synchronously from Incoming::accept. Preserve that
/// connection's context in the driver so certificate-verifier warnings identify failed handshakes.
/// Socket and timer behavior remains Tokio's unchanged implementation.
#[derive(Debug)]
pub(crate) struct ServerQuicRuntime;

impl quinn::Runtime for ServerQuicRuntime {
    fn new_timer(&self, instant: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(instant)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        quinn::TokioRuntime.spawn(Box::pin(inherit(future)));
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        quinn::TokioRuntime.now()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use quinn::Runtime;

    use super::ServerQuicRuntime;

    #[tokio::test(start_paused = true)]
    async fn quic_clock_follows_tokio_simulated_time() {
        let runtime = ServerQuicRuntime;
        let started = runtime.now();

        tokio::time::advance(Duration::from_secs(60)).await;

        assert_eq!(runtime.now() - started, Duration::from_secs(60));
    }
}
