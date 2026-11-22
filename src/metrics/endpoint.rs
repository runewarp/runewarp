//! Bounded HTTP/1.1 scrape listener: GET `/metrics` only, at most four connections at once,
//! one request per connection and a five-second connection deadline.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use prometheus_client::collector::Collector;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::runtime_log;

pub(crate) const MAX_SCRAPE_CONNECTIONS: usize = 4;
pub(crate) const SCRAPE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// A running scrape listener. Dropping it stops the listener and every open scrape.
pub(crate) struct MetricsEndpoint {
    local_addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl MetricsEndpoint {
    /// Bind and serve `collector`. Metrics never gate serving: a bind failure logs an error
    /// naming `config_key` and returns `None`, and the runtime continues without metrics.
    pub(crate) async fn bind(
        role: &'static str,
        config_key: &'static str,
        bind_addr: SocketAddr,
        collector: Arc<dyn Collector>,
    ) -> Option<Self> {
        let listener = match TcpListener::bind(bind_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                runtime_log::metrics_listener_bind_failed(role, config_key, bind_addr, &error);
                return None;
            }
        };
        let local_addr = match listener.local_addr() {
            Ok(address) => address,
            Err(error) => {
                runtime_log::metrics_listener_bind_failed(role, config_key, bind_addr, &error);
                return None;
            }
        };
        runtime_log::metrics_listener_enabled(role, local_addr);
        let task = tokio::spawn(serve(listener, collector));
        Some(Self { local_addr, task })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for MetricsEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(listener: TcpListener, collector: Arc<dyn Collector>) {
    let permits = Arc::new(Semaphore::new(MAX_SCRAPE_CONNECTIONS));
    // Owned here so aborting the listener task also aborts every open scrape.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    // Over the cap, close at once rather than queueing work.
                    let Ok(permit) = permits.clone().try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let collector = collector.clone();
                    connections.spawn(async move {
                        serve_connection(stream, collector).await;
                        drop(permit);
                    });
                }
                Err(_) => tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await,
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve_connection(stream: TcpStream, collector: Arc<dyn Collector>) {
    let service = service_fn(move |request| {
        let collector = collector.clone();
        async move { Ok::<_, Infallible>(respond(&request, collector)) }
    });
    let connection = http1::Builder::new()
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service);
    let _ = tokio::time::timeout(SCRAPE_CONNECTION_TIMEOUT, connection).await;
}

fn respond(request: &Request<Incoming>, collector: Arc<dyn Collector>) -> Response<Full<Bytes>> {
    if request.method() != Method::GET || request.uri().path() != "/metrics" {
        return status(StatusCode::NOT_FOUND);
    }
    let body = super::render(collector);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    response
}

/// Minimal HTTP/1.1 client for tests: send `method path`, return status and body.
#[cfg(test)]
pub(crate) async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
) -> std::io::Result<(u16, String)> {
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(format!("{method} {path} HTTP/1.1\r\nHost: metrics\r\n\r\n").as_bytes())
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::other(format!("malformed response: {response}")))?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use prometheus_client::encoding::DescriptorEncoder;
    use std::io;

    use tokio::io::AsyncReadExt;

    use super::*;

    #[derive(Debug)]
    struct Fixed;

    impl Collector for Fixed {
        fn encode(&self, mut encoder: DescriptorEncoder) -> fmt::Result {
            super::super::encode_gauge(&mut encoder, "fixture_up", "Fixture.", None, 1)
        }
    }

    async fn bind() -> MetricsEndpoint {
        MetricsEndpoint::bind(
            "server",
            "server.metrics-bind-address",
            "127.0.0.1:0".parse().expect("literal address"),
            Arc::new(Fixed),
        )
        .await
        .expect("ephemeral bind succeeds")
    }

    #[tokio::test]
    async fn serves_openmetrics_on_get_metrics() -> io::Result<()> {
        let endpoint = bind().await;
        let (status, body) = request(endpoint.local_addr(), "GET", "/metrics").await?;
        assert_eq!(status, 200);
        assert!(body.contains("fixture_up 1"), "{body}");
        assert!(body.ends_with("# EOF\n"), "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn rejects_other_methods_and_paths_with_404() -> io::Result<()> {
        let endpoint = bind().await;
        for (method, path) in [
            ("POST", "/metrics"),
            ("HEAD", "/metrics"),
            ("GET", "/"),
            ("GET", "/metrics/extra"),
        ] {
            let (status, _) = request(endpoint.local_addr(), method, path).await?;
            assert_eq!(status, 404, "{method} {path}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn closes_connections_over_the_cap_and_recovers() -> io::Result<()> {
        let endpoint = bind().await;
        // Idle connections hold every slot until their deadline.
        let mut held = Vec::new();
        for _ in 0..MAX_SCRAPE_CONNECTIONS {
            held.push(TcpStream::connect(endpoint.local_addr()).await?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut rejected = TcpStream::connect(endpoint.local_addr()).await?;
        let mut buffer = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut buffer))
            .await
            .expect("an over-cap connection is closed at once");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

        drop(held);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (status, _) = request(endpoint.local_addr(), "GET", "/metrics").await?;
        assert_eq!(status, 200);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_closed_at_the_deadline() -> io::Result<()> {
        let endpoint = bind().await;
        let mut idle = TcpStream::connect(endpoint.local_addr()).await?;
        let mut buffer = [0; 1];
        let read = tokio::time::timeout(
            SCRAPE_CONNECTION_TIMEOUT + Duration::from_secs(1),
            idle.read(&mut buffer),
        )
        .await
        .expect("the scrape deadline closes an idle connection");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        Ok(())
    }

    #[tokio::test]
    async fn bind_failure_returns_none_without_panicking() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = occupied.local_addr().expect("address");
        let endpoint = MetricsEndpoint::bind(
            "server",
            "server.metrics-bind-address",
            address,
            Arc::new(Fixed),
        )
        .await;
        assert!(endpoint.is_none());
    }
}
