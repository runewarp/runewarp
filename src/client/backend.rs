use quinn::{RecvStream, SendStream};
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::client::service::select_service;
use crate::client_hello::read_client_hello;
use crate::runtime_log::{client_route_line, emit_stderr, warning_line};
use crate::{ClientServiceSettings, proxy::proxy_stream_error_code, proxy::proxy_tcp_over_quic};

pub(crate) async fn handle_tunnel_stream(
    send: SendStream,
    mut recv: RecvStream,
    services: Vec<ClientServiceSettings>,
    logs: bool,
) -> io::Result<()> {
    let (backend_address, public_hostname, buffered_bytes) =
        match resolve_backend(&services, &mut recv).await {
            Ok(selection) => selection,
            Err(BackendResolutionError::ReadClientHello(error)) => {
                emit_stderr(
                    logs,
                    &warning_line("client", &format!("rejected stream: {error}")),
                );
                reject_stream(send, recv);
                return Err(error);
            }
            Err(BackendResolutionError::NoMatchingService { public_hostname }) => {
                emit_stderr(
                    logs,
                    &client_route_line(&public_hostname, "rejected (no matching service)"),
                );
                reject_stream(send, recv);
                return Ok(());
            }
        };

    let mut backend_stream = match TcpStream::connect(backend_address.as_str()).await {
        Ok(stream) => stream,
        Err(error) => {
            emit_stderr(logs, &backend_connect_failed_route_line(&public_hostname));
            reject_stream(send, recv);
            return Err(error);
        }
    };
    if let Err(error) = backend_stream.write_all(&buffered_bytes).await {
        emit_stderr(logs, &backend_write_failed_route_line(&public_hostname));
        reject_stream(send, recv);
        return Err(error);
    }
    emit_stderr(logs, &forwarded_route_line(&public_hostname));

    proxy_tcp_over_quic(backend_stream, Vec::new(), send, recv).await
}

enum BackendResolutionError {
    ReadClientHello(io::Error),
    NoMatchingService { public_hostname: String },
}

async fn resolve_backend(
    services: &[ClientServiceSettings],
    recv: &mut RecvStream,
) -> Result<(String, String, Vec<u8>), BackendResolutionError> {
    let parsed_client_hello = read_client_hello(recv)
        .await
        .map_err(io::Error::other)
        .map_err(BackendResolutionError::ReadClientHello)?;
    let (public_hostname, buffered_bytes) = parsed_client_hello.into_parts();
    let Some(service) = select_service(services, &public_hostname) else {
        return Err(BackendResolutionError::NoMatchingService { public_hostname });
    };

    Ok((
        service.backend_address.clone(),
        public_hostname,
        buffered_bytes,
    ))
}

fn reject_stream(mut send: SendStream, mut recv: RecvStream) {
    let _ = send.reset(proxy_stream_error_code());
    let _ = recv.stop(proxy_stream_error_code());
}

fn backend_connect_failed_route_line(public_hostname: &str) -> String {
    client_route_line(public_hostname, "backend connect failed")
}

fn backend_write_failed_route_line(public_hostname: &str) -> String {
    client_route_line(public_hostname, "backend write failed")
}

fn forwarded_route_line(public_hostname: &str) -> String {
    client_route_line(public_hostname, "forwarded")
}

#[cfg(test)]
mod tests {
    use super::{
        backend_connect_failed_route_line, backend_write_failed_route_line, forwarded_route_line,
    };

    #[test]
    fn route_lines_do_not_log_backend_addresses() {
        assert_eq!(
            backend_connect_failed_route_line("app.example.test"),
            "client route app.example.test -> backend connect failed"
        );
        assert_eq!(
            backend_write_failed_route_line("app.example.test"),
            "client route app.example.test -> backend write failed"
        );
        assert_eq!(
            forwarded_route_line("app.example.test"),
            "client route app.example.test -> forwarded"
        );
    }
}
