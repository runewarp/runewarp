use std::io;
use std::net::SocketAddr;

use quinn::{RecvStream, SendStream};
use tokio::net::TcpStream;

use crate::proxy::{proxy_stream_error_code, proxy_tcp_over_quic};

pub(crate) async fn handle_tunnel_stream(
    send: SendStream,
    recv: RecvStream,
    backend_addr: SocketAddr,
) -> io::Result<()> {
    let backend_stream = match TcpStream::connect(backend_addr).await {
        Ok(stream) => stream,
        Err(error) => {
            let mut send = send;
            let mut recv = recv;
            let _ = send.reset(proxy_stream_error_code());
            let _ = recv.stop(proxy_stream_error_code());
            return Err(error);
        }
    };

    proxy_tcp_over_quic(backend_stream, Vec::new(), send, recv).await
}
