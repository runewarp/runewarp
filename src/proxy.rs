use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy};
use tokio::net::TcpStream;

pub(crate) async fn proxy_tcp_over_tunnel<R, W>(
    tcp_stream: TcpStream,
    initial_bytes: Vec<u8>,
    mut tunnel_send: W,
    mut tunnel_recv: R,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut tcp_reader, mut tcp_writer) = tcp_stream.into_split();
    let (to_tunnel, to_tcp) = tokio::join!(
        async move {
            tunnel_send.write_all(&initial_bytes).await?;
            tunnel_send.flush().await?;
            copy(&mut tcp_reader, &mut tunnel_send).await?;
            tunnel_send.shutdown().await
        },
        async move {
            copy(&mut tunnel_recv, &mut tcp_writer).await?;
            tcp_writer.shutdown().await
        }
    );
    to_tunnel.and(to_tcp)
}

#[cfg(test)]
mod tests {
    use super::proxy_tcp_over_tunnel;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    #[tokio::test]
    async fn failed_tunnel_write_preserves_the_response_in_flight() {
        timeout(Duration::from_secs(2), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
            let mut visitor = TcpStream::connect(listener.local_addr().expect("address"))
                .await
                .expect("Visitor connects");
            let (tcp, _) = listener.accept().await.expect("proxy socket");
            let (tunnel_send, stopped_reader) = duplex(8);
            drop(stopped_reader);
            let (mut response_writer, tunnel_recv) = duplex(8);
            let response = vec![b'r'; 64 * 1024];
            let expected = response.clone();
            let proxy = tokio::spawn(proxy_tcp_over_tunnel(
                tcp,
                b"request".to_vec(),
                tunnel_send,
                tunnel_recv,
            ));
            let sends_response = async move {
                response_writer.write_all(&response).await?;
                response_writer.shutdown().await
            };
            let mut received = Vec::new();
            let (sent, read) = tokio::join!(sends_response, visitor.read_to_end(&mut received),);
            read.expect("Visitor reads to FIN");
            assert!(
                received == expected,
                "the failed request must not cancel the response"
            );
            sent.expect("the whole response is sent");
            assert!(proxy.await.expect("proxy task").is_err());
        })
        .await
        .expect("proxy directions finish promptly");
    }
}
