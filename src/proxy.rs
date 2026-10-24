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
    tokio::try_join!(
        async {
            tunnel_send.write_all(&initial_bytes).await?;
            tunnel_send.flush().await?;
            copy(&mut tcp_reader, &mut tunnel_send).await?;
            tunnel_send.shutdown().await
        },
        async {
            copy(&mut tunnel_recv, &mut tcp_writer).await?;
            tcp_writer.shutdown().await
        }
    )?;
    Ok(())
}
