use std::io;

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

const PROXY_STREAM_ERROR_CODE: u32 = 1;

pub(crate) async fn proxy_tcp_over_quic(
    tcp_stream: TcpStream,
    initial_bytes: Vec<u8>,
    quic_send: SendStream,
    quic_recv: RecvStream,
) -> io::Result<()> {
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();

    let (send_result, recv_result) = tokio::join!(
        forward_tcp_to_quic(tcp_reader, quic_send, initial_bytes),
        forward_quic_to_tcp(quic_recv, tcp_writer)
    );

    send_result?;
    recv_result
}

pub(crate) fn proxy_stream_error_code() -> quinn::VarInt {
    PROXY_STREAM_ERROR_CODE.into()
}

async fn forward_tcp_to_quic(
    mut tcp_reader: OwnedReadHalf,
    mut quic_send: SendStream,
    initial_bytes: Vec<u8>,
) -> io::Result<()> {
    let result = async {
        if !initial_bytes.is_empty() {
            quic_send.write_all(&initial_bytes).await?;
        }

        copy(&mut tcp_reader, &mut quic_send).await?;
        quic_send.finish().map_err(io::Error::other)
    }
    .await;

    if result.is_err() {
        let _ = quic_send.reset(proxy_stream_error_code());
    }

    result
}

async fn forward_quic_to_tcp(
    mut quic_recv: RecvStream,
    mut tcp_writer: OwnedWriteHalf,
) -> io::Result<()> {
    let result = async {
        copy(&mut quic_recv, &mut tcp_writer).await?;
        tcp_writer.shutdown().await
    }
    .await;

    if result.is_err() {
        let _ = quic_recv.stop(proxy_stream_error_code());
    }

    result
}
