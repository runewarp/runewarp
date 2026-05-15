use std::io;

use tokio::net::TcpStream;

use crate::client_hello::read_client_hello;
use crate::proxy::proxy_tcp_over_quic;

use super::active_client::ActiveClientSlot;

pub(crate) async fn handle_visitor_connection(
    mut visitor_stream: TcpStream,
    active_client_slot: ActiveClientSlot,
) -> io::Result<()> {
    let parsed_client_hello = match read_client_hello(&mut visitor_stream).await {
        Ok(parsed_client_hello) => parsed_client_hello,
        Err(_) => return Ok(()),
    };
    let (_public_hostname, buffered_bytes) = parsed_client_hello.into_parts();

    let Some(active_connection) = active_client_slot.current_connection().await else {
        return Ok(());
    };

    let (send, recv) = match active_connection.open_bi().await {
        Ok(stream) => stream,
        Err(_) => return Ok(()),
    };

    proxy_tcp_over_quic(visitor_stream, buffered_bytes, send, recv).await
}
