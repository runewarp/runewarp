//! THROWAWAY bounded CLOSE capsule codec. No general Capsule API is claimed.
use super::{ClientRequest, Result};
use crate::vendor::{h3, h3_quinn};
use bytes::{Buf, Bytes};

pub(super) fn close() -> Bytes {
    Bytes::from_static(&[0x68, 0x43, 4, 0, 0, 0, 0])
}
fn validate(buffer: &[u8]) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    } // A bare FIN is normal session close.
    let mut cursor = buffer;
    let mut closed = false;
    while !cursor.is_empty() {
        if closed {
            return Err("data after CLOSE capsule".into());
        }
        let kind = h3::proto::varint::VarInt::decode(&mut cursor)
            .map_err(|e| format!("capsule varint: {e:?}"))?;
        let length = h3::proto::varint::VarInt::decode(&mut cursor)
            .map_err(|e| format!("capsule varint: {e:?}"))?
            .into_inner() as usize;
        if length > cursor.len() {
            return Err("truncated capsule".into());
        }
        if kind.into_inner() == 0x2843 {
            if !(4..=1028).contains(&length) || std::str::from_utf8(&cursor[4..length]).is_err() {
                return Err("invalid CLOSE capsule".into());
            }
            closed = true;
        }
        cursor.advance(length);
    }
    Ok(())
}
fn append(buffer: &mut Vec<u8>, mut data: impl Buf) -> Result<()> {
    if buffer.len() + data.remaining() > 8192 {
        return Err("prototype capsule intake bound".into());
    }
    buffer.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    Ok(())
}
pub(super) async fn receive_client(stream: &mut ClientRequest, buffer: &mut Vec<u8>) -> Result<()> {
    while let Some(data) = stream.recv_data().await? {
        append(buffer, data)?;
    }
    validate(buffer)
}
pub(super) async fn receive_server(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    while let Some(data) = stream.recv_data().await? {
        append(buffer, data)?;
    }
    validate(buffer)
}
