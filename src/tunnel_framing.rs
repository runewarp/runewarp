use std::io;

use tokio::io::AsyncRead;

use crate::VisitorTcpAddresses;
use crate::client_hello::{ParsedClientHello, read_client_hello};
use crate::proxy_protocol::read_proxy_v2;

#[derive(Debug)]
pub(crate) struct DecodedTunnelStream {
    pub(crate) addresses: VisitorTcpAddresses,
    pub(crate) client_hello: ParsedClientHello,
}

pub(crate) fn encode_tunnel_stream(
    addresses: VisitorTcpAddresses,
    buffered_client_hello: &[u8],
) -> Vec<u8> {
    let mut encoded = addresses.encode_proxy_v2();
    encoded.extend_from_slice(buffered_client_hello);
    encoded
}

pub(crate) async fn read_tunnel_stream<R>(reader: &mut R) -> io::Result<DecodedTunnelStream>
where
    R: AsyncRead + Unpin,
{
    let addresses = read_proxy_v2(reader).await.map_err(io::Error::other)?;
    let client_hello = read_client_hello(reader).await.map_err(io::Error::other)?;
    Ok(DecodedTunnelStream {
        addresses,
        client_hello,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConnection, RootCertStore};
    use tokio::io::{AsyncRead, ReadBuf};

    use super::{encode_tunnel_stream, read_tunnel_stream};
    use crate::VisitorTcpAddresses;

    #[tokio::test]
    async fn round_trips_fragmented_ipv4_frame_and_buffered_client_hello() {
        let addresses = addresses("192.0.2.10:12345", "198.51.100.20:443");
        let client_hello = build_client_hello("app.example.test");

        let encoded = encode_tunnel_stream(addresses, &client_hello);

        assert_eq!(
            &encoded[..28],
            &[
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
                0x00, 0x0c, 192, 0, 2, 10, 198, 51, 100, 20, 0x30, 0x39, 0x01, 0xbb,
            ]
        );
        assert_eq!(&encoded[28..], client_hello.as_slice());

        let mut reader = ChunkedReader::one_byte_at_a_time(encoded);
        let decoded = read_tunnel_stream(&mut reader).await.unwrap();

        assert_eq!(decoded.addresses, addresses);
        assert_eq!(
            decoded.client_hello.public_hostname().as_str(),
            "app.example.test"
        );
        assert_eq!(decoded.client_hello.buffered_bytes(), client_hello);
    }

    #[tokio::test]
    async fn round_trips_fragmented_ipv6_frame() {
        let addresses = addresses("[2001:db8::1]:12345", "[2001:db8::2]:443");
        let client_hello = build_client_hello("app.example.test");
        let encoded = encode_tunnel_stream(addresses, &client_hello);
        let mut reader = ChunkedReader::one_byte_at_a_time(encoded);

        let decoded = read_tunnel_stream(&mut reader).await.unwrap();

        assert_eq!(decoded.addresses, addresses);
        assert_eq!(decoded.client_hello.buffered_bytes(), client_hello);
    }

    #[tokio::test]
    async fn ignores_allowed_proxy_tlvs_before_buffered_client_hello() {
        let addresses = addresses("192.0.2.10:12345", "198.51.100.20:443");
        let client_hello = build_client_hello("app.example.test");
        let mut encoded = encode_tunnel_stream(addresses, &client_hello);
        let proxy_len = 28;
        let tlv = [0xe0, 0x00, 0x03, b'r', b'a', b'w'];
        encoded.splice(proxy_len..proxy_len, tlv);
        encoded[14..16].copy_from_slice(&18_u16.to_be_bytes());
        let mut reader = ChunkedReader::one_byte_at_a_time(encoded);

        let decoded = read_tunnel_stream(&mut reader).await.unwrap();

        assert_eq!(decoded.addresses, addresses);
        assert_eq!(decoded.client_hello.buffered_bytes(), client_hello);
    }

    #[tokio::test]
    async fn rejects_malformed_proxy_metadata() {
        let addresses = addresses("192.0.2.10:12345", "198.51.100.20:443");
        let client_hello = build_client_hello("app.example.test");
        let mut encoded = encode_tunnel_stream(addresses, &client_hello);
        encoded[0] ^= 0xff;

        let error = read_tunnel_stream(&mut encoded.as_slice())
            .await
            .unwrap_err();

        assert!(error.to_string().contains("PROXY protocol v2"));
    }

    #[tokio::test]
    async fn rejects_malformed_client_hello_after_valid_metadata() {
        let addresses = addresses("192.0.2.10:12345", "198.51.100.20:443");
        let encoded = encode_tunnel_stream(addresses, b"not TLS");

        let error = read_tunnel_stream(&mut encoded.as_slice())
            .await
            .unwrap_err();

        assert!(error.to_string().contains("client hello"));
    }

    fn addresses(source: &str, destination: &str) -> VisitorTcpAddresses {
        VisitorTcpAddresses {
            source: source.parse::<SocketAddr>().unwrap(),
            destination: destination.parse::<SocketAddr>().unwrap(),
        }
    }

    fn build_client_hello(server_name: &'static str) -> Vec<u8> {
        let trusted_cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(trusted_cert.cert)).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_name).unwrap();
        let mut connection = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).unwrap();
        bytes
    }

    struct ChunkedReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkedReader {
        fn one_byte_at_a_time(bytes: Vec<u8>) -> Self {
            Self {
                chunks: bytes.into_iter().map(|byte| vec![byte]).collect(),
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            buffer.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }
}
