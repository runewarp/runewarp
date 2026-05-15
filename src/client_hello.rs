use std::fmt;
use std::io::Cursor;

use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const CLIENT_HELLO_BUFFER_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    buffered_bytes: Vec<u8>,
    server_name: String,
}

impl ParsedClientHello {
    pub fn buffered_bytes(&self) -> &[u8] {
        &self.buffered_bytes
    }

    pub fn into_buffered_bytes(self) -> Vec<u8> {
        self.buffered_bytes
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.server_name, self.buffered_bytes)
    }
}

#[derive(Debug)]
pub enum ClientHelloError {
    Io(std::io::Error),
    InvalidTls,
    MissingSni,
    TooLong { limit: usize },
    UnexpectedEof,
}

impl fmt::Display for ClientHelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "client hello IO error: {error}"),
            Self::InvalidTls => formatter.write_str("invalid TLS client hello"),
            Self::MissingSni => formatter.write_str("missing SNI in client hello"),
            Self::TooLong { limit } => {
                write!(formatter, "client hello exceeded the {limit}-byte limit")
            }
            Self::UnexpectedEof => {
                formatter.write_str("client connection closed before the client hello completed")
            }
        }
    }
}

impl std::error::Error for ClientHelloError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidTls | Self::MissingSni | Self::TooLong { .. } | Self::UnexpectedEof => {
                None
            }
        }
    }
}

pub async fn read_client_hello<R>(reader: &mut R) -> Result<ParsedClientHello, ClientHelloError>
where
    R: AsyncRead + Unpin,
{
    let mut acceptor = Acceptor::default();
    let mut buffered_bytes = Vec::new();
    let mut read_buffer = [0_u8; 4096];

    loop {
        let read = reader
            .read(&mut read_buffer)
            .await
            .map_err(ClientHelloError::Io)?;
        if read == 0 {
            return Err(ClientHelloError::UnexpectedEof);
        }

        buffered_bytes.extend_from_slice(&read_buffer[..read]);
        if buffered_bytes.len() > CLIENT_HELLO_BUFFER_LIMIT {
            return Err(ClientHelloError::TooLong {
                limit: CLIENT_HELLO_BUFFER_LIMIT,
            });
        }

        let mut cursor = Cursor::new(&read_buffer[..read]);
        acceptor
            .read_tls(&mut cursor)
            .map_err(ClientHelloError::Io)?;

        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let server_name = accepted
                    .client_hello()
                    .server_name()
                    .ok_or(ClientHelloError::MissingSni)?
                    .to_owned();

                return Ok(ParsedClientHello {
                    buffered_bytes,
                    server_name,
                });
            }
            Ok(None) => {}
            Err((_error, _alert)) => return Err(ClientHelloError::InvalidTls),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use rcgen::generate_simple_self_signed;
    use rustls::ClientConnection;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncRead, ReadBuf};

    use super::{
        CLIENT_HELLO_BUFFER_LIMIT, ClientHelloError, ParsedClientHello, read_client_hello,
    };

    #[tokio::test]
    async fn parses_sni_from_a_valid_client_hello() {
        let server_name = "app.example.test";
        let client_hello = build_client_hello(ServerName::try_from(server_name).unwrap());
        let parsed = parse_from_chunks(vec![client_hello.clone()]).await.unwrap();

        assert_eq!(parsed.server_name(), server_name);
        assert_eq!(parsed.buffered_bytes(), client_hello.as_slice());
    }

    #[tokio::test]
    async fn preserves_extra_bytes_read_past_the_client_hello() {
        let client_hello = build_client_hello(ServerName::try_from("app.example.test").unwrap());
        let mut buffered = client_hello.clone();
        buffered.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

        let parsed = parse_from_chunks(vec![buffered.clone()]).await.unwrap();

        assert_eq!(parsed.server_name(), "app.example.test");
        assert_eq!(parsed.buffered_bytes(), buffered.as_slice());
    }

    #[tokio::test]
    async fn parses_a_client_hello_split_across_multiple_tls_records() {
        let client_hello = build_client_hello(ServerName::try_from("app.example.test").unwrap());
        let split_client_hello = split_tls_record(&client_hello, 19);
        let chunks = split_client_hello
            .iter()
            .copied()
            .map(|byte| vec![byte])
            .collect();

        let parsed = parse_from_chunks(chunks).await.unwrap();

        assert_eq!(parsed.server_name(), "app.example.test");
        assert_eq!(parsed.buffered_bytes(), split_client_hello.as_slice());
    }

    #[tokio::test]
    async fn rejects_a_client_hello_without_sni() {
        let server_name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
        let client_hello = build_client_hello(server_name);
        let error = parse_from_chunks(vec![client_hello]).await.unwrap_err();

        assert!(matches!(error, ClientHelloError::MissingSni));
    }

    #[tokio::test]
    async fn enforces_the_client_hello_size_limit() {
        let mut oversized = vec![0x16, 0x03, 0x03, 0x40, 0x01];
        oversized.extend(std::iter::repeat_n(0_u8, CLIENT_HELLO_BUFFER_LIMIT));

        let error = parse_from_chunks(vec![oversized]).await.unwrap_err();

        assert!(matches!(
            error,
            ClientHelloError::TooLong {
                limit: CLIENT_HELLO_BUFFER_LIMIT
            }
        ));
    }

    async fn parse_from_chunks(
        chunks: Vec<Vec<u8>>,
    ) -> Result<ParsedClientHello, ClientHelloError> {
        let mut reader = ChunkedReader::new(chunks);
        read_client_hello(&mut reader).await
    }

    fn build_client_hello(server_name: ServerName<'static>) -> Vec<u8> {
        let trusted_cert = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(trusted_cert.cert);
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut connection = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).unwrap();
        bytes
    }

    fn split_tls_record(bytes: &[u8], first_record_body_len: usize) -> Vec<u8> {
        assert!(bytes.len() > 5);

        let header = &bytes[..5];
        let body = &bytes[5..];
        assert!(first_record_body_len > 0);
        assert!(first_record_body_len < body.len());

        let second_record_body_len = body.len() - first_record_body_len;
        let mut fragmented = Vec::with_capacity(bytes.len() + 5);

        fragmented.extend_from_slice(&[
            header[0],
            header[1],
            header[2],
            ((first_record_body_len >> 8) & 0xff) as u8,
            (first_record_body_len & 0xff) as u8,
        ]);
        fragmented.extend_from_slice(&body[..first_record_body_len]);
        fragmented.extend_from_slice(&[
            header[0],
            header[1],
            header[2],
            ((second_record_body_len >> 8) & 0xff) as u8,
            (second_record_body_len & 0xff) as u8,
        ]);
        fragmented.extend_from_slice(&body[first_record_body_len..]);

        fragmented
    }

    struct ChunkedReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into(),
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(front) = self.chunks.front_mut() else {
                return Poll::Ready(Ok(()));
            };

            let written = front.len().min(buffer.remaining());
            buffer.put_slice(&front[..written]);

            if written == front.len() {
                self.chunks.pop_front();
            } else {
                front.drain(..written);
            }

            Poll::Ready(Ok(()))
        }
    }
}
