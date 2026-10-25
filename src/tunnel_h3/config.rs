//! QUIC and TLS configuration for HTTP/3 Tunnel connections.

use std::sync::Arc;

use quinn::TransportConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::quic::{
    ClientIdentityAdmission, IDLE_TIMEOUT, KEEPALIVE_INTERVAL, QuicConfigError,
    pinned_client_auth_server_builder, pinned_client_auth_server_crypto,
};

use super::TUNNEL_H3_ALPN;

/// Maximum decoded HTTP/3 field-section size on either peer, limiting QPACK expansion.
pub(super) const MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;

/// Connection-wide QUIC receive credit on either peer, bounding unread transport data across streams.
const CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Per-stream QUIC receive credit on either peer, retaining Quinn's 1.25 MB default.
const STREAM_RECEIVE_WINDOW: u32 = 1_250_000;

/// Receive slots, idle or assigned, one Tunnel connection may hold: the Client-instance
/// stream-handler budget, which no single connection can exceed.
const MAX_RECEIVE_SLOTS: u32 = 1024;

/// Request streams for the event-stream subscription, its replacement during resubscription, and
/// other bodyless signaling requests.
const SIGNALING_REQUEST_STREAMS: u32 = 8;

/// Client-initiated request streams the Server admits concurrently on one Tunnel connection.
pub(crate) const MAX_TUNNEL_REQUEST_STREAMS: u32 = MAX_RECEIVE_SLOTS + SIGNALING_REQUEST_STREAMS;

/// Unidirectional streams each peer admits: the HTTP/3 control stream, both QPACK streams, and
/// headroom for reserved stream types that peers may send and receivers must ignore.
const MAX_H3_UNI_STREAMS: u32 = 8;

/// Server QUIC configuration for HTTP/3 Tunnel connections.
///
/// Requires a Client certificate whose pinned identity `admission` authorizes, negotiates ALPN
/// `h3`, and never accepts application early data.
pub fn make_server_tunnel_h3_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    admission: Arc<dyn ClientIdentityAdmission>,
) -> Result<quinn::ServerConfig, QuicConfigError> {
    let server_crypto = pinned_client_auth_server_crypto(cert_chain, private_key, admission)?;
    server_config(server_crypto)
}

/// Server HTTP/3 configuration with a live certificate resolver, including ACME.
pub fn make_server_tunnel_h3_config_with_resolver(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    admission: Arc<dyn ClientIdentityAdmission>,
) -> Result<quinn::ServerConfig, QuicConfigError> {
    server_config(pinned_client_auth_server_builder(admission)?.with_cert_resolver(resolver))
}

fn server_config(
    mut server_crypto: rustls::ServerConfig,
) -> Result<quinn::ServerConfig, QuicConfigError> {
    server_crypto.alpn_protocols = vec![TUNNEL_H3_ALPN.to_vec()];
    server_crypto.max_early_data_size = 0;

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport_config(Arc::new(server_transport_config()));
    Ok(server_config)
}

/// Client QUIC configuration for HTTP/3 Tunnel connections.
///
/// Presents the Client identity certificate, negotiates ALPN `h3`, and never sends application
/// early data. Session resumption may remain; every connection still waits for a fresh handshake.
pub fn make_client_tunnel_h3_config(
    roots: RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<quinn::ClientConfig, QuicConfigError> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, private_key)?;
    client_crypto.alpn_protocols = vec![TUNNEL_H3_ALPN.to_vec()];
    client_crypto.enable_early_data = false;

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(Arc::new(client_transport_config()));
    Ok(client_config)
}

fn server_transport_config() -> TransportConfig {
    let mut transport_config = base_transport_config();
    transport_config.max_concurrent_bidi_streams(MAX_TUNNEL_REQUEST_STREAMS.into());
    // Only the Client sends keepalives; the Server relies on received traffic and idle timeout.
    transport_config.keep_alive_interval(None);
    transport_config
}

fn client_transport_config() -> TransportConfig {
    let mut transport_config = base_transport_config();
    // HTTP/3 forbids Server-opened bidirectional streams.
    transport_config.max_concurrent_bidi_streams(0_u8.into());
    transport_config.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
    transport_config
}

fn base_transport_config() -> TransportConfig {
    let mut transport_config = TransportConfig::default();
    transport_config.max_concurrent_uni_streams(MAX_H3_UNI_STREAMS.into());
    transport_config.receive_window(CONNECTION_RECEIVE_WINDOW.into());
    transport_config.stream_receive_window(STREAM_RECEIVE_WINDOW.into());
    transport_config.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .expect("the fixed idle timeout should fit quinn's idle timeout type"),
    ));
    transport_config
}

#[cfg(test)]
mod tests {
    use super::{client_transport_config, server_transport_config};

    #[test]
    fn both_peers_bound_connection_and_stream_receive_windows() {
        for config in [server_transport_config(), client_transport_config()] {
            let config = format!("{config:?}");
            assert!(config.contains("receive_window: 67108864"), "{config}");
            assert!(
                config.contains("stream_receive_window: 1250000"),
                "{config}"
            );
        }
    }

    #[test]
    fn transport_admits_client_requests_only_and_keeps_alive_from_the_client() {
        let server = format!("{:?}", server_transport_config());
        let client = format!("{:?}", client_transport_config());

        assert!(
            server.contains("max_concurrent_bidi_streams: 1032"),
            "{server}"
        );
        assert!(server.contains("keep_alive_interval: None"), "{server}");
        assert!(
            client.contains("max_concurrent_bidi_streams: 0"),
            "{client}"
        );
        assert!(
            client.contains("keep_alive_interval: Some(20s)"),
            "{client}"
        );
        for config in [&server, &client] {
            assert!(config.contains("max_concurrent_uni_streams: 8"), "{config}");
            assert!(config.contains("max_idle_timeout: Some(60000)"), "{config}");
        }
    }
}
