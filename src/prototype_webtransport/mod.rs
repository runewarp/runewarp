//! THROWAWAY. Loopback-only WebTransport carrier evidence, never used by either runtime.

mod adapter;
mod capsule;
mod client;
mod experiment;
mod fixture;
mod measure;
mod server;

pub use experiment::run;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;
const STEP: std::time::Duration = std::time::Duration::from_secs(5);
const SERVER: &str = "tunnel.example.test";
const SESSION_PATH: &str = "/prototype/webtransport";

type WtStream = crate::vendor::h3_webtransport::stream::BidiStream<
    crate::vendor::h3_quinn::BidiStream<bytes::Bytes>,
    bytes::Bytes,
>;
type Session = crate::vendor::h3_webtransport::server::WebTransportSession<
    crate::vendor::h3_quinn::Connection,
    bytes::Bytes,
>;
type ClientRequest = crate::vendor::h3::client::RequestStream<
    crate::vendor::h3_quinn::BidiStream<bytes::Bytes>,
    bytes::Bytes,
>;

/// THROWAWAY: measure only the WT path for a carrier binary-size comparison.
pub async fn timings_only() -> Result<()> {
    for _ in 0..3 {
        for count in [1, 32, 64, 128] {
            tokio::time::timeout(STEP, measure::wt(count)).await??;
        }
    }
    Ok(())
}
