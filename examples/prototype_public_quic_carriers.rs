//! THROWAWAY. Three Public QUIC carrier profiles on one loopback mTLS H3 connection.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    runewarp::prototype_webtransport::public_quic::run().await
}
