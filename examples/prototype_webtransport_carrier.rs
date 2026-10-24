//! THROWAWAY. No runtime wiring, no persistent material, loopback only.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    runewarp::prototype_webtransport::run().await
}
