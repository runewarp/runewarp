//! THROWAWAY. WT-only link target for comparison against the git-pinned slot path.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    runewarp::prototype_webtransport::timings_only().await
}
