use std::convert::Infallible;
use std::io;
use std::path::Path;

use futures_util::StreamExt;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, AcmeState};

pub(crate) const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

pub(crate) type ManagedAcmeState = AcmeState<io::Error>;

pub(crate) fn build_acme_state(
    server_hostname: &str,
    email: &str,
    state_directory: &Path,
) -> ManagedAcmeState {
    AcmeConfig::new([server_hostname])
        .contact_push(format!("mailto:{email}"))
        .directory_lets_encrypt(true)
        .cache(DirCache::new(state_directory.to_path_buf()))
        .state()
}

pub(crate) async fn run_acme_state(mut state: ManagedAcmeState) -> io::Result<Infallible> {
    loop {
        match state.next().await {
            Some(Ok(_event)) => {}
            Some(Err(error)) => {
                eprintln!("warning: ACME certificate management error: {error}");
            }
            None => {
                return Err(io::Error::other(
                    "ACME certificate manager stopped unexpectedly",
                ));
            }
        }
    }
}
