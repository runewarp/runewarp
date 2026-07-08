---
status: accepted
---

# Trusted main Docker cache layering

Runewarp keeps Docker cache scope as part of the trust boundary: pull requests may use the same dependency-aware Dockerfile optimization, but only with per-PR cache namespaces, while trusted `main` CI continues warming the shared trusted-main cache that native per-architecture `Images` publish jobs later reuse and refresh. Trusted publication now fans out into native `amd64` and `arm64` jobs, smokes each immutable per-architecture commit tag before merge, and preserves the merged bare 12-character commit tag as the release handoff artifact. We still prefer a simple multi-stage Dockerfile with a dummy dependency build over heavier tooling because it improves cache reuse for Rust dependencies without letting untrusted cache output cross into privileged image publication, and it keeps commit provenance in `--version` even though the final application crate still recompiles per commit.
