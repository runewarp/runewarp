#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

main() {
  cd "$repo_root"
 
  section "Validating release metadata"
  ./scripts/validate-release-metadata.sh ci

  section "Checking Rust formatting"
  cargo fmt --check

  section "Running Clippy"
  cargo clippy --all-targets -- -D warnings

  section "Running Rust tests"
  cargo test --quiet

  section "Building documentation"
  cargo doc --no-deps

  section "Running Docker smoke test"
  ./examples/docker/smoke.sh

  success "CI contract passed"
  note "Release metadata, Rust checks, docs, and Docker smoke test all succeeded"
}

main "$@"
