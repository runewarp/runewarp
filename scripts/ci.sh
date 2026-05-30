#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

main() {
  cd "$repo_root"

  section "Linting workflows"
  ./scripts/lint-workflows.sh
  ./scripts/test-lint-workflows.sh

  section "Validating release metadata"
  ./scripts/validate-release-metadata.sh ci
  ./scripts/test-release-metadata.sh
  ./scripts/test-docker-hub-tag.sh

  section "Checking source install surface"
  ./scripts/validate-install-surfaces.sh cargo-install --bin-name runewarp --probe-arg --help --expected-text "Usage: runewarp"

  section "Checking package readiness"
  ./scripts/validate-install-surfaces.sh package-readiness

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

  section "Checking Docker image surface"
  ./scripts/validate-install-surfaces.sh docker-image --probe-arg --help --expected-text "Usage: runewarp" --image-tag runewarp:ci

  success "CI contract passed"
  note "Release metadata, install surfaces, Rust checks, docs, and Docker validation all succeeded"
}

main "$@"
