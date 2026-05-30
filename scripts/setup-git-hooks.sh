#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

main() {
  require_command git

  section "Configuring Git hooks"
  note "Repository root: $repo_root"

  git -C "$repo_root" config core.hooksPath .githooks

  success "git hooks are configured"
  note "Staged workflow changes now run through .githooks/pre-commit"
}

main "$@"
