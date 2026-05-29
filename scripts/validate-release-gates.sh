#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_root="$(cd "$script_dir/.." && pwd)"
repo_root="$tool_root"

. "$tool_root/scripts/lib.sh"

usage() {
  usage_error "$(basename "$0") <rehearsal|tag> [--repo-root PATH] --tag vX.Y.Z [--allowed-signers-file PATH]"
}

is_stable_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

validate_rehearsal_mode() {
  local repo_root="$1"
  local release_tag="$2"
  local cargo_version expected_tag

  [[ -n "$release_tag" ]] || die "rehearsal mode requires --tag vX.Y.Z"
  cargo_version="$(runewarp_version "$repo_root")" || die "failed to read version from Cargo.toml"
  is_stable_version "$cargo_version" || die "rehearsal mode requires a stable Cargo version, found $cargo_version"
  expected_tag="v$cargo_version"
  [[ "$release_tag" == "$expected_tag" ]] || die "rehearsal tag $release_tag must match Cargo version $cargo_version as $expected_tag"

  "$tool_root/scripts/validate-release-metadata.sh" ci --repo-root "$repo_root"
  "$tool_root/scripts/render-release-notes.sh" --repo-root "$repo_root" --version "$cargo_version" >/dev/null

  success "release rehearsal gate is valid"
}

validate_tag_mode() {
  local repo_root="$1"
  local release_tag="$2"
  local allowed_signers_file="$3"

  [[ -n "$release_tag" ]] || die "tag mode requires --tag vX.Y.Z"
  [[ -n "$allowed_signers_file" ]] || die "tag mode requires --allowed-signers-file"
  [[ -f "$allowed_signers_file" ]] || die "allowed signers file is required at $allowed_signers_file"

  require_command git

  "$tool_root/scripts/validate-release-metadata.sh" release --repo-root "$repo_root" --tag "$release_tag"

  section "Verifying signed release tag"
  note "Tag: $release_tag"
  note "Allowed signers: $allowed_signers_file"

  git \
    -C "$repo_root" \
    -c gpg.format=ssh \
    -c gpg.ssh.program=ssh-keygen \
    -c gpg.ssh.allowedSignersFile="$allowed_signers_file" \
    verify-tag "$release_tag" \
    >/dev/null

  success "release tag gate is valid"
}

main() {
  local mode="${1:-}"
  local release_tag=""
  local allowed_signers_file=""

  [[ -n "$mode" ]] || usage
  shift

  while (($#)); do
    case "$1" in
      --repo-root)
        [[ $# -ge 2 ]] || usage
        repo_root="$2"
        shift 2
        ;;
      --tag)
        [[ $# -ge 2 ]] || usage
        release_tag="$2"
        shift 2
        ;;
      --allowed-signers-file)
        [[ $# -ge 2 ]] || usage
        allowed_signers_file="$2"
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done

  case "$mode" in
    rehearsal)
      validate_rehearsal_mode "$repo_root" "$release_tag"
      ;;
    tag)
      validate_tag_mode "$repo_root" "$release_tag" "$allowed_signers_file"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
