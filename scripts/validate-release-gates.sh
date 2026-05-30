#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_root="$(cd "$script_dir/.." && pwd)"
repo_root="$tool_root"

. "$tool_root/scripts/lib.sh"
. "$script_dir/lib-release-metadata.sh"

usage() {
  usage_error "$(basename "$0") <rehearsal|tag> [--repo-root PATH] [--metadata-repo-root PATH] --tag vX.Y.Z [--allowed-signers-file PATH]"
}



require_commit_reachable_from_main() {
  local repo_root="$1"
  local candidate_ref="$2"
  local main_ref="refs/remotes/origin/main"

  require_command git

  git -C "$repo_root" rev-parse --verify "${candidate_ref}^{commit}" >/dev/null 2>&1 ||
    die "candidate ref $candidate_ref does not exist in $repo_root"
  git -C "$repo_root" rev-parse --verify "${main_ref}^{commit}" >/dev/null 2>&1 ||
    die "main ref $main_ref does not exist in $repo_root"
  git -C "$repo_root" merge-base --is-ancestor "$candidate_ref" "$main_ref" ||
    die "candidate ref $candidate_ref must be reachable from $main_ref"
}

validate_rehearsal_mode() {
  local repo_root="$1"
  local metadata_repo_root="$2"
  local release_tag="$3"
  local cargo_version expected_tag

  [[ -n "$release_tag" ]] || die "rehearsal mode requires --tag vX.Y.Z"
  cargo_version="$(runewarp_version "$metadata_repo_root")" || die "failed to read version from Cargo.toml"
  runewarp_release_metadata_is_stable_version "$cargo_version" || die "rehearsal mode requires a stable Cargo version, found $cargo_version"
  expected_tag="$(runewarp_release_metadata_tag_from_version "$cargo_version")" ||
    die "rehearsal mode requires a stable Cargo version, found $cargo_version"
  [[ "$release_tag" == "$expected_tag" ]] || die "rehearsal tag $release_tag must match Cargo version $cargo_version as $expected_tag"

  require_commit_reachable_from_main "$repo_root" HEAD
  "$tool_root/scripts/validate-release-metadata.sh" ci --repo-root "$metadata_repo_root"
  "$tool_root/scripts/render-release-notes.sh" --repo-root "$metadata_repo_root" --version "$cargo_version" >/dev/null

  success "release rehearsal gate is valid"
}

validate_tag_mode() {
  local repo_root="$1"
  local metadata_repo_root="$2"
  local release_tag="$3"
  local allowed_signers_file="$4"

  [[ -n "$release_tag" ]] || die "tag mode requires --tag vX.Y.Z"
  [[ -n "$allowed_signers_file" ]] || die "tag mode requires --allowed-signers-file"
  [[ -f "$allowed_signers_file" ]] || die "allowed signers file is required at $allowed_signers_file"

  require_command git

  "$tool_root/scripts/validate-release-metadata.sh" release --repo-root "$metadata_repo_root" --tag-repo-root "$repo_root" --tag "$release_tag"
  require_commit_reachable_from_main "$repo_root" "$release_tag"

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
  local metadata_repo_root=""

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
      --metadata-repo-root)
        [[ $# -ge 2 ]] || usage
        metadata_repo_root="$2"
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

  if [[ -z "$metadata_repo_root" ]]; then
    metadata_repo_root="$repo_root"
  fi

  case "$mode" in
    rehearsal)
      validate_rehearsal_mode "$repo_root" "$metadata_repo_root" "$release_tag"
      ;;
    tag)
      validate_tag_mode "$repo_root" "$metadata_repo_root" "$release_tag" "$allowed_signers_file"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
