#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"
. "$script_dir/lib-changelog.sh"

usage() {
  usage_error "render-release-notes.sh --version X.Y.Z [--repo-root PATH]"
}

main() {
  local version=""

  while (($#)); do
    case "$1" in
      --repo-root)
        [[ $# -ge 2 ]] || usage
        repo_root="$2"
        shift 2
        ;;
      --version)
        [[ $# -ge 2 ]] || usage
        version="$2"
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done

  [[ -n "$version" ]] || usage

  local changelog_path="$repo_root/CHANGELOG.md"
  [[ -f "$changelog_path" ]] || die "CHANGELOG.md is required at $changelog_path"

  local release_heading
  release_heading="$(runewarp_changelog_find_release_heading "$changelog_path" "$version")"
  [[ -n "$release_heading" ]] || die "CHANGELOG.md does not contain a release entry for $version"
  runewarp_changelog_validate_section_subsection_headings "$changelog_path" "$release_heading"

  runewarp_changelog_print_release_section "$changelog_path" "$release_heading"

  printf '\n## Install\n\n'
  printf '```bash\n'
  printf 'cargo install --version %s runewarp\n' "$version"
  printf 'docker pull runewarp/runewarp:%s\n' "$version"
  printf '```\n'
}

main "$@"
