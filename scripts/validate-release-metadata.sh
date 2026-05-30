#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_root="$(cd "$script_dir/.." && pwd)"
repo_root="$tool_root"

. "$tool_root/scripts/lib.sh"
. "$script_dir/lib-release-metadata.sh"
. "$script_dir/lib-changelog.sh"

usage() {
  usage_error "validate-release-metadata.sh <ci|release> [--repo-root PATH] [--tag-repo-root PATH] [--tag vX.Y.Z]"
}

validate_ci_mode() {
  local repo_root="$1"
  local cargo_version="$2"
  local changelog_path="$3"
  local first_heading normalized_first_heading release_heading

  first_heading="$(runewarp_changelog_first_h2_heading "$changelog_path")"
  [[ -n "$first_heading" ]] || die "CHANGELOG.md must contain at least one level-2 section heading"
  normalized_first_heading="$(runewarp_changelog_normalize_heading "$first_heading")"

  runewarp_changelog_validate_release_headings "$changelog_path"
  runewarp_changelog_validate_subsection_headings "$changelog_path"

  if runewarp_release_metadata_is_stable_version "$cargo_version"; then
    release_heading="$(runewarp_changelog_find_release_heading "$changelog_path" "$cargo_version")"
    [[ -n "$release_heading" ]] || die "stable Cargo version $cargo_version requires a matching changelog release entry"
    ! runewarp_changelog_has_unreleased_heading "$changelog_path" || die "stable Cargo version $cargo_version must not keep an Unreleased section"
    [[ "$first_heading" == "[${cargo_version}]"* ]] || die "stable Cargo version $cargo_version requires the top changelog section to match that release"
    runewarp_changelog_section_has_list_item "$changelog_path" "$release_heading" || die "release entry $cargo_version must contain at least one bullet item"
    return
  fi

  [[ "$normalized_first_heading" == "Unreleased" ]] || die "pre-release Cargo version $cargo_version requires Unreleased to be the top changelog section"
  runewarp_changelog_has_unreleased_heading "$changelog_path" || die "pre-release Cargo version $cargo_version requires an Unreleased section"
}

validate_release_mode() {
  local repo_root="$1"
  local tag_repo_root="$2"
  local cargo_version="$3"
  local release_tag="$4"

  [[ -n "$release_tag" ]] || die "release mode requires --tag vX.Y.Z"
  runewarp_release_metadata_is_stable_version "$cargo_version" || die "release mode requires a stable Cargo version, found $cargo_version"

  local expected_tag
  expected_tag="$(runewarp_release_metadata_tag_from_version "$cargo_version")" ||
    die "release mode requires a stable Cargo version, found $cargo_version"
  [[ "$release_tag" == "$expected_tag" ]] || die "release tag $release_tag must match Cargo version $cargo_version as $expected_tag"

  local tag_commit
  tag_commit="$(git -C "$tag_repo_root" rev-list -n1 "$release_tag" 2>/dev/null || true)"
  [[ -n "$tag_commit" ]] || die "git tag $release_tag does not exist in $tag_repo_root"

  local head_commit
  head_commit="$(git -C "$repo_root" rev-parse HEAD)"
  [[ "$tag_commit" == "$head_commit" ]] || die "git tag $release_tag must point at HEAD"

  "$tool_root/scripts/render-release-notes.sh" --repo-root "$repo_root" --version "$cargo_version" >/dev/null
}

main() {
  local mode="${1:-}"
  local release_tag=""
  local tag_repo_root=""

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
      --tag-repo-root)
        [[ $# -ge 2 ]] || usage
        tag_repo_root="$2"
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done

  case "$mode" in
    ci|release) ;;
    *)
      usage
      ;;
  esac

  local changelog_path="$repo_root/CHANGELOG.md"
  local cargo_toml_path="$repo_root/Cargo.toml"

  if [[ -z "$tag_repo_root" ]]; then
    tag_repo_root="$repo_root"
  fi

  [[ -f "$cargo_toml_path" ]] || die "Cargo.toml is required at $cargo_toml_path"
  [[ -f "$changelog_path" ]] || die "CHANGELOG.md is required at $changelog_path"
  grep -qx '# Changelog' "$changelog_path" || die "CHANGELOG.md must start with a '# Changelog' heading"

  local cargo_version
  cargo_version="$(runewarp_version "$repo_root")" || die "failed to read version from Cargo.toml"

  validate_ci_mode "$repo_root" "$cargo_version" "$changelog_path"

  if [[ "$mode" == "release" ]]; then
    validate_release_mode "$repo_root" "$tag_repo_root" "$cargo_version" "$release_tag"
  fi

  success "release metadata is valid"
}

main "$@"
