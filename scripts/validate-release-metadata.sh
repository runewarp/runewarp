#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_root="$(cd "$script_dir/.." && pwd)"
repo_root="$tool_root"

. "$tool_root/scripts/lib.sh"

usage() {
  usage_error "validate-release-metadata.sh <ci|release> [--repo-root PATH] [--tag-repo-root PATH] [--tag vX.Y.Z]"
}

is_stable_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

read_first_h2_heading() {
  awk '
    /^## / {
      sub(/^## /, "", $0)
      print
      exit
    }
  ' "$1"
}

validate_version_headings() {
  local changelog_path="$1"

  awk '
    /^## / {
      if ($0 == "## Unreleased") {
        next
      }

      if ($0 !~ /^## \[[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$/) {
        printf "error: invalid changelog release heading: %s\n", $0 > "/dev/stderr"
        exit 1
      }
    }
  ' "$changelog_path"
}

validate_subsection_headings() {
  local changelog_path="$1"

  awk '
    BEGIN {
      allowed["Added"] = 1
      allowed["Changed"] = 1
      allowed["Deprecated"] = 1
      allowed["Removed"] = 1
      allowed["Fixed"] = 1
      allowed["Security"] = 1
      in_section = 0
    }

    /^## / {
      in_section = 1
      next
    }

    /^### / {
      heading = $0
      sub(/^### /, "", heading)

      if (!in_section) {
        printf "error: changelog subsection must appear under a changelog section: %s\n", heading > "/dev/stderr"
        exit 1
      }

      if (!(heading in allowed)) {
        printf "error: invalid changelog subsection: %s\n", heading > "/dev/stderr"
        exit 1
      }
    }
  ' "$changelog_path"
}

find_release_heading() {
  local changelog_path="$1"
  local version="$2"

  grep -E "^## \[$version\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" "$changelog_path" | head -n1 || true
}

section_has_list_item() {
  local changelog_path="$1"
  local heading="$2"

  awk -v heading="$heading" '
    $0 == heading {
      in_section = 1
      next
    }

    in_section && /^## / {
      exit found ? 0 : 1
    }

    in_section && /^- / {
      found = 1
    }

    END {
      if (in_section) {
        exit found ? 0 : 1
      }

      exit 2
    }
  ' "$changelog_path"
}

validate_ci_mode() {
  local repo_root="$1"
  local cargo_version="$2"
  local changelog_path="$3"
  local first_heading release_heading

  first_heading="$(read_first_h2_heading "$changelog_path")"
  [[ -n "$first_heading" ]] || die "CHANGELOG.md must contain at least one level-2 section heading"

  validate_version_headings "$changelog_path"
  validate_subsection_headings "$changelog_path"

  if is_stable_version "$cargo_version"; then
    release_heading="$(find_release_heading "$changelog_path" "$cargo_version")"
    [[ -n "$release_heading" ]] || die "stable Cargo version $cargo_version requires a matching changelog release entry"
    ! grep -qx '## Unreleased' "$changelog_path" || die "stable Cargo version $cargo_version must not keep an Unreleased section"
    [[ "$first_heading" == "[${cargo_version}]"* ]] || die "stable Cargo version $cargo_version requires the top changelog section to match that release"
    section_has_list_item "$changelog_path" "$release_heading" || die "release entry $cargo_version must contain at least one bullet item"
    return
  fi

  [[ "$first_heading" == "Unreleased" ]] || die "pre-release Cargo version $cargo_version requires Unreleased to be the top changelog section"
  grep -qx '## Unreleased' "$changelog_path" || die "pre-release Cargo version $cargo_version requires an Unreleased section"
}

validate_release_mode() {
  local repo_root="$1"
  local tag_repo_root="$2"
  local cargo_version="$3"
  local release_tag="$4"

  [[ -n "$release_tag" ]] || die "release mode requires --tag vX.Y.Z"
  is_stable_version "$cargo_version" || die "release mode requires a stable Cargo version, found $cargo_version"

  local expected_tag="v$cargo_version"
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
