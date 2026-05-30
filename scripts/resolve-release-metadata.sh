#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"
. "$script_dir/lib-release-metadata.sh"

usage() {
  usage_error "resolve-release-metadata.sh"
}

main() {
  local event_name="${EVENT_NAME:-}"
  local push_tag="${PUSH_TAG:-}"
  local workflow_mode_input="${WORKFLOW_MODE:-}"
  local workflow_tag="${WORKFLOW_TAG:-}"
  local image_repository="${IMAGE_REPOSITORY:-}"
  local github_env="${GITHUB_ENV:-}"
  local github_output="${GITHUB_OUTPUT:-}"
  local resolved_metadata docker_tags workflow_mode release_tag release_version release_source_ref primary_image_ref

  [[ -n "$event_name" ]] || die "EVENT_NAME is required"
  [[ -n "$image_repository" ]] || die "IMAGE_REPOSITORY is required"
  [[ -n "$github_env" ]] || die "GITHUB_ENV is required"
  [[ -n "$github_output" ]] || die "GITHUB_OUTPUT is required"

  resolved_metadata="$(
    runewarp_release_metadata_resolve \
      "$event_name" \
      "$push_tag" \
      "$workflow_mode_input" \
      "$workflow_tag" \
      "$image_repository"
  )" || die "stable release tag is required"

  while IFS='=' read -r key value; do
    case "$key" in
      workflow_mode) workflow_mode="$value" ;;
      release_tag) release_tag="$value" ;;
      release_version) release_version="$value" ;;
      release_source_ref) release_source_ref="$value" ;;
      primary_image_ref) primary_image_ref="$value" ;;
    esac
  done <<< "$resolved_metadata"

  docker_tags="$(runewarp_release_metadata_print_docker_tags "$image_repository" "$release_version")"

  {
    printf 'WORKFLOW_MODE=%s\n' "$workflow_mode"
    printf 'RELEASE_TAG=%s\n' "$release_tag"
    printf 'RELEASE_VERSION=%s\n' "$release_version"
    printf 'RELEASE_SOURCE_REF=%s\n' "$release_source_ref"
    printf 'IMAGE_REPOSITORY=%s\n' "$image_repository"
    printf 'PRIMARY_IMAGE_REF=%s\n' "$primary_image_ref"
    printf 'DOCKER_TAGS<<EOF\n%s\nEOF\n' "$docker_tags"
  } >> "$github_env"

  {
    printf '%s\n' "$resolved_metadata"
    printf 'docker_tags<<EOF\n%s\nEOF\n' "$docker_tags"
  } >> "$github_output"
}

main "$@"
