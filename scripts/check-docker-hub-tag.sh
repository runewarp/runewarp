#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"
. "$script_dir/lib-docker-hub.sh"

usage() {
  usage_error "check-docker-hub-tag.sh --image-ref docker.io/<namespace>/<repository>:<tag>"
}

main() {
  local image_ref=""
  local github_output="${GITHUB_OUTPUT:-}"
  local http_status exists

  while (($#)); do
    case "$1" in
      --image-ref)
        [[ $# -ge 2 ]] || usage
        image_ref="$2"
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done

  [[ -n "$image_ref" ]] || die "--image-ref is required"

  http_status="$(runewarp_docker_hub_tag_status_from_image_ref "$image_ref")" ||
    die "failed to query Docker Hub tag metadata for $image_ref"

  case "$http_status" in
    200) exists="true" ;;
    404) exists="false" ;;
    *) die "unexpected Docker Hub tag lookup status for $image_ref: $http_status" ;;
  esac

  printf 'exists=%s\n' "$exists"

  if [[ -n "$github_output" ]]; then
    printf 'exists=%s\n' "$exists" >> "$github_output"
  fi
}

main "$@"
