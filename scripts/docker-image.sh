#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

usage() {
  usage_error "$(basename "$0") <platform> <output-dir>"
}

main() {
  local platform output_dir artifact_dir version commit platform_suffix artifact_name artifact_path

  if [[ $# -ne 2 ]]; then
    usage
  fi

  platform="$1"
  output_dir="$2"
  artifact_dir="$repo_root/$output_dir"
  version="$(runewarp_version "$repo_root")"
  [[ -n "$version" ]] || die "failed to read version from Cargo.toml"
  commit="$(runewarp_git_commit "$repo_root")"
  [[ -n "$commit" ]] || die "failed to resolve git commit"
  platform_suffix="${platform//\//-}"
  artifact_name="runewarp-v${version}-${commit}-${platform_suffix}"
  artifact_path="$artifact_dir/${artifact_name}.oci.tar"

  require_command docker
  if ! docker buildx version >/dev/null 2>&1; then
    die "docker buildx is required to export OCI image artifacts"
  fi

  mkdir -p "$artifact_dir"

  section "Exporting OCI image"
  note "Platform: $platform"
  note "Destination: $artifact_path"

  docker buildx build \
    --file "$repo_root/Dockerfile" \
    --platform "$platform" \
    --output "type=oci,dest=${artifact_path}" \
    --tag "runewarp:${artifact_name}" \
    "$repo_root"

  success "OCI image exported"
  note "Artifact ready at $artifact_path"
  printf '%s\n' "$artifact_path"
}

main "$@"
