#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

main() {
  local platform output_dir version commit platform_suffix artifact_base artifact_path

  case $# in
    2)
      ;;
    *)
      usage_error "$(basename "$0") <platform> <output-dir>"
      ;;
  esac

  platform="$1"
  output_dir="$2"
  version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -n1)"
  commit="${RUNEWARP_GIT_COMMIT:-}"
  if [[ -z "$commit" ]]; then
    commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
  fi
  platform_suffix="${platform//\//-}"
  artifact_base="runewarp-v${version}-${commit}-${platform_suffix}"
  artifact_path="$repo_root/$output_dir/${artifact_base}.oci.tar"

  require_command docker
  if ! docker buildx version >/dev/null 2>&1; then
    die "docker buildx is required to export OCI image artifacts"
  fi

  cd "$repo_root"
  mkdir -p "$output_dir"

  section "Exporting OCI image"
  note "Platform: $platform"
  note "Destination: $artifact_path"

  docker buildx build \
    --file "$repo_root/Dockerfile" \
    --platform "$platform" \
    --output "type=oci,dest=${artifact_path}" \
    --tag "runewarp:${artifact_base}" \
    "$repo_root"

  success "OCI image exported"
  note "Artifact ready at $artifact_path"
  printf '%s\n' "$artifact_path"
}

main "$@"
