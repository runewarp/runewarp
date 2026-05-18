#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <platform> <output-dir>" >&2
  exit 1
fi

platform="$1"
output_dir="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -n1)"
commit="${RUNEWARP_GIT_COMMIT:-}"
if [[ -z "$commit" ]]; then
  commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
fi
platform_suffix="${platform//\//-}"
artifact_base="runewarp-v${version}-${commit}-${platform_suffix}"
artifact_path="$repo_root/$output_dir/${artifact_base}.oci.tar"

if ! docker buildx version >/dev/null 2>&1; then
  echo "docker buildx is required to export OCI image artifacts" >&2
  exit 1
fi

cd "$repo_root"
mkdir -p "$output_dir"

docker buildx build \
  --file "$repo_root/Dockerfile" \
  --platform "$platform" \
  --output "type=oci,dest=${artifact_path}" \
  --tag "runewarp:${artifact_base}" \
  "$repo_root"

printf '%s\n' "$artifact_path"
