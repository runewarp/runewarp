#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
default_target="$(docker run --rm rust:1.88-bookworm rustc -vV | sed -n 's/^host: //p')"
target="${1:-$default_target}"
output_dir="target/package-test-artifacts"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -n1)"
commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
archive="$repo_root/${output_dir}/runewarp-v${version}-${commit}-${target}.tar.gz"
checksum="${archive}.sha256"

rm -rf "$repo_root/$output_dir"

docker run --rm \
  -e "RUNEWARP_GIT_COMMIT=$commit" \
  -v "$repo_root:/repo" \
  -w /repo \
  rust:1.88-bookworm \
  sh -lc "./scripts/package-linux-release.sh '$target' '$output_dir'"

test -f "$archive"
test -f "$checksum"
tar -tzf "$archive" | grep -Fx "runewarp" >/dev/null
grep -F "$(basename "$archive")" "$checksum" >/dev/null
