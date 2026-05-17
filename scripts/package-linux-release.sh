#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <target-triple> <output-dir>" >&2
  exit 1
fi

target="$1"
output_dir="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -n1)"
commit="${RUNEWARP_GIT_COMMIT:-}"
if [[ -z "$commit" ]]; then
  commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
fi
cargo_bin="$(command -v cargo || true)"
if [[ -z "$cargo_bin" && -x /usr/local/cargo/bin/cargo ]]; then
  cargo_bin="/usr/local/cargo/bin/cargo"
fi
if [[ -z "$cargo_bin" ]]; then
  echo "cargo not found" >&2
  exit 1
fi
rustup_bin="$(command -v rustup || true)"
if [[ -z "$rustup_bin" && -x /usr/local/cargo/bin/rustup ]]; then
  rustup_bin="/usr/local/cargo/bin/rustup"
fi
artifact_base="runewarp-v${version}-${commit}-${target}"
archive_path="$repo_root/$output_dir/${artifact_base}.tar.gz"
checksum_path="${archive_path}.sha256"
staging_dir="$(mktemp -d "$repo_root/target/package-${target}.XXXXXX")"

cleanup() {
  rm -rf "$staging_dir"
}

trap cleanup EXIT

cd "$repo_root"
mkdir -p "$output_dir"

if [[ -n "$rustup_bin" ]]; then
  "$rustup_bin" target add "$target" >/dev/null
fi

"$cargo_bin" build --release --locked --bin runewarp --target "$target"
install -m 0755 "target/${target}/release/runewarp" "$staging_dir/runewarp"
tar -C "$staging_dir" -czf "$archive_path" runewarp

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$archive_path" > "$checksum_path"
else
  sha256sum "$archive_path" > "$checksum_path"
fi

printf '%s\n' "$archive_path"
