#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose_file="$example_dir/compose.yaml"
material_dir="$example_dir/material"
project_name="${RUNEWARP_EXAMPLE_PROJECT:-runewarp-preview}"
public_port="${RUNEWARP_PUBLIC_PORT:-8443}"
ca_file="$material_dir/caddy-data/caddy/pki/authorities/local/root.crt"

export RUNEWARP_UID="${RUNEWARP_UID:-$(id -u)}"
export RUNEWARP_GID="${RUNEWARP_GID:-$(id -g)}"
export RUNEWARP_PUBLIC_PORT="$public_port"

cleanup() {
  docker compose -f "$compose_file" -p "$project_name" down --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT

reset_material_dir() {
  local dir="$1"
  mkdir -p "$dir"
  find "$dir" -mindepth 1 ! -name '.gitignore' -exec rm -rf {} +
}

reset_material_dir "$material_dir/server-cert"
reset_material_dir "$material_dir/client-identity"
reset_material_dir "$material_dir/caddy-data"
reset_material_dir "$material_dir/caddy-config"

docker compose -f "$compose_file" -p "$project_name" up -d --build

for _ in $(seq 1 30); do
  if [[ -f "$ca_file" ]]; then
    break
  fi
  sleep 1
done

if [[ ! -f "$ca_file" ]]; then
  echo "expected Caddy to write an internal CA root at $ca_file" >&2
  exit 1
fi

check_response() {
  local hostname="$1"
  local expected="$2"
  local url="https://${hostname}:${public_port}/"
  local response=""

  for _ in $(seq 1 30); do
    if response="$(
      curl --silent --show-error --fail \
        --cacert "$ca_file" \
        --resolve "${hostname}:${public_port}:127.0.0.1" \
        "$url"
    )"; then
      if [[ "$response" == "$expected" ]]; then
        return 0
      fi
    fi
    sleep 1
  done

  echo "unexpected response for $hostname: ${response:-<none>}" >&2
  exit 1
}

check_response "hello.preview.test" "hello from hello.preview.test"
check_response "goodbye.preview.test" "goodbye from goodbye.preview.test"

test -f "$material_dir/server-cert/server-ca.crt"
test -f "$material_dir/client-identity/client-identity.txt"
