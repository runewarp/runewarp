#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
generated_dir="$script_dir/generated"
server_dir="$generated_dir/server-cert"
server_state_dir="$server_dir/state"
client_dir="$generated_dir/client-identity"
config_dir="$generated_dir/config"
client_trust_dir="$generated_dir/server-ca"
caddy_data_dir="$generated_dir/caddy/data"
caddy_config_dir="$generated_dir/caddy/config"
server_template="$script_dir/server-config.toml.template"
client_template="$script_dir/client-config.toml.template"
image_tag="runewarp-example:local"

usage() {
  echo "usage: $0 [--reset]" >&2
  exit 1
}

fail() {
  echo "$1" >&2
  exit 1
}

if [[ $# -gt 1 ]]; then
  usage
fi

reset_requested=false
if [[ $# -eq 1 ]]; then
  case "$1" in
    --reset)
      reset_requested=true
      ;;
    *)
      usage
      ;;
  esac
fi

server_files=(
  "server.crt"
  "server.key"
  "server-ca.crt"
  "state/server-ca.key"
  "state/server-hostname.txt"
)
client_files=(
  "client.crt"
  "client.key"
  "client-identity.txt"
)

all_files_exist() {
  local base_dir="$1"
  shift
  local relative_path
  for relative_path in "$@"; do
    [[ -f "$base_dir/$relative_path" ]] || return 1
  done
}

any_file_exists() {
  local base_dir="$1"
  shift
  local relative_path
  for relative_path in "$@"; do
    if [[ -e "$base_dir/$relative_path" ]]; then
      return 0
    fi
  done
  return 1
}

assert_complete_or_empty() {
  local label="$1"
  local base_dir="$2"
  shift 2
  if all_files_exist "$base_dir" "$@"; then
    return 0
  fi
  if any_file_exists "$base_dir" "$@"; then
    fail "found incomplete $label in $base_dir; rerun $0 --reset to rebuild it cleanly"
  fi
}

prepare_directories() {
  mkdir -p \
    "$server_state_dir" \
    "$client_dir" \
    "$config_dir" \
    "$client_trust_dir" \
    "$caddy_data_dir" \
    "$caddy_config_dir"
}

allow_container_writes() {
  chmod 0777 "$server_dir" "$server_state_dir" "$client_dir"
}

lock_directories() {
  chmod 0755 "$server_dir" "$server_state_dir" "$client_dir"
}

build_image() {
  docker build --tag "$image_tag" "$repo_root"
}

run_runewarp() {
  docker run --rm \
    --volume "$script_dir:/workspace" \
    "$image_tag" \
    "$@"
}

render_server_config() {
  local client_identity
  client_identity="$(tr -d '[:space:]' < "$client_dir/client-identity.txt")"
  sed "s/__CLIENT_IDENTITY__/$client_identity/g" \
    "$server_template" > "$config_dir/server.toml"
}

render_client_config() {
  cp "$client_template" "$config_dir/client.toml"
}

render_client_trust_bundle() {
  cp "$server_dir/server-ca.crt" "$client_trust_dir/server-ca.crt"
}

if $reset_requested; then
  rm -rf "$generated_dir"
fi

prepare_directories
assert_complete_or_empty "server certificate material" "$server_dir" "${server_files[@]}"
assert_complete_or_empty "client identity material" "$client_dir" "${client_files[@]}"

build_image
allow_container_writes
trap lock_directories EXIT

if ! all_files_exist "$server_dir" "${server_files[@]}"; then
  run_runewarp \
    server cert init \
    --directory /workspace/generated/server-cert \
    --hostname tunnel.example.test
fi

if ! all_files_exist "$client_dir" "${client_files[@]}"; then
  run_runewarp \
    client identity init \
    --directory /workspace/generated/client-identity
fi

render_client_trust_bundle
render_server_config
render_client_config
