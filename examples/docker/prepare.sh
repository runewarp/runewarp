#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$example_dir/../.." && pwd)"

. "$repo_root/scripts/lib.sh"

generated_dir="$example_dir/generated"
server_service_dir="$generated_dir/server"
server_source_dir="$server_service_dir/cert-source"
server_state_dir="$server_source_dir/state"
server_runtime_dir="$server_service_dir/cert"
server_config_path="$server_service_dir/config.toml"
client_service_dir="$generated_dir/client"
client_source_dir="$client_service_dir/identity-source"
client_runtime_dir="$client_service_dir/identity"
client_trust_dir="$client_service_dir/trust"
client_config_path="$client_service_dir/config.toml"
caddy_service_dir="$generated_dir/caddy"
caddy_data_dir="$caddy_service_dir/data"
caddy_config_dir="$caddy_service_dir/config"
server_template="$example_dir/server/config.toml.template"
client_template="$example_dir/client/config.toml.template"
image_tag="runewarp/runewarp:local"
reset_requested=false
server_source_files=(
  "server.crt"
  "server.key"
  "server-ca.crt"
  "state/server-ca.key"
  "state/server-hostname.txt"
)
client_source_files=(
  "client.crt"
  "client.key"
  "client-identity.txt"
)

usage() {
  usage_error "$(basename "$0") [--reset]"
}

parse_args() {
  if (( $# > 1 )); then
    usage
  fi

  case "${1-}" in
    "")
      ;;
    --reset)
      reset_requested=true
      ;;
    *)
      usage
      ;;
  esac
}

all_files_exist() {
  local base_dir="$1"
  local relative_path

  shift
  for relative_path in "$@"; do
    [[ -f "$base_dir/$relative_path" ]] || return 1
  done
}

any_file_exists() {
  local base_dir="$1"
  local relative_path

  shift
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
    die "found incomplete $label in $base_dir; rerun $(basename "$0") --reset to rebuild it cleanly"
  fi
}

prepare_directories() {
  mkdir -p \
    "$server_service_dir" \
    "$server_source_dir" \
    "$server_state_dir" \
    "$server_runtime_dir" \
    "$client_service_dir" \
    "$client_source_dir" \
    "$client_runtime_dir" \
    "$client_trust_dir" \
    "$caddy_data_dir" \
    "$caddy_config_dir"
}

build_image() {
  section "Building local Runewarp image"

  docker build \
    --file "$repo_root/Dockerfile" \
    --tag "$image_tag" \
    "$repo_root"
}

run_runewarp() {
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "$example_dir:/workspace" \
    "$image_tag" \
    "$@"
}

render_server_config() {
  local client_identity

  client_identity="$(tr -d '[:space:]' < "$client_source_dir/client-identity.txt")"
  sed "s/__CLIENT_IDENTITY__/$client_identity/g" \
    "$server_template" > "$server_config_path"
}

render_client_config() {
  cp "$client_template" "$client_config_path"
}

install_readonly_copy() {
  local source_path="$1"
  local destination_path="$2"

  install -m 0444 "$source_path" "$destination_path"
}

render_server_runtime_material() {
  install_readonly_copy "$server_source_dir/server.crt" "$server_runtime_dir/server.crt"
  install_readonly_copy "$server_source_dir/server.key" "$server_runtime_dir/server.key"
  install_readonly_copy "$server_source_dir/server-ca.crt" "$server_runtime_dir/server-ca.crt"
}

render_client_runtime_material() {
  install_readonly_copy "$client_source_dir/client.crt" "$client_runtime_dir/client.crt"
  install_readonly_copy "$client_source_dir/client.key" "$client_runtime_dir/client.key"
  install_readonly_copy "$client_source_dir/client-identity.txt" "$client_runtime_dir/client-identity.txt"
}

render_client_trust_bundle() {
  install_readonly_copy "$server_source_dir/server-ca.crt" "$client_trust_dir/server-ca.crt"
}

reset_generated_state() {
  section "Resetting generated Docker example state"
  note "Removing generated state"
  rm -rf "$generated_dir"
  rm -f "$example_dir/.env"
}

prepare_server_certificate_material() {
  section "Preparing server certificate material"

  if ! all_files_exist "$server_source_dir" "${server_source_files[@]}"; then
    note "Generating certificate material for tunnel.example.test"
    run_runewarp \
      server cert init \
      --dir /workspace/generated/server/cert-source \
      --hostname tunnel.example.test
    return
  fi

  note "Reusing existing server certificate material"
}

prepare_client_identity_material() {
  section "Preparing client identity material"

  if ! all_files_exist "$client_source_dir" "${client_source_files[@]}"; then
    note "Generating client identity material"
    run_runewarp \
      client identity init \
      --dir /workspace/generated/client/identity-source
    return
  fi

  note "Reusing existing client identity material"
}

render_runtime_configuration() {
  section "Rendering Docker example configuration"
  render_server_runtime_material
  render_client_runtime_material
  render_client_trust_bundle
  render_server_config
  render_client_config
}

main() {
  parse_args "$@"
  require_command docker

  if [[ "$reset_requested" == true ]]; then
    reset_generated_state
  fi

  section "Preparing Docker example state"
  prepare_directories

  assert_complete_or_empty "server certificate material" "$server_source_dir" "${server_source_files[@]}"
  assert_complete_or_empty "client identity material" "$client_source_dir" "${client_source_files[@]}"

  build_image
  prepare_server_certificate_material
  prepare_client_identity_material
  render_runtime_configuration

  success "Docker example is ready"
  note "Generated state: $generated_dir"
  note "Source material: generated/server/cert-source and generated/client/identity-source"
}

main "$@"
