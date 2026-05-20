#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$example_dir/../.." && pwd)"

. "$repo_root/scripts/lib.sh"

generated_dir="$example_dir/generated"
compose_file="$example_dir/docker-compose.yml"
caddy_root_ca="$generated_dir/caddy/root.crt"
caddy_container_root_ca="/data/caddy/pki/authorities/local/root.crt"
stack_started=false

compose() {
  docker compose -f "$compose_file" "$@"
}

stop_stack() {
  compose down --volumes --remove-orphans --timeout 1 >/dev/null 2>&1 || true
}

require_compose() {
  docker compose version >/dev/null 2>&1 || die "docker compose is required"
}

cleanup() {
  if [[ "$stack_started" != true ]]; then
    return
  fi

  section "Stopping Docker example stack"
  stop_stack
  stack_started=false
  note "Docker example stack is down"
}

wait_for_caddy_root_ca() {
  local attempts="$1"
  local delay_seconds="$2"
  local attempt

  section "Waiting for Caddy root CA"

  for (( attempt = 1; attempt <= attempts; attempt += 1 )); do
    if compose exec -T caddy sh -c "test -f '$caddy_container_root_ca'" >/dev/null 2>&1; then
      compose exec -T caddy sh -c "cat '$caddy_container_root_ca'" > "$caddy_root_ca"
      note "Copied root CA to $caddy_root_ca"
      return 0
    fi

    if (( attempt < attempts )); then
      note "Root CA not ready yet; retrying ($attempt/$attempts)"
      sleep "$delay_seconds"
    fi
  done

  warn "Timed out waiting for the Caddy root CA; dumping caddy logs"
  compose logs --no-color caddy >&2 || true
  die "timed out waiting for $caddy_container_root_ca in the caddy container"
}

assert_hostname_response() {
  local hostname="$1"
  local expected_body="$2"
  local response=""
  local attempt

  section "Verifying $hostname"

  for (( attempt = 1; attempt <= 30; attempt += 1 )); do
    if response="$(
      curl \
        --silent \
        --show-error \
        --fail \
        --cacert "$caddy_root_ca" \
        --resolve "${hostname}:8443:127.0.0.1" \
        "https://${hostname}:8443/" 2>&1
    )"; then
      if [[ "$response" == "$expected_body" ]]; then
        note "Received the expected response"
        return 0
      fi

      die "expected ${hostname} to return '${expected_body}', got '${response}'"
    fi

    if (( attempt < 30 )); then
      note "Request failed; retrying ($attempt/30): ${response}"
      sleep 2
    fi
  done

  warn "Timed out waiting for ${hostname}; dumping docker compose logs"
  compose logs --no-color caddy server client >&2 || true
  die "timed out waiting for ${hostname} to respond over TLS"
}

reset_stack() {
  section "Resetting Docker example stack"
  stop_stack
}

main() {
  trap cleanup EXIT
  require_command docker
  require_compose
  require_command curl

  reset_stack
  "$example_dir/prepare.sh" --reset

  section "Starting Docker example stack"
  compose up -d >/dev/null
  stack_started=true

  wait_for_caddy_root_ca 30 1
  assert_hostname_response "app.example.test" "app.example.test via runewarp"
  assert_hostname_response "api.example.test" "api.example.test via runewarp"

  cleanup
  trap - EXIT

  success "Smoke test passed"
  note "Both public hostnames responded over TLS"
}

main "$@"
