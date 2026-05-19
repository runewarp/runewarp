#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
generated_dir="$example_dir/generated"
compose_file="$example_dir/docker-compose.yml"
caddy_root_ca="$generated_dir/caddy/data/caddy/pki/authorities/local/root.crt"

fail() {
  echo "$1" >&2
  exit 1
}

compose() {
  docker compose -f "$compose_file" "$@"
}

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}

wait_for_file() {
  local path="$1"
  local attempts="$2"
  local delay_seconds="$3"
  local attempt
  for (( attempt = 0; attempt < attempts; attempt += 1 )); do
    if [[ -f "$path" ]]; then
      return 0
    fi
    sleep "$delay_seconds"
  done
  fail "timed out waiting for $path"
}

assert_hostname_response() {
  local hostname="$1"
  local expected_body="$2"
  local response=""
  local attempt

  for (( attempt = 0; attempt < 30; attempt += 1 )); do
    if response="$(
      curl \
        --silent \
        --show-error \
        --fail \
        --cacert "$caddy_root_ca" \
        --resolve "${hostname}:8443:127.0.0.1" \
        "https://${hostname}:8443/"
    )"; then
      [[ "$response" == "$expected_body" ]] \
        || fail "expected ${hostname} to return '${expected_body}', got '${response}'"
      return 0
    fi
    sleep 2
  done

  fail "timed out waiting for ${hostname} to respond over TLS"
}

trap cleanup EXIT

cleanup
"$example_dir/prepare.sh" --reset
compose up -d
wait_for_file "$caddy_root_ca" 30 2
assert_hostname_response "app.example.test" "app.example.test via runewarp"
assert_hostname_response "api.example.test" "api.example.test via runewarp"
