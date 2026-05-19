#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
generated_dir="$example_dir/generated"
compose_file="$example_dir/docker-compose.yml"
caddy_root_ca="$generated_dir/caddy/root.crt"
caddy_container_root_ca="/data/caddy/pki/authorities/local/root.crt"

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

wait_for_caddy_root_ca() {
  local attempts="$1"
  local delay_seconds="$2"
  local attempt
  echo "Waiting for caddy root CA in container path $caddy_container_root_ca (max $attempts attempts)" >&2
  for (( attempt = 0; attempt < attempts; attempt += 1 )); do
    echo "Checking caddy container for root CA (attempt $((attempt+1))/$attempts)..." >&2
    if compose exec -T caddy sh -c "test -f '$caddy_container_root_ca'" >/dev/null 2>&1; then
      echo "Caddy root CA found in container; copying to host: $caddy_root_ca" >&2
      compose exec -T caddy sh -c "cat '$caddy_container_root_ca'" > "$caddy_root_ca"
      echo "Wrote $caddy_root_ca" >&2
      return 0
    fi
    sleep "$delay_seconds"
  done
  echo "Timed out waiting for caddy root CA in container; dumping caddy logs:" >&2
  compose logs --no-color caddy >&2 || true
  fail "timed out waiting for $caddy_container_root_ca in the caddy container"
}

assert_hostname_response() {
  local hostname="$1"
  local expected_body="$2"
  local response=""
  local attempt

  echo "Checking hostname ${hostname} over TLS; expected body: '${expected_body}'" >&2
  for (( attempt = 0; attempt < 30; attempt += 1 )); do
    echo "curl attempt $((attempt+1))/30 for ${hostname}..." >&2
    if response="$(
      curl \
        --silent \
        --show-error \
        --fail \
        --cacert "$caddy_root_ca" \
        --resolve "${hostname}:8443:127.0.0.1" \
        "https://${hostname}:8443/" 2>&1
    )"; then
      echo "curl succeeded; response: '${response}'" >&2
      if [[ "$response" == "$expected_body" ]]; then
        echo "Got expected response for ${hostname}" >&2
        return 0
      else
        echo "Unexpected body for ${hostname}: got '${response}' expected '${expected_body}'" >&2
        fail "expected ${hostname} to return '${expected_body}', got '${response}'"
      fi
    else
      echo "curl failed (attempt $((attempt+1))): ${response}" >&2
    fi
    sleep 2
  done

  echo "Timed out waiting for ${hostname} to respond; dumping docker compose logs:" >&2
  compose logs --no-color caddy server client >&2 || true
  fail "timed out waiting for ${hostname} to respond over TLS"
}

trap cleanup EXIT

cleanup
"$example_dir/prepare.sh" --reset
compose up -d
wait_for_caddy_root_ca 30 1
assert_hostname_response "app.example.test" "app.example.test via runewarp"
assert_hostname_response "api.example.test" "api.example.test via runewarp"
