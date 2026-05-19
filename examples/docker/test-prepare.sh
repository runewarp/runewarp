#!/usr/bin/env bash
set -euo pipefail

example_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
generated_dir="$example_dir/generated"

fail() {
  echo "$1" >&2
  exit 1
}

assert_exists() {
  local path="$1"
  [[ -e "$path" ]] || fail "expected $path to exist"
}

assert_contains() {
  local path="$1"
  local expected="$2"
  grep -Fq "$expected" "$path" || fail "expected $path to contain: $expected"
}

assert_file_equals() {
  local left="$1"
  local right="$2"
  cmp -s "$left" "$right" || fail "expected $left and $right to match"
}

"$example_dir/prepare.sh" --reset

top_level_dirs="$(find "$generated_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | tr '\n' ' ')"
[[ "$top_level_dirs" == "caddy client server " ]] \
  || fail "expected generated to contain only caddy, client, and server directories"

assert_exists "$generated_dir/server/config.toml"
assert_exists "$generated_dir/server/cert/server.crt"
assert_exists "$generated_dir/server/cert/server.key"
assert_exists "$generated_dir/server/cert/server-ca.crt"
assert_exists "$generated_dir/server/cert/state/server-ca.key"
assert_exists "$generated_dir/server/cert/state/server-hostname.txt"

assert_exists "$generated_dir/client/config.toml"
assert_exists "$generated_dir/client/identity/client.crt"
assert_exists "$generated_dir/client/identity/client.key"
assert_exists "$generated_dir/client/identity/client-identity.txt"
assert_exists "$generated_dir/client/trust/server-ca.crt"

assert_exists "$generated_dir/caddy/data"
assert_exists "$generated_dir/caddy/config"

client_identity="$(tr -d '[:space:]' < "$generated_dir/client/identity/client-identity.txt")"
assert_contains "$generated_dir/server/config.toml" 'hostname = "tunnel.example.test"'
assert_contains "$generated_dir/server/config.toml" 'directory = "/runewarp/cert"'
assert_contains "$generated_dir/server/config.toml" 'public-hostnames = ["app.example.test", "api.example.test"]'
assert_contains "$generated_dir/server/config.toml" "client-identity = \"$client_identity\""
assert_contains "$generated_dir/client/config.toml" 'server-hostname = "tunnel.example.test"'
assert_contains "$generated_dir/client/config.toml" 'identity-directory = "/runewarp/identity"'
assert_contains "$generated_dir/client/config.toml" 'server-ca-file = "/runewarp/trust/server-ca.crt"'
assert_contains "$generated_dir/client/config.toml" 'backend-address = "caddy:443"'
assert_file_equals \
  "$generated_dir/server/cert/server-ca.crt" \
  "$generated_dir/client/trust/server-ca.crt"

if grep -Fq "public-hostnames" "$generated_dir/client/config.toml"; then
  fail "expected generated client config to stay in catch-all mode"
fi

server_cert_before="$(shasum -a 256 "$generated_dir/server/cert/server.crt" | awk '{print $1}')"
client_identity_before="$(shasum -a 256 "$generated_dir/client/identity/client-identity.txt" | awk '{print $1}')"

"$example_dir/prepare.sh"

server_cert_after="$(shasum -a 256 "$generated_dir/server/cert/server.crt" | awk '{print $1}')"
client_identity_after="$(shasum -a 256 "$generated_dir/client/identity/client-identity.txt" | awk '{print $1}')"

[[ "$server_cert_before" == "$server_cert_after" ]] \
  || fail "expected prepare.sh to preserve server material by default"
[[ "$client_identity_before" == "$client_identity_after" ]] \
  || fail "expected prepare.sh to preserve client identity material by default"
