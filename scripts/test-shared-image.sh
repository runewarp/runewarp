#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_tag="${RUNEWARP_IMAGE_TAG:-runewarp:test-shared-image-$$}"
mkdir -p "$repo_root/target"
work_dir="$(mktemp -d "$repo_root/target/shared-image-test.XXXXXX")"
server_container_id=""

cleanup() {
  if [[ -n "$server_container_id" ]]; then
    docker rm -f "$server_container_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$work_dir"
  docker image rm -f "$image_tag" >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker build --tag "$image_tag" "$repo_root"
chmod 0777 "$work_dir"
mkdir -p "$work_dir/server-cert" "$work_dir/client-identity"
chmod 0777 "$work_dir/server-cert" "$work_dir/client-identity"

image_user="$(docker image inspect "$image_tag" --format '{{.Config.User}}')"
if [[ -z "$image_user" || "$image_user" == "0" || "$image_user" == "root" ]]; then
  echo "expected shared image to use a non-root user, got '${image_user:-<empty>}'" >&2
  exit 1
fi

docker run --rm -v "$work_dir:/work" -w /work "$image_tag" \
  server cert init --directory server-cert --hostname tunnel.example.test >/dev/null
docker run --rm -v "$work_dir:/work" -w /work "$image_tag" \
  client identity init --directory client-identity >/dev/null

test -f "$work_dir/server-cert/server-ca.crt"
test -f "$work_dir/client-identity/client-identity.txt"

client_identity="$(tr -d '\r\n' < "$work_dir/client-identity/client-identity.txt")"
cat >"$work_dir/config.toml" <<EOF
[server]
hostname = "tunnel.example.test"

[server.cert]
directory = "server-cert"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "$client_identity"
EOF

server_container_id="$(docker run -d --cap-add=NET_BIND_SERVICE -v "$work_dir:/work" "$image_tag" server --config /work/config.toml)"
sleep 2
if [[ "$(docker inspect --format '{{.State.Running}}' "$server_container_id")" != "true" ]]; then
  docker logs "$server_container_id" >&2 || true
  echo "expected shared image server to stay up with CAP_NET_BIND_SERVICE" >&2
  exit 1
fi
