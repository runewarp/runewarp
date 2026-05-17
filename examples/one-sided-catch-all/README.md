# One-sided Catch-all preview example

This example runs the approved phase-4 preview topology:

- Server hostname: `tunnel.preview.test`
- Public hostnames: `hello.preview.test` and `goodbye.preview.test`
- one Client instance with one Catch-all Service
- one Caddy Local backend that terminates real TLS and returns distinct responses per Public hostname
- one-shot init services that generate Server and Client material into example-local bind mounts

Generated material lives under `examples/one-sided-catch-all/material/`.

## Run the stack

```bash
export RUNEWARP_UID="$(id -u)"
export RUNEWARP_GID="$(id -g)"
docker compose -f examples/one-sided-catch-all/compose.yaml up --build
```

The stack exposes Visitor TLS on `127.0.0.1:${RUNEWARP_PUBLIC_PORT:-8443}`. The Client reaches the Server over the internal Compose network using the Server hostname alias `tunnel.preview.test`.

## Smoke-test the example

```bash
./examples/one-sided-catch-all/smoke.sh
```

That script rebuilds the stack, waits for Caddy's internal CA root, and verifies both Public hostnames over TLS without insecure verification bypasses.

## Inspect generated material

- Server material: `examples/one-sided-catch-all/material/server-cert/`
- Client material: `examples/one-sided-catch-all/material/client-identity/`
- Caddy internal CA and state: `examples/one-sided-catch-all/material/caddy-data/`

If you want a fresh bootstrap, stop the stack and delete the generated contents under `material/` before running `docker compose up` again.
