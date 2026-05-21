# Usage

This guide is the operator-facing path for installing Runewarp, preparing trust material, starting the runtime, and verifying traffic. Use [`docs/configuration.md`](configuration.md) when you need the full key reference or additional config shapes.

## Choose a path

| Path | Best for | Next step |
| --- | --- | --- |
| Released binary | Running Runewarp directly on your own hosts or service manager | Follow [Operate from the released binary](#operate-from-the-released-binary) |
| Docker example | Evaluating the shipped topology end to end before adapting it | Follow [Evaluate with the Docker example](#evaluate-with-the-docker-example) |

## Before you start

Runewarp assumes:

- a public **Server** reachable on `443/tcp` for **Visitor** TLS traffic and `443/udp` for **Client** tunnel connections
- one or more operator-owned **Public hostnames** that resolve to the Server
- a TLS-terminating **Local backend** behind the Client
- a decision about the Server certificate path: ACME for the **Server hostname** or the manual/private-CA path

If the product language in this guide feels unfamiliar, read [`CONTEXT.md`](../CONTEXT.md) first.

## Evaluate with the Docker example

The repository ships one concrete example under [`examples/docker/`](../examples/docker/) that demonstrates:

- one **Server**
- one **Client**
- one **Tunnel**
- a **Catch-all Service** that forwards both `app.example.test` and `api.example.test` to Caddy

Use it when you want to prove the end-to-end path before writing your own config.

```bash
git clone https://github.com/runewarp/runewarp.git
cd runewarp/examples/docker
./prepare.sh
docker compose up -d
./smoke.sh
```

Use [`examples/docker/README.md`](../examples/docker/README.md) for the full walkthrough, topology, and reset flow.

## Operate from the released binary

### 1. Install Runewarp

```bash
cargo install runewarp
```

Runewarp is one binary with role-specific subcommands:

```bash
runewarp server --help
runewarp client --help
```

### 2. Prepare the Server certificate path

Choose one of the two supported Server-certificate paths:

| Path | When to use it | What to do |
| --- | --- | --- |
| ACME | Publicly routable Server hostname and standard public trust | Create a writable ACME state directory and configure `[server.acme]` |
| Manual/private-CA | Private deployments or operator-managed trust | Create the material with `runewarp server cert init` and distribute `server-ca.crt` to Clients |

Manual/private-CA initialization:

```bash
runewarp server cert init \
  --directory /etc/runewarp/server \
  --hostname tunnel.example.com
```

### 3. Prepare the Client identity

Create the Client keypair, certificate, and durable `client-identity`:

```bash
runewarp client identity init --directory /etc/runewarp/client
```

Read the generated `/etc/runewarp/client/client-identity.txt` value and place it into the matching Server `[[server.tunnels]]` entry as `client-identity`.

### 4. Write config

The smallest practical setup is a Server with explicit **Public hostnames** and one Client **Catch-all Service**:

```toml
# /etc/runewarp/server.toml
[server]
hostname = "tunnel.example.com"

[server.acme]
email = "admin@example.com"
state-directory = "/var/lib/runewarp/acme"

[[server.tunnels]]
public-hostnames = ["app.example.com", "api.example.com"]
client-identity = "4f7b6f7a9b0f0d2b..."
```

```toml
# /etc/runewarp/client.toml
[client]
server-hostname = "tunnel.example.com"
identity-directory = "/etc/runewarp/client"
reconnect-interval = 5

[[client.services]]
backend-address = "caddy.local:443"
```

That Client has a **Catch-all Service**: the Server stays explicit about the authorized **Public hostnames**, while the sole Client **Service** forwards every admitted hostname to one TLS-terminating backend.

If you are using the manual/private-CA Server path, add:

```toml
server-ca-file = "/etc/runewarp/server-ca.crt"
```

See [`docs/configuration.md`](configuration.md) for exact-match Client routing, multi-Tunnel Server configs, multi-Service Client configs, and the complete key reference.

### 5. Start the runtime

```bash
runewarp server --config /etc/runewarp/server.toml
runewarp client --config /etc/runewarp/client.toml
```

Runewarp defaults to `./config.toml` when `--config` is omitted, but explicit paths are easier to operate and review.

### 6. Verify traffic

1. Point each **Public hostname** at the Server.
2. Make a TLS request to the Public hostname.
3. Confirm the backend answers with its own certificate and application response.

When logs are enabled, the Server and Client emit human-readable routing diagnostics that help confirm:

- which **Public hostname** was selected
- which **Tunnel** was chosen
- which **Service** accepted the stream on the Client

## Troubleshooting

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| No traffic reaches the backend | No active **Tunnel connection** | Confirm the Client is running and can reach the Server on `443/udp` |
| Client cannot connect to the Server | Wrong Server trust path | Check `client.server-ca-file` for the manual/private-CA path, or confirm the ACME/public-CA chain is trusted |
| Server drops a Public hostname | Hostname is not authorized on any Server `[[tunnels]]` entry | Check `server.tunnels[].public-hostnames` |
| Client rejects the stream | No matching **Service** on the Client | Check Client `public-hostnames`, or confirm the sole Service is intentionally Catch-all |
| Backend handshake fails | Backend is not terminating TLS | Confirm `backend-address` points at a TLS-speaking endpoint |
