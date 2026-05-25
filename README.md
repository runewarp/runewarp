<div align="center">
  <h1>
    Runewarp
  </h1>
</div>

Runewarp is a self-hostable ingress tunneling tool for private TLS passthrough by default, with optional Client-side TLS termination.

## Goals

- **TLS passthrough ingress tunneling** — Server routes traffic by SNI without terminating or inspecting TLS
- **Privacy-respecting by design** — the Server sees SNI and IPs, and customer plaintext reaches Runewarp only on the Client in opt-in terminate mode
- **Traverse NAT and firewalls** — Clients initiate outbound QUIC connections, so no port forwarding needed
- **Self-hostable and operator-controlled** — single Rust binary, Apache 2.0
- **Remain operationally simple** — TOML config, a handful of CLI subcommands, no runtime dependencies

## Non-goals

- **Server TLS termination** — Server never decrypts or re-encrypts Visitor traffic
- **HTTP-layer routing** — no path-based routing, header inspection, or Layer 7 awareness of any kind

## Install

Available from [crates.io](https://crates.io/crates/runewarp):
```bash
cargo install runewarp
```

Container image from [Docker Hub](https://hub.docker.com/r/runewarp/runewarp):
```bash
docker pull runewarp/runewarp
```

## Start here

1. Walkthrough of the Docker example with minimal config and XDG-backed defaults [`examples/docker/README.md`](examples/docker/README.md).
2. Read [`docs/usage.md`](docs/usage.md) for the operator workflow.
3. Read [`docs/configuration.md`](docs/configuration.md) for config keys and examples.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | Guide for installation, setup, startup, verification, and troubleshooting |
| [`docs/configuration.md`](docs/configuration.md) | Canonical configuration reference, defaults, and example configs |
| [`docs/architecture.md`](docs/architecture.md) | High-level design, routing model, trust boundaries, and topology diagrams |
| [`docs/security.md`](docs/security.md) | Visibility model, trust model, and security limits |
| [`docs/protocol.md`](docs/protocol.md) | Wire behavior and runtime invariants |
| [`docs/roadmap.md`](docs/roadmap.md) | Forward-looking roadmap and planned features |
| [`examples/docker/README.md`](examples/docker/README.md) | Walkthrough of the Docker example |

## License

Apache 2.0. See [`LICENSE`](LICENSE).
