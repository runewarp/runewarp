<div align="center">
  <h1>
    Runewarp
  </h1>
  <p>
    <strong>
      Public ingress. Private by design.
    </strong>
  </p>
</div>

Runewarp is an ingress tunneling tool for exposing local services without moving TLS termination to the edge. Clients connect out over QUIC, so you can publish services without putting your backend directly on the Internet or leaking your public IP.

## Goals

- **TLS passthrough ingress tunneling** — Server routes traffic by SNI without terminating or inspecting TLS
- **Privacy-respecting by design** — Server never sees HTTP headers or application plaintext
- **Traverse NAT and firewalls** — Client uses outbound QUIC, so no port forwarding or public IP is required
- **Self-hostable and operator-controlled** — single Rust binary for both Client and Server
- **Remain operationally simple** — TOML config, a handful of CLI commands, no runtime dependencies

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

## Getting started

1. Walkthrough of the Docker example with minimal config [`examples/docker/README.md`](examples/docker/README.md).
2. Read [`docs/usage.md`](docs/usage.md) for the operator workflow.
3. Read [`docs/configuration.md`](docs/configuration.md) for config keys and examples.

## Documentation

| Document | Purpose |
| --- | --- |
| [`docs/usage.md`](docs/usage.md) | Guide for installation, setup, startup, verification, and troubleshooting |
| [`docs/configuration.md`](docs/configuration.md) | Configuration reference, defaults, and example configs |
| [`docs/architecture.md`](docs/architecture.md) | High-level design, routing model, trust boundaries, and topology diagrams |
| [`docs/security.md`](docs/security.md) | Visibility model, trust model, and security limits |
| [`docs/protocol.md`](docs/protocol.md) | Wire behavior and runtime invariants |
| [`docs/roadmap.md`](docs/roadmap.md) | Forward-looking roadmap and planned features |
| [`examples/docker/README.md`](examples/docker/README.md) | Walkthrough of the Docker example |

## License

Licensed under Apache License, Version 2.0 ([`LICENSE`](LICENSE)).
