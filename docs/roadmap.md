# Roadmap

Runewarp is being built as a self-hosted TLS passthrough tunnel first. This is the only document that uses MVP terminology directly; other docs describe the full intended design and call out future work where needed.

## Current state

- the docs are ahead of the code
- the implementation is still minimal
- self-hosting is the priority

## Phase 1 - MVP data path

Goal: prove the tunnel works end to end.

Scope:

- one public server
- one client
- one catch-all tunnel on the server
- one catch-all service on the client
- public TLS passthrough on `443/tcp`
- client QUIC tunnel on `443/udp`
- no multi-hostname routing yet

## Phase 2 - MVP config and authentication

Goal: make the single-tunnel design usable by operators.

Scope:

- TOML config loading
- boot-time config validation
- `runewarp server`, `runewarp client`, and `runewarp keygen`
- pinned client public-key fingerprints
- client certificate auto-renewal with stable keys
- manual server certs and ACME TLS-ALPN-01
- human-readable logs

## Phase 3 - Multi-hostname routing

Goal: move beyond the catch-all form.

Scope:

- multiple server tunnel entries
- multiple client service entries
- exact-match hostname routing
- stronger hostname overlap validation
- clearer operator docs and DNS examples

## Phase 4 - Tunnel pools and balancing

Goal: scale one routed hostname set across multiple clients.

Scope:

- least-active balancing
- round-robin tie-breaking
- same-fingerprint client pools
- later in this phase: multiple fingerprints per tunnel entry
- clearer handling for misconfigured replicas

## Phase 5 - Packaging and release engineering

Goal: make Runewarp easy to ship and run.

Scope:

- unit, integration, and end-to-end tests
- Clippy, fmt, docs, and audit checks in CI
- release binaries
- Docker Hub and GHCR images
- minimal container images, ideally distroless and non-root where practical

## Phase 6 - Protocol growth

Goal: expand the data plane without changing the core model.

Scope:

- public QUIC and HTTP/3 on `443/udp`
- wildcard hostnames
- HTTP/3-based remote configuration instead of a custom control protocol
- structured JSON logging
- IPv6 support

## Phase 7 - Advanced operations

Goal: support larger and more dynamic deployments.

Scope:

- live config reload without dropping active connections
- backend health-aware routing
- metrics for Prometheus and StatsD
- configurable public and tunnel ports
- eventual per-hostname public port support
- downstream connection reuse or pooling where it proves worthwhile

## Phase 8 - Advanced network features

Goal: handle more demanding edge and privacy requirements.

Scope:

- ECH for public and client connections
- clustered multi-node mode
- better key-rotation workflows
- deeper HTTP/3 and QUIC passthrough work

## Testing priorities

- unit tests for ClientHello parsing, config validation, auth, and stream accounting
- integration tests for routing, reconnects, and tunnel pools
- end-to-end tests with a local TLS terminator behind the client
- benchmarks for parsing, forwarding, and allocation-sensitive paths
- stronger property testing and fuzzing for security-critical code

## Dependency guide

Core crates for the current design:

- `tokio`
- `quinn`
- `rustls`
- `instant-acme`

Module layout can change. The important thing is keeping the data path simple, fast, and well-tested.

## Open questions worth tracking

- how public QUIC passthrough should coexist with client tunnels on `443/udp`
- how clustered mode should route requests to the correct tunnel without centralizing the data path
- whether downstream connection reuse materially improves performance without hurting correctness
