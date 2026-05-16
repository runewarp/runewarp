# Roadmap

Runewarp is being built as a self-hosted TLS passthrough tunnel. The core docs describe the committed baseline; this document owns sequencing and longer-range expansion.

## Current state

- the phase-1 data path is implemented as a library-first `Server` and `Client` runtime
- the current phase-2 Catch-all operator surface is implemented with `runewarp keygen`, flat cert/key config, and additive `server-ca-file`
- the agreed next phase-2 surface replaces that with `runewarp server cert ...`, `runewarp client identity ...`, directory-based material, and tighter trust semantics
- the current implementation uses a Catch-all Tunnel, a Catch-all Service, and one active Client instance with one Tunnel connection

## Phase 1 - Library data path

Goal: prove the tunnel works end to end.

Status: implemented as the core library runtime and end-to-end test path.

Scope:

- one public Server
- one Client instance
- one Catch-all Tunnel on the Server
- one Catch-all Service on the Client
- public TLS passthrough on `443/tcp`
- Client QUIC tunnel on `443/udp`

## Phase 2 - Operator runtime and Client authentication

Goal: make the single-Tunnel design usable by operators.

Status: config loading, `runewarp server`, `runewarp client`, and the older `runewarp keygen` surface are implemented for the Catch-all manual-TLS path. The corrected phase-2 follow-up still needs the role-first `server cert` / `client identity` operator surface, directory-based material, tighter Client trust semantics, Client-identity enforcement, certificate renewal, and ACME.

Scope:

- TOML config loading
- boot-time config validation
- `runewarp server`, `runewarp client`, `runewarp server cert ...`, and `runewarp client identity ...`
- directory-based Server cert and Client identity material
- one shared `client-identity` per Tunnel
- exclusive Client trust of a configured manual Server CA file
- Client certificate auto-renewal with stable keys and explicit identity rotation
- manual/private-CA Server certs with explicit `renew` and `rotate-ca`
- ACME TLS-ALPN-01 for the Server hostname
- human-readable logs

## Phase 3 - Exact-match hostname routing

Goal: move beyond Catch-all mode without changing the transparent data path.

Scope:

- multiple Server Tunnels
- multiple Client Services
- exact-match Public hostname routing
- clearer Hostname mirroring guidance
- stronger intra-side hostname validation

## Phase 4 - Multi-instance tunnels and availability

Goal: in a much later phase, scale one routed hostname set across multiple Client instances.

Scope:

- multiple Client instances per Tunnel
- Tunnel pools with least-active balancing
- round-robin tie-breaking
- one shared `client-identity` per Tunnel by default, with separate identities as a later advanced case
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

Goal: expand the data plane without changing the product boundary.

Scope:

- public QUIC and HTTP/3 on `443/udp`
- wildcard Public hostnames
- HTTP/3-based remote configuration instead of a custom control protocol
- structured JSON logging
- IPv6 support

## Phase 7 - Operations and safety

Goal: support larger and more dynamic deployments.

Scope:

- live config reload without dropping active connections
- backend health-aware routing
- metrics for Prometheus and StatsD
- configurable public and tunnel ports
- lint and doctor tooling for Hostname mirroring drift
- eventual per-hostname public port support

## Phase 8 - Advanced network features

Goal: handle more demanding edge and privacy requirements.

Scope:

- ECH for public and Client connections
- clustered multi-node mode
- zero-downtime identity and CA rotation workflows
- deeper HTTP/3 and QUIC passthrough work

## Deliberate non-goals

- edge TLS termination for customer traffic
- plain HTTP backend support

## Testing priorities

- unit tests for ClientHello parsing, config validation, auth, and stream accounting
- integration tests for routing, reconnects, and multi-instance Tunnel pools
- end-to-end tests with a local TLS terminator behind the Client
- benchmarks for parsing, forwarding, and allocation-sensitive paths
- stronger property testing and fuzzing for security-critical code

## Open questions worth tracking

- how public QUIC passthrough should coexist with Client tunnels on `443/udp`
- how clustered mode should route requests to the correct Tunnel without centralizing the data path
- whether the Server should keep one coordinating accept loop or move to a clearer supervision model as the runtime grows
- whether Server-side Tunnel selection and Client-side Service selection should eventually share a routing abstraction once exact-match routing is real on both sides
- whether downstream connection reuse materially improves performance without hurting correctness
