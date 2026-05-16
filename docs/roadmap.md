# Roadmap

Runewarp is being built as a self-hosted TLS passthrough tunnel. The core docs describe the committed baseline; this document owns sequencing and longer-range expansion.

## Current state

- the phase-1 data path is implemented as a library-first `Server` and `Client` runtime
- the current phase-2 legacy Catch-all operator surface is implemented with `runewarp keygen`, flat cert/key config, and additive `server-ca-file`
- the agreed next phase-2 surface replaces that with `runewarp server cert ...`, `runewarp client identity ...`, directory-based material, and tighter trust semantics
- the current implementation still uses a legacy Server Catch-all Tunnel, a Client Catch-all Service, and one active Client instance with one Tunnel connection
- the committed phase-3 model removes Server Catch-all: every Server Tunnel must list explicit `public-hostnames`, while the Client either uses explicit `public-hostnames` too or one Catch-all Service

## Phase 1 - Library data path

Goal: prove the tunnel works end to end.

Status: implemented as the core library runtime and end-to-end test path.

Scope:

- one public Server
- one Client instance
- one Server Tunnel
- one Client Service
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

Goal: make Server-side Public hostname authorization explicit while adding Client-side routing flexibility without changing the transparent data path.

Scope:

- required `server.tunnels[].public-hostnames`; Server Catch-all is removed from the intended model
- multiple Server Tunnels
- multiple Client instances, with one Client instance per Tunnel
- one active Tunnel connection per Tunnel, with per-Tunnel isolation and latest-wins replacement
- multiple Client Services
- exact-match Public hostname routing on the Server
- explicit Client exact-match Services and Client Catch-all as the two valid client-side routing shapes
- `Hostname mirroring` for both-sides explicit configs and `One-sided Catch-all` for Server exact-match plus Client Catch-all
- no runtime cross-side hostname validation; mirrored coverage remains an operator responsibility
- stronger hostname validation and normalization, including duplicate rejection, wildcard rejection, required server hostnames, and explicit single-entry exact-match
- fail-closed routing when no authorized or connected Tunnel or Service is available
- per-role `logs` booleans controlling human-readable routing diagnostics

## Phase 4 - Packaging and release engineering

Goal: make Runewarp easy to evaluate, ship, and run as an operator-focused technical preview.

Scope:

- customer/operator-facing documentation uplift
- a rewritten README focused on operator outcomes and product boundaries instead of project status
- `docs/usage.md`
- common usage examples, including Docker Compose and Caddy
- changelog
- Clippy, fmt, docs, tests, and release-path checks in CI
- crates.io release
- release binaries
- Docker Hub and GHCR images
- minimal container images, ideally distroless and non-root where practical

## Phase 5 - Multi-instance tunnels and availability

Goal: scale one routed hostname set across multiple Client instances of the same Tunnel.

Scope:

- multiple Client instances per single Tunnel
- Tunnel pools with least-active balancing
- round-robin tie-breaking
- one shared `client-identity` per Tunnel by default, with separate identities as a later advanced case
- clearer handling for misconfigured replicas


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

- unit tests for ClientHello parsing, config validation, hostname normalization, auth, and stream accounting
- integration tests for exact-match routing, per-Tunnel isolation, reconnects, and later multi-instance Tunnel pools
- end-to-end tests with a local TLS terminator behind the Client
- benchmarks for parsing, forwarding, and allocation-sensitive paths
- stronger property testing and fuzzing for security-critical code

## Open questions worth tracking

- how public QUIC passthrough should coexist with Client tunnels on `443/udp`
- how clustered mode should route requests to the correct Tunnel without centralizing the data path
- whether the Server should keep one coordinating accept loop or move to a clearer supervision model as the runtime grows
- whether Server-side Tunnel selection and Client-side Service selection should eventually share a routing abstraction once exact-match routing is real on both sides
- whether downstream connection reuse materially improves performance without hurting correctness
