# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed

- Contracted redundant `config::client` / `config::server` config aliases to role-qualified entry points and exposed preparation-owned material outcomes (`resolve_server_cert_material_dir`, `resolve_server_cert_hostname`, `resolve_client_identity_material_dir`, `resolve_client_public_cert_material_dir`) for public Rust consumers. (#210)

### Security

- Bounded the complete routed-stream setup lifecycle: distinct Server pending-`open_bi` and active routed-stream budgets, a 5-second `open_bi` deadline, keyed active Visitor-stream tracking, a Client-instance aggregate stream-handler limit aligned with QUIC bidi credit, and 5-second Client setup deadlines for tunneled ClientHello, backend connect/write, Terminate handshake, and ACME challenge handshake, while leaving established proxies long-lived. (#208)
- Bounded Managed-session SSE framing, snapshot size, decoded allocation, and role-input cardinalities; moved applied-state reporting off the reconciliation critical path with coalesced latest-revision acknowledgments, bodyless-204 enforcement, and 5-second request/response deadlines. (#207)
- Bounded Server admission before Visitor and QUIC-handshake task creation, added a 5-second ClientHello deadline, capped active Tunnel connections globally/per-Tunnel/per-Client-identity, and made transient public-listener accept failures recover with bounded backoff. (#206)
- Upgraded the Rust dependency baseline past RUSTSEC-2026-0185 (`quinn-proto`) and RUSTSEC-2026-0190 (`anyhow`), replaced unmaintained `rustls-pemfile` PEM parsing with maintained `rustls-pki-types` APIs (RUSTSEC-2025-0134), and added a required `./scripts/audit-dependencies` CI gate. (#204)

### Fixed

- Fixed Client ACME and Terminate-mode TLS preparation so one **Client instance** owns validated Services and ACME managers once across multi-address fanout and Tunnel reconnects, with supervised ACME shutdown instead of per-connection fire-and-forget tasks. (#203)
- Fixed the amd64 runtime regression where a long-lived top-level stderr lock could stall background runtime logging and break idle tunnel registration. (#140)

### Added

- Added required managed Server **Tunnel ID** (`tunnels[].id`): opaque Control-owned continuity keys (shared validation with revision), ID-keyed live pool rematch on apply, and static mode remains ID-less. (#192)
- Added the Managed-session protocol and Control interoperability guide in `docs/managed.md`, with cross-links from architecture, protocol, security, configuration, usage, and the README documentation index. (#190)
- Added managed Client retirement and recovery: connected address removal marks workers Retiring without local closure or Infrastructure drain, re-adding re-adopts without duplicate dialing, Control loss and repeated-revision reconnect preserve the last assignment, process restart fail-closes until a fresh snapshot, and per-address failures stay isolated while fatal workers exit nonzero. (#189)
- Added managed Client assignment reconciliation: the Managed-session Client adapter atomically replaces Address-controller maintenance intent from Control-published Server-address snapshots, acknowledges revisions without awaiting network convergence, tracks Unconverged / Partially converged / Converged assignment progress (excluding Retiring connections), and keeps independent per-address reconnect loops while skipping the static one-shot Client-ready event. (#188)
- Added managed Server authorization apply: the Managed-session Server adapter atomically commits Control-published Tunnel authorization, defers **Server readiness** until the first successful apply, retains prior authorization on rejected candidates, and acknowledges applied revisions over the Control session. (#185)
- Added managed Server revocation and drain enforcement: Client-identity and Public-hostname authorization changes apply immediately (including during bounded graceful drain), surviving work is remapped by identity continuity, the Managed session stays active through drain until final process exit, and unrecoverable post-commit readiness failures drop readiness and exit nonzero. (#187)
- Added the role-neutral Managed-session engine that validates Server/Client snapshot inputs, applies them through a role-adapter seam, and acknowledges successfully handled snapshots with the applied opaque revision on the same authenticated HTTP/2 connection as the SSE downlink. (#184)
- Added the role-neutral Managed-session Control downlink: mutually authenticated HTTP/2, exact role-specific SSE paths, snapshot envelope validation, 60-second first-snapshot and silence windows, and full-jitter reconnect that replaces the whole connection on failure. (#166)
- Added managed-mode `[control]` configuration with `control.address`, `control.trust`, and `control.ca-file`, runtime `--control-address` on `runewarp server` and `runewarp client`, and managed-only `server.identity-dir` for Server identity material. (#165)
- Added the runtime-only `runewarp server --hostname <HOSTNAME>` override so one shared Server config can inject the effective Server hostname before validation, Server certificate checks, and Server ACME setup. (#138)
- Added the narrow `RUNEWARP_SERVER_HOSTNAME` override for `runewarp server`, `runewarp server cert init`, and `runewarp server cert rotate-ca`, with precedence between `--hostname` and `server.hostname`. (#144)
- Added opt-in `server.readiness-bind-address` TCP readiness probes plus `server.graceful-shutdown-duration` so Server ingress admission and orderly shutdown mode are explicit and operator-configurable. (#148)

### Changed

- Changed Managed-session state reporting to one revision acknowledgment per successfully handled snapshot, removed periodic Core state heartbeats, and made failed or stalled acknowledgments replace the session while retaining Control-owned SSE keepalives. (#198)
- Removed automatic and manual self-signed Client identity certificate renewal. New Client identities receive a 100-year certificate, the Server continues to authorize the pinned public key without validating certificate expiry, and `runewarp client identity renew` is gone. (#161)
- Added standard top-level `--version` and `-V` output, with `-dev` builds now appending the baked-in 12-character commit SHA for traceability. (#135)

## [0.2.0] - 2026-06-30

### Added

- Added `server.tunnels[].client-identities` so one Tunnel can authorize multiple Client identities, while keeping `client-identity` as the single-value shorthand. (#128)
- Added same-Tunnel Client pools on one Server node, with least-active new-stream placement and round-robin tie-breaking across equal-load pool members. (#129)
- Added Client static fanout so one Client instance can connect to one or more Server addresses through `client.server-addresses` or repeated `--server-address` flags, while keeping the singular config shortcut for the common one-target case. (#127)

### Changed

- Renamed the public validated configuration API around `config` terminology, including `load_client_config`, `load_server_config`, `ClientConfigResolutionDefaults`, `ClientConnectConfig`, and `ServerBindConfig`. (#115)
- Hostname-bearing config and routed SNI values now normalize to lowercase and strip a trailing dot before duplicate detection and route lookup. (#116)
- Simplified Docker example preparation so it stages only the runtime material needed by the read-only Compose mounts, removing the old `source-data` directories while keeping Linux CI-safe permissions for the distroless `nonroot` containers. (#123)

### Security

- Removed remote socket addresses from Server tunnel lifecycle and forwarded-route logs, and reduced forwarded-route debug logging to the normalized public hostname plus stable key=value fields. (#129)

## [0.1.0] - 2026-05-29

### Added

- Public TLS passthrough ingress with Server-authoritative routing by explicit Public hostnames.
- Operator workflows for Server and Client setup, including Client identity management, Server certificates, manual Public hostname certificates, and ACME-backed trust paths.
- Core operator documentation for architecture, protocol, security boundaries, configuration, and an end-to-end Docker example.

### Security

- Pinned Client identity authentication, Server certificate validation, and explicit Public hostname authorization as the default trust boundary for public ingress.

[unreleased]: https://github.com/runewarp/runewarp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/runewarp/runewarp/releases/tag/v0.2.0
[0.1.0]: https://github.com/runewarp/runewarp/releases/tag/v0.1.0
