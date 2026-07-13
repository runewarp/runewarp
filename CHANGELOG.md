# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Fixed

- Fixed the amd64 runtime regression where a long-lived top-level stderr lock could stall background runtime logging and break idle tunnel registration. (#140)

### Added

- Added managed-mode `[control]` configuration with `control.address`, `control.trust`, and `control.ca-file`, runtime `--control-address` on `runewarp server` and `runewarp client`, and managed-only `server.identity-dir` for Server identity material. (#165)
- Added the runtime-only `runewarp server --hostname <HOSTNAME>` override so one shared Server config can inject the effective Server hostname before validation, Server certificate checks, and Server ACME setup. (#138)
- Added the narrow `RUNEWARP_SERVER_HOSTNAME` override for `runewarp server`, `runewarp server cert init`, and `runewarp server cert rotate-ca`, with precedence between `--hostname` and `server.hostname`. (#144)
- Added opt-in `server.readiness-bind-address` TCP readiness probes plus `server.graceful-shutdown-duration` so Server ingress admission and orderly shutdown mode are explicit and operator-configurable. (#148)

### Changed

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
