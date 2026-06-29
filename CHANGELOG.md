# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Allowed one Server Tunnel to authorize one or more Client identities through `client-identities`, while keeping `client-identity` as the single-value shorthand.
- Added automatic same-Tunnel Client pools on one Server node, with least-active new-stream placement and round-robin tie-breaking across equal-load pool members.
- Added selected pool-member `remote-address` and `active-streams` context to forwarded Server route debug logs for same-Tunnel pools.
- Removed remote socket addresses from info and warn Server tunnel lifecycle logs, keeping them only on debug-detail lines.
- Rewrote the main documentation set for a tighter, more direct operator and maintainer voice.
- Renamed the public validated configuration API around `config` terminology, including `load_client_config`, `load_server_config`, `ClientConfigResolutionDefaults`, and precise runtime types `ClientConnectConfig` and `ServerBindConfig`.
- Exposed deep `config::client` and `config::server` module paths and moved config preparation under the shared `config` module so config-related code lives in one place.
- Replaced the repository-owned release, CI, workflow-lint, Docker example, and release publication helper scripts with Ruby entry points and Ruby automation tests, and removed the repo-owned git hooks.
- Refactored the Ruby automation layout around executable kebab-case entrypoints, moved Ruby tests under `scripts/test`, and replaced the old Docker example wrappers with `./scripts/docker-example`.
- Deepened hostname handling around distinct typed **Server hostname** and **Public hostname** values so config validation, ClientHello parsing, and routing all share one canonical normalization seam.
- Simplified Docker example preparation so it stages only the runtime material needed by the read-only Compose mounts, avoiding the old `source-data` directories while keeping Linux CI-safe permissions for the distroless `nonroot` containers.
- Added separate Rust and Docker build cache scopes for pull request CI, trusted `main` CI, and trusted release flows, with release rehearsal warming the same release caches used by publish.
- Added OSS Client static fanout so one Client instance can reconcile one or more Server addresses through `client.server-addresses` or repeated `--server-address` flags while keeping the singular config shortcut for the common one-target case.

## [0.1.0] - 2026-05-29

### Added

- Public TLS passthrough ingress with Server-authoritative routing by explicit Public hostnames.
- Operator workflows for Server and Client setup, including Client identity management, Server certificates, manual Public hostname certificates, and ACME-backed trust paths.
- Core operator documentation for architecture, protocol, security boundaries, configuration, and an end-to-end Docker example.

### Security

- Pinned Client identity authentication, Server certificate validation, and explicit Public hostname authorization as the default trust boundary for public ingress.

[unreleased]: https://github.com/runewarp/runewarp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/runewarp/runewarp/releases/tag/v0.1.0
