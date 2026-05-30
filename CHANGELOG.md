# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Rewrote the main documentation set for a tighter, more direct operator and maintainer voice.
- Renamed the public validated configuration API around `config` terminology, including `load_client_config`, `load_server_config`, `ClientConfigResolutionDefaults`, and precise runtime types `ClientConnectConfig` and `ServerBindConfig`.
- Replaced the repository-owned release, CI, workflow-lint, Docker example, and release publication helper scripts with Ruby entry points and Ruby automation tests, and removed the repo-owned git hooks.
- Refactored the Ruby automation layout around executable snake_case entrypoints, moved Ruby tests under `scripts/test`, and replaced the old Docker example wrappers with `./scripts/docker_example`.
- Deepened hostname handling around distinct typed **Server hostname** and **Public hostname** values so config validation, ClientHello parsing, and routing all share one canonical normalization seam.

## [0.1.0] - 2026-05-29

### Added

- Public TLS passthrough ingress with Server-authoritative routing by explicit Public hostnames.
- Operator workflows for Server and Client setup, including Client identity management, Server certificates, manual Public hostname certificates, and ACME-backed trust paths.
- Core operator documentation for architecture, protocol, security boundaries, configuration, and an end-to-end Docker example.

### Security

- Pinned Client identity authentication, Server certificate validation, and explicit Public hostname authorization as the default trust boundary for public ingress.

[unreleased]: https://github.com/runewarp/runewarp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/runewarp/runewarp/releases/tag/v0.1.0
