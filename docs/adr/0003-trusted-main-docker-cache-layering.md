# Trusted main Docker cache layering

## Status

Accepted

## Context

Container builds need useful Rust dependency caching without allowing untrusted pull-request cache output to cross into privileged image publication.

## Decision

Cache scope is part of the trust boundary. Pull requests use per-PR namespaces; trusted `main` CI warms the trusted-main cache reused by native `amd64` and `arm64` Images jobs. Each architecture publishes and smokes an immutable commit tag before manifest merge. The merged bare 12-character commit tag is the release handoff artifact.

Runewarp keeps the dependency-aware multi-stage Dockerfile instead of adding heavier cache tooling.

## Consequences

- untrusted and trusted cache output remain separated
- native images are smoke-tested before merge and stable-tag promotion
- released `--version` output retains commit provenance
- the application crate still recompiles per commit even when dependencies are cached
