# Trusted main Docker cache layering

## Status

Accepted

## Context

Container builds need useful Rust dependency caching without allowing untrusted pull-request cache output to cross into privileged image publication.

## Decision

Cache scope is part of the trust boundary: untrusted pull-request output must never feed a privileged image publication. Current cache namespaces, image build stages, smoke order, and release lineage are implementation details documented in [`../release-automation.md`](../release-automation.md).

## Consequences

- untrusted and trusted cache output remain separated
- trusted publication may reuse only trusted cache output
- cache or workflow changes must preserve that boundary even when their mechanics change
