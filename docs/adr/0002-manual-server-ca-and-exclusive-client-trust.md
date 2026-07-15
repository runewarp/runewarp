# Manual Server CA and exclusive Client trust

## Status

Accepted

## Context

Private deployments need a stable trust anchor for the Server hostname without silently retaining trust in unrelated public roots.

## Decision

The manual Server certificate path uses a private Server CA to issue the Server leaf. A Client selects exclusive CA-bundle trust with `client.server-trust = "ca-file"`; `client.server-ca-file` may override the default bundle path.

## Consequences

- ordinary Server leaf renewal does not change Client trust
- configured private trust does not combine with the system trust store
- the simple path may colocate the private Server CA key with the public Server in `state/`, trading stronger key separation for operational simplicity
- ACME remains the expected default for most publicly reachable deployments
