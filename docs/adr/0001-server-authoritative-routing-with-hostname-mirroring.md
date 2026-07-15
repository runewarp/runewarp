# Server-authoritative routing with Hostname mirroring

## Status

Accepted

## Context

The Server must authorize public traffic before a Client can select a local Service, while TLS passthrough prevents either side from relying on HTTP-layer metadata.

## Decision

Runewarp keeps public routing authority on the Server and does not use Client registration or in-protocol Service identifiers. Operators mirror Public hostnames in Server Tunnels and Client Services when both sides need exact hostname matching. The Server chooses the Tunnel and the Client chooses the Service from the forwarded ClientHello.

## Consequences

- public hostname authorization remains explicit and Server-owned
- the public data path stays independent of control-plane negotiation
- operators must keep mirrored hostname sets consistent when they do not use a Catch-all Service
- Tunnel and Service groupings may differ as long as the hostname coverage agrees
