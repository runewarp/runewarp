# Managed Tunnel ID as continuity key

## Status

Accepted

## Context

Managed Server snapshots can reorder or replace Tunnels while live Tunnel pools continue serving traffic. Ordinal position is not a durable continuity key.

## Decision

Managed Server Tunnels require a Control-owned opaque **Tunnel ID** (`tunnels[].id`) that Core uses as the live-pool continuity key across snapshot applies. Admission and revocation remain grounded in Client identity and Public hostname facts. Static mode has no Tunnel ID.

## Consequences

- snapshot reorder does not break live-pool continuity
- future patch addressing has a stable key
- Core validates opacity and bounds but not a UUID format; Control may still emit UUIDs
- static configuration keeps its simpler ID-less model
