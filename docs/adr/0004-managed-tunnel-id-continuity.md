# Managed Tunnel ID as continuity key

Managed Server tunnels require a Control-owned opaque **Tunnel ID** (`tunnels[].id`) that Core uses as the live-pool continuity key across snapshot applies, while admission and revocation stay grounded in Client identity and Public hostname facts. Static mode has no Tunnel ID. We rejected leaving continuity ordinal-only (fragile under reorder; weak patch addressing) and rejected UUID-format validation in Core (opacity matches revision; Control may still emit UUIDs).
