# Metrics

Server and Client runtimes can serve Prometheus metrics in OpenMetrics text format. Metrics are off by default and opt in with one key per role:

```toml
[server]
metrics-bind-address = "127.0.0.1:9100"

[client]
metrics-bind-address = "127.0.0.1:9101"
```

Runewarp makes no outbound calls for metrics. Any collector that scrapes Prometheus or OpenMetrics text works.

## Endpoint

- `GET /metrics` returns `200` with `application/openmetrics-text; version=1.0.0; charset=utf-8`. Every other method or path returns `404`.
- At most 4 scrape connections are open at once. Further connections close immediately.
- Each connection serves one request and closes. A connection still open after 5 seconds is closed.
- The listener has no authentication or TLS. Bind it to loopback or a private network.
- A bind failure never stops the runtime. It logs `ERROR <role> metrics listener disabled: config-key=<key> bind-address=<address>: bind failed: <error>` and the runtime keeps serving without metrics. A successful bind logs `INFO <role> metrics listener enabled: bind-address=<address>`.
- The Server keeps the listener open through graceful shutdown and Managed drain. A Managed Server runtime keeps it open after a drain completes, while it keeps reporting, and closes it when the runtime returns.

## Guarantees

- Every runtime owns its own series. Two runtimes in one process never share values.
- Counters start at zero when a runtime starts and reset with each new runtime, including a new runtime in the same process. They are operational and best-effort, never a usage ledger.
- Gauges are atomics updated where state changes. A scrape only reads atomics: it takes no locks and never walks Tunnel pools.
- Labels come only from values enumerated in code. Series never carry hostnames, IP addresses, Client identities or Tunnel IDs, so the series count per role is fixed.
- Metric names, types, units and label values are a public contract. Changes follow changelog discipline.

## Identity series

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `runewarp_build_info` | info | `version`, `revision`, `role` (`server`, `client`), `mode` (`static`, `managed`) | Crate version, full build commit (empty when unknown), role and admission mode. |
| `target_info` | info | `service_name`, `service_version`, `service_instance_id` | OpenTelemetry resource attributes. `service_name` is `runewarp-server` or `runewarp-client`. `service_version` matches `runewarp --version`. On a Server, `service_instance_id` is the Server runtime generation, so overlapping generations during a rollout stay distinct. Each Client runtime mints its own UUIDv7. |

## Server

| Metric | Type | Unit | Labels | Boundary |
| --- | --- | --- | --- | --- |
| `runewarp_server_ready` | gauge | | | `1` while the Server admits new ingress, the same state the readiness probe reports. It does not need `server.readiness-bind-address`. `0` before the first Managed apply, during certificate maintenance, and from the start of shutdown or drain. |
| `runewarp_server_draining` | gauge | | | `1` from the start of orderly shutdown or a Managed drain. It never returns to `0`. |
| `runewarp_server_tunnel_connections` | gauge | | | Accepted Tunnel connections that have not closed. Counted from Tunnel pool registration until the close is observed. |
| `runewarp_server_tunnels_connected` | gauge | | | Tunnels with at least one connection in their pool. |
| `runewarp_server_tunnel_connections_accepted_total` | counter | | | Tunnel connections registered in a Tunnel pool after a successful handshake. |
| `runewarp_server_tunnel_connections_rejected_total` | counter | | `reason` | Tunnel connections refused before registration. `unauthorized`: the pinned-identity check refused the Client identity, or it maps to no Tunnel. `handshake_failed`: QUIC, TLS, HTTP/3 or event-stream setup failed or timed out, or the pending-handshake limit was full. `pool_full`: a Tunnel connection admission limit was full. `shutdown`: the Server had stopped accepting, or shutdown interrupted the handshake. |
| `runewarp_server_tunnel_connections_closed_total` | counter | | `reason` | Accepted connections that ended. `closed`: the peer closed with `H3_NO_ERROR` or QUIC `NO_ERROR`, or the local session driver closed after the WebTransport session ended, including Client withdrawal. `dropped`: any other end, such as a peer error code, an idle timeout or a reset. `replaced`: an Authorization replacement revoked its Client identity. `shutdown`: Server shutdown or Managed drain closed it. |
| `runewarp_server_tunnel_connection_duration_seconds` | histogram | seconds | | Lifetime of each accepted connection, from registration to close. Buckets: 1, 10, 60, 300, 1800, 3600, 21600, 86400 and 604800 seconds. |
| `runewarp_server_admission_in_use` | gauge | | `limit` | Work holding an aggregate admission limit. `visitor_global`, `quic_handshake_global`, `pending_stream_open`, `active_routed_stream`, `tunnel_connection_global`. |
| `runewarp_server_admission_limit` | gauge | | `limit` | Effective limit after file-descriptor sizing. The in-use values plus `visitor_source`, `tunnel_connection_per_tunnel` and `tunnel_connection_per_client_identity`. |
| `runewarp_server_managed_session_connected` | gauge | | | Managed mode only. `1` once a validated snapshot arrives on the active downlink, `0` while the session reconnects. |
| `runewarp_server_managed_session_events_total` | counter | | `event` | Managed mode only. `snapshot`, `applying`, `applied`, `rejected`, `superseded`, `reconnecting`, matching the Managed-session log events. |
| `runewarp_server_certificate_expiry_timestamp_seconds` | gauge | seconds | | Expiry of the serving Server certificate as a Unix timestamp. From the manual certificate leaf, or the current ACME snapshot. Absent until a certificate is known. |
| `runewarp_acme_events_total` | counter | | `event` | Server certificate ACME events. `ownership_acquired`, `certificate_installed` (a new serving certificate fingerprint), `failure`, `maintenance_started`, `challenge_handled` (a TLS-ALPN-01 connection reached the Server). |

Per-source, per-Tunnel and per-Client-identity limits have no in-use series. Their usage is per key, and keys are never labels.

## Client

| Metric | Type | Labels | Boundary |
| --- | --- | --- | --- |
| `runewarp_client_tunnel_connections` | gauge | | Tunnel connections that completed establishment and have not ended, including candidate connections. |
| `runewarp_client_tunnel_connection_attempts_total` | counter | `outcome` | Every primary and candidate attempt. `connected`, `resolution_failed`, `unauthorized` (the Server refused the Client identity), `wrong_generation` (a candidate reached the wrong Server runtime), `failed` (any other failure). |
| `runewarp_client_visitor_credit_available` | gauge | | Idle permit-backed Visitor credit currently offered to Servers, summed over every connection. |
| `runewarp_client_stream_handlers_active` | gauge | | Visitor streams holding a stream-handler permit, from stream acceptance until both stream halves drop. Idle credit plus active handlers never exceeds `client.max-visitor-streams`. |

The `client stream handlers saturated` warning reports this active count as `active-work`.
