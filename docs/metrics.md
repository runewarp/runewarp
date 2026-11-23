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
| `runewarp_server_visitors_accepted_total` | counter | | | Visitor TCP connections accepted from a public listener, before any admission check. Every accepted Visitor ends as exactly one rejection, one placement, or one ACME TLS-ALPN-01 challenge for the Server hostname (counted by `runewarp_acme_events_total`), so once Visitors settle, accepted equals rejected plus placed plus challenges. |
| `runewarp_server_visitors_rejected_total` | counter | | `reason` | Visitors dropped before placement. `admission_visitor_global`, `admission_visitor_source`, `admission_pending_stream_open`, `admission_active_routed_stream`: that admission limit was full. `intake_timeout`: the PROXY v2 header and ClientHello did not arrive within the intake deadline. `parse_failed`: the PROXY v2 header was malformed or came from an untrusted peer, or the ClientHello was malformed, incomplete, oversized or had no valid SNI. `unknown_server_hostname`: the ClientHello named the Server hostname without offering ACME TLS-ALPN-01, or offered it with no ACME TLS config. `unauthorized_hostname`: no Tunnel authorizes the Public hostname, including an Authorization replacement between routing and placement. `no_tunnel_connection`: the Tunnel has no live connection. `stream_open_failed`: opening the Tunnel stream failed or hit the stream-open deadline. `certificate_not_serving`: the managed Server certificate was not serving. `shutdown`: shutdown or drain started before placement. |
| `runewarp_server_visitors_placed_total` | counter | | | Visitors whose Tunnel stream opened and that registered as active work. |
| `runewarp_server_visitors_closed_total` | counter | | `outcome` | Placed Visitors that ended. `ok`: both directions finished cleanly. `error`: either direction failed, such as a reset. `cancelled`: an Authorization replacement, shutdown or drain aborted the Visitor. |
| `runewarp_server_visitors_active` | gauge | | | Placed Visitors that have not ended. |
| `runewarp_server_visitor_duration_seconds` | histogram | seconds | | Lifetime of each placed Visitor, from TCP accept to close. Buckets: 0.01, 0.1, 1, 10, 60, 300, 1800, 3600, 21600 and 86400 seconds. |
| `runewarp_server_visitor_stream_open_duration_seconds` | histogram | seconds | | Time to open the Tunnel stream, observed for placed Visitors. Failed opens count as `stream_open_failed`. Buckets: 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5 and 5 seconds. |
| `runewarp_server_visitor_bytes_total` | counter | bytes | `direction` | Visitor stream bytes the destination writer accepted, counted after each successful write. `from_visitor`: written to the Tunnel stream, including the buffered ClientHello. `to_visitor`: written to the Visitor socket. Both are the Visitor's TLS records. See [Bandwidth](#bandwidth). |
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
| `runewarp_client_visitors_handled_total` | counter | | Visitor streams a Server opened that reached this Client instance, including ones rejected. |
| `runewarp_client_visitors_rejected_total` | counter | `reason` | Visitor streams dropped before reaching a Local backend. `no_service`: no Service matches the Public hostname. `intake_timeout`: the Runewarp framing and ClientHello did not arrive within the intake deadline. `parse_failed`: the framing or ClientHello was malformed. `saturated`: every stream-handler permit was in use, so the stream was reset. |
| `runewarp_client_visitors_active` | gauge | | Visitor streams inside a stream handler, from acceptance until the handler returns. |
| `runewarp_client_backend_connect_duration_seconds` | histogram | | Time to connect to the Local backend, for successful connects. Same buckets as `runewarp_server_visitor_stream_open_duration_seconds`. |
| `runewarp_client_backend_connect_failures_total` | counter | | Local backend connects that failed or hit the connect deadline. |
| `runewarp_client_backend_bytes_total` | counter | `direction` | Bytes at the Local backend socket. `to_backend`: written to the socket, including any regenerated PROXY v2 header. `from_backend`: read from the socket. TLS records under TLS passthrough, plaintext in Terminate mode. See [Bandwidth](#bandwidth). |

The `client stream handlers saturated` warning reports this active count as `active-work`.

## Bandwidth

Byte counters are operational and best-effort. They are not usage accounting and must not be used for billing: they reset with each runtime, a scrape can miss the last increments before a process exits, and the two roles count at different boundaries.

- The Server counts Visitor stream bytes. It includes the buffered ClientHello and every forwarded TLS record, and excludes the incoming PROXY v2 prefix, the Runewarp framing prefix on the Tunnel stream, and QUIC and Tunnel TLS overhead.
- The Client counts at the Local backend socket, which also carries the regenerated PROXY v2 header for Services that opt in.
- Each write counts only the bytes the destination accepted. A partial write counts its accepted part, and bytes moved before a cancellation, reset or half-close stay counted.
