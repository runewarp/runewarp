# Traces

Server and Client runtimes can export spans over OTLP/HTTP with protobuf encoding. Export is off by default and opts in with one top-level key:

```toml
otlp-traces-endpoint = "http://127.0.0.1:4318"
trace-sample-ratio = 0.1
```

Nothing leaves the process while `otlp-traces-endpoint` is unset. Any collector or backend that accepts OTLP/HTTP protobuf works.

## Configuration

- `otlp-traces-endpoint` is an `http` or `https` URL. Runewarp posts to it as given, or to `/v1/traces` when the URL has no path. Credentials in the URL are rejected. `https` uses the system trust store.
- `trace-sample-ratio` is a number from `0` to `1`. It defaults to `1`, which exports every span. It requires `otlp-traces-endpoint`.
- Sampling is parent-based ratio sampling. Every Runewarp root span takes the ratio decision, and its child spans follow it.
- The first runtime in a process fixes trace export, like `log-format`.
- The standard `OTEL_EXPORTER_OTLP_TRACES_HEADERS` or `OTEL_EXPORTER_OTLP_HEADERS` environment variable adds request headers, such as a collector API key. The config keys set the endpoint, and each request times out after 10 seconds, whatever the other `OTEL_EXPORTER_OTLP_*` variables say.
- A successful start logs `INFO <role> trace export enabled: endpoint=<endpoint> sample-ratio=<ratio>`. The logged endpoint omits any query.

## Export

- Finished spans wait in a bounded queue of 2,048 spans. When the queue is full, new spans are dropped. Span creation never waits for export.
- A background exporter sends batches of up to 512 spans every 5 seconds, or sooner when a batch fills.
- A failed export is retried a few times with backoff within the 10-second timeout, then the batch is dropped. They log at `debug`, at most once per minute: `<role> trace export failed: <error> suppressed=<count>`, where the count is the failures since the last line.
- On exit the runtime flushes queued spans for up to 5 seconds.
- Export never gates serving. An unreachable collector costs only failed requests on the exporter thread.

## Spans

Every span has the `service.name` resource attribute `runewarp-server` or `runewarp-client`, and `service.version` matching `runewarp --version`.

| Span | Role | Starts | Ends | Attributes |
| --- | --- | --- | --- | --- |
| `visitor` | Server | A public TCP connection is accepted. | At placement on a Tunnel stream or at rejection, not when the Visitor stream closes. | `runewarp.outcome`, `runewarp.server_generation` |
| `intake` | Server | Child of `visitor`: PROXY v2 and ClientHello intake. | Intake completes, fails or times out. | |
| `route` | Server | Child of `visitor`: Tunnel selection for the Public hostname. | A Tunnel connection is selected or the route is refused. | |
| `stream_open` | Server | Child of `visitor`: waiting for Visitor stream credit. | The stream opens, or the open fails or times out. | |
| `tunnel_connection.handshake` | Server | A Tunnel connection's QUIC handshake is admitted. | The connection is registered in a Tunnel pool or rejected. | `runewarp.outcome`, `runewarp.server_generation` |
| `client.tunnel_connect` | Client | A primary or candidate Tunnel connection attempt starts. | The connection is established or the attempt fails. | `runewarp.outcome`, `runewarp.candidate` |
| `client.visitor` | Client | A Visitor stream is accepted. | The backend is connected or the stream is rejected. | `runewarp.outcome` |
| `managed.apply` | Both | A validated Managed snapshot starts applying. | The apply succeeds or is rejected. | `runewarp.outcome`, `runewarp.role`, `runewarp.revision` |

`runewarp.outcome` values:

- `visitor`: `placed`, `rejected`, `acme_challenge`, `shutdown`, `cancelled`.
- `tunnel_connection.handshake`: `accepted`, or a rejection reason from `runewarp_server_tunnel_connections_rejected_total`: `unauthorized`, `handshake_failed`, `pool_full`, `shutdown`.
- `client.tunnel_connect`: the outcome from `runewarp_client_tunnel_connection_attempts_total`: `connected`, `resolution_failed`, `unauthorized`, `wrong_generation`, `failed`.
- `client.visitor`: `connected`, `rejected`, `acme_challenge`, `cancelled`.
- `managed.apply`: `applied`, `rejected`, `cancelled`.

`cancelled` means the work ended without an outcome, for example when its task stopped.

## Privacy

- Span attributes come only from code-enumerated values, the Server runtime generation, Control revisions and the Client candidate flag. They never carry hostnames, IP addresses, ports, Client identities or Tunnel IDs.
- Log events are never attached to spans, so log message fields do not reach the collector.
- Runewarp does not propagate trace context over the Tunnel. Correlate Server and Control activity by Server generation, revision and time.
- Spans from dependencies are never exported.

## Logs

Trace export does not change runtime log output. Text and JSON lines are identical with and without it, and `log-level` does not affect which spans export.
