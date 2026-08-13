# PROTOTYPE: published quiche HTTP/3 signaling result

Evidence for the quiche half of the stack comparison informing [#239](https://github.com/runewarp/runewarp/issues/239), measured on 13 August 2026. This is a throwaway prototype result, not production canon or a stack selection.

## Question

Can published, unmodified `quiche` 0.29.3 support a production-shaped vertical slice of Runewarp ordinary-H3 Tunnel signaling and the reserved Public QUIC carrier seam on one authenticated connection, and what does Runewarp have to own?

## Run

```sh
cargo run --bin prototype_quiche_h3
cargo test --bin prototype_quiche_h3
```

The binary creates private test credentials in a temporary directory, opens real Tokio UDP sockets on loopback, drives both quiche packet/timer/H3 sides from one owner task, prints the complete observed state, and removes the credentials on exit. It does not contact or change external infrastructure.

## Result

Published quiche can carry the attempted signaling and Public QUIC vertical slice without a dependency patch. The cost is substantial application ownership: Runewarp supplies the UDP/Tokio event loop, BoringSSL mTLS construction, H3 request policy, exact GOAWAY enforcement policy, manual H3 Datagram Quarter Stream ID routing, the Context ID framing, the Capsule codec, and terminal flush/timeout ownership.

The deepest useful seam remains one connection-owning H3 adapter. Deleting it would spread packet routing, TLS identity, SETTINGS, request, Datagram, Capsule, cancellation, and teardown details across Client and Server callers. The prototype does not justify a generic transport abstraction or extension registry.

## Acceptance matrix

| Behavior | Result | Evidence or limitation |
| --- | --- | --- |
| Real authenticated H3 connection | **Measured** | Real loopback UDP, QUIC, TLS, H3, and Tokio I/O |
| Mandatory bilateral custom SETTINGS | **Measured** | Both peers sent `0x370e8f9b5f484846 = 1` and observed it through raw peer SETTINGS |
| Arbitrary local and raw unknown peer SETTINGS | **Measured** | A second prototype Public QUIC marker was sent and observed unchanged; quiche grease was also visible |
| Missing/invalid signaling error mapping | **Weakened** | Adapter policy tests map missing frame to `H3_MISSING_SETTINGS`, omitted marker to `H3_GENERAL_PROTOCOL_ERROR`, and value other than `1` to `H3_SETTINGS_ERROR`; invalid live peers and close frames were not exercised |
| Bodyless withdrawal `PUT` and delayed bodyless `204` | **Measured, weakened semantics** | Ordinary request stream `0` carried the exact method/path and FIN; bodyless `204` plus FIN was observed. The prototype commits deliberately but does not model real placement quiescence or the five-second deadline/grace |
| Exact first-unprocessed GOAWAY boundary | **Measured, weakened enforcement** | Server sent exact ID `16`; Client observed `16`; lower stream `12` completed. No live request at/above `16` was admitted and rejected, so application-side boundary enforcement remains unproved |
| Directional cancellation with caller-selected H3 code | **Measured, partial** | Client applied read and write shutdown with `H3_REQUEST_CANCELLED`; Server observed reset code `0x10c`. STOP_SENDING and RESET_STREAM were not separately packet-asserted |
| Standard malformed request/stream/connection mappings | **Missing** | No malformed QPACK/frame/content-length fixture; only well-formed request routing and SETTINGS policy were attempted |
| Certificate-required mTLS | **Measured** | BoringSSL used `PEER | FAIL_IF_NO_PEER_CERT`; a certificate-less Client failed and a CA-issued Client connected |
| Peer identity extraction | **Measured, weakened authorization** | Server observed verified peer DER through `peer_cert()`; the prototype did not convert it to the production pinned `ClientIdentity` or test authorization replacement |
| Application 0-RTT disabled | **Configuration evidence only** | `enable_early_data` is never called and H3 is created only after `is_established`; no resumed-session/early-data rejection fixture was built |
| Connection teardown owns all H3 work | **Measured** | One owner continued packet/timer driving until both quiche connections reached `is_closed`; repeated runs terminated with no spawned task |
| Separate optional Public QUIC SETTINGS | **Measured** | Bilateral prototype marker `0x370e8f9b5f4847 = 1` remained separate from mandatory signaling |
| Narrow Extended CONNECT carrier | **Measured** | Real request stream `4`, private protocol token, Capsule opt-in field, and body-open `200` response |
| Reliable lifecycle Capsule | **Measured, manual** | One bounded three-byte prototype Capsule crossed H3 DATA in both directions. quiche has no Capsule API, so Runewarp owns framing and parsing |
| H3 Datagram send/receive and request routing | **Measured, manual** | QUIC and H3 Datagram negotiation succeeded; Runewarp manually framed Quarter Stream ID plus Context ID and routed it to the live carrier request |
| Real 1200-byte inner QUIC Initial both ways | **Measured** | A real quiche-generated 1200-byte Initial became a 1202-byte H3 Datagram payload with one-byte identifiers and arrived byte-identical both ways |
| No reliable packet fallback | **Measured by construction** | Packet bytes used only QUIC DATAGRAM; H3 DATA carried lifecycle only |
| Carrier cleanup isolated from signaling | **Measured** | Carrier stream cancellation was followed by a successful ordinary withdrawal on stream `12` before connection GOAWAY |
| Live MTU envelope and varint effects | **Partial** | Loopback application-Datagram ceiling was `1412`; one-byte identifiers required `1202`. Per #180, widths 2/2, 4/4, and 8/8 require 1204, 1208, and 1216; this run did not repeat every width |
| CID/rebinding correction | **Preserved limitation** | No rebinding claim. Opaque routing still cannot generally identify a session when source tuple and backend-issued DCID change together |

## Directional measurements

Five optimized loopback runs on Apple arm64 produced:

| Signal | Observed range |
| --- | ---: |
| Authenticated QUIC + H3 SETTINGS setup | 2.669–3.437 ms |
| Withdrawal request to prototype commit | 45–57 µs |
| Commit to complete bodyless `204` | 40–42 µs |
| Carrier request to accepted response | 47–68 µs |
| Signaling completion while 128 Datagrams were queued | 271–293 µs |
| 128 × 1202-byte loopback Datagram workload | 1.309–1.394 Gbit/s |
| Observed workload drops | 0 of 128 per run |

These are in-process loopback directions, not production benchmarks. The workload is too small and clean to characterize nested congestion, loss, fairness, queue expiry, Internet PMTU, CPU, or allocations.

## Build and ownership impact

- Exact published dependency: `quiche = 0.29.3`; no quiche patch or fork.
- Direct BoringSSL dependency: `boring = 4.22.0`, selected by quiche's compatible range.
- Lockfile: 31 additional packages from the fresh base.
- Cold optimized prototype build: 35.57 s wall, 200.36 s user, 781 MB maximum resident set on the measurement host.
- Optimized standalone prototype binary: 3.3 MB. The separately built existing `runewarp` binary remained 9.6 MB because the throwaway binary alone references quiche.
- Runewarp-owned prototype implementation: one dedicated binary plus research/result notes; existing runtime modules were not edited.
- Existing production seams a real migration replaces: Quinn endpoint/connection and Tokio integration, rustls trust/mTLS identity handling, raw Tunnel stream ownership, close/error classification, shutdown flushing, and Quinn-based network fixtures.
- Runewarp prototype code contains no `unsafe`. The quiche/BoringSSL dependency sources contain FFI and dependency-internal `unsafe`.

## Missing proof and remaining risk

- Full #225 quiescence, concurrent duplicate/retry, five-second request timeout, and post-quiescence enforcement timing.
- Live malformed HTTP/3/QPACK/frame fixtures and exact stream-versus-connection close frames.
- Separate packet assertions for STOP_SENDING and RESET_STREAM, plus at/above-GOAWAY rejection.
- TLS resumption with proof that neither endpoint exposes application 0-RTT.
- Production `ClientIdentity` extraction/authorization semantics rather than verified certificate presence.
- General Capsule parsing, partial DATA reassembly, bounded lengths, unknown Capsule handling, and lifecycle race policy.
- Multiple carriers/contexts, teardown races, queue bounds/drop policy, loss, nested congestion, sustained fairness, CPU, and allocation measurements.
- Arbitrary paths, PMTU change, identifier-width cliffs, load balancers, full CID routing, public UDP classification, and a Local backend relay.
- The prototype owns one connection in one task but is not integrated with production Client/Server runtime, graceful shutdown, Managed replacement, or existing observability.

## Primary-source refresh

See [quiche HTTP/3 API refresh](quiche-h3-prototype-api-refresh.md) for exact published API/source evidence and the BoringSSL verification warning. Related decisions and prior measurements remain authoritative inputs in [#238](https://github.com/runewarp/runewarp/issues/238), [#175](https://github.com/runewarp/runewarp/issues/175), and [#180](https://github.com/runewarp/runewarp/issues/180).
