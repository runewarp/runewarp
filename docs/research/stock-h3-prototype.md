# PROTOTYPE: ordinary-H3 signaling on stock `hyperium/h3`

Throwaway research note. Not a production stack selection, protocol specification, or implementation authorization. Inputs: #226, #225, #223, #242, #244, #239.

## Question

Can Runewarp's ordinary-HTTP/3 Tunnel signaling and a Visitor byte carrier be built on unmodified upstream `hyperium/h3` + `h3-quinn` (keeping Quinn 0.11 + rustls 0.23), so Runewarp does not maintain an h3 fork?

The redesign under test drops the three #242 patches:

1. No custom SETTINGS marker. The Client gates availability on the first valid event-stream state (`version` + opaque Server runtime `generation`). The Server gates placement on real Client-provided slots.
2. Stock `server::Connection::shutdown(n)` instead of an exact-ID GOAWAY API.
3. No arbitrary Extended CONNECT `:protocol`. Receive slots use plain CONNECT or a streaming POST.

## Exact revisions

| Item | Revision |
| --- | --- |
| Runewarp base | `8cb31c6ff3ecfb933fa31eda94cb80444552730b` |
| `h3` + `h3-quinn` | `hyperium/h3` main [`43745ad87e95b0c035ac9c547aad467303213425`](https://github.com/hyperium/h3/commit/43745ad87e95b0c035ac9c547aad467303213425) (2026-09-20), git dev-dependency, unmodified. Crate versions still read `h3 0.0.8` / `h3-quinn 0.0.10`. `h3` uses its stock `tracing` feature, for GOAWAY observation only. |
| Quinn / rustls | `quinn 0.11.11`, `rustls 0.23.42` (single copies; unchanged from main) |
| Toolchain | `rustc 1.96.0`, macOS, loopback |

## How to run

```sh
cargo run --example prototype_stock_h3_signaling            # debug
cargo run --release --example prototype_stock_h3_signaling  # release timings
```

Everything lives in `examples/prototype_stock_h3_signaling.rs`: in-process certificates (rcgen), required client-certificate mTLS, loopback endpoints, a tiny UDP forwarder. Only `Cargo.toml`/`Cargo.lock` (dev-dependencies) changed. No production module changed. No `unsafe`. The run ends with a result matrix; `PARTIAL` lines name each deviation.

## Result matrix

| # | Experiment | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Build, ALPN `h3`, required mTLS, no application 0-RTT | Pass | Builds against Runewarp's Quinn/rustls with no duplicate Quinn. Anonymous Client refused (`peer sent no certificates`). Server extracts the peer chain via `peer_identity()` (1 cert, ~370 B leaf). Negotiated ALPN `h3`. A Client with `enable_early_data = true` resumes but `into_0rtt()` fails because the Server ticket carries `max_early_data_size = 0`. |
| 2 | GOAWAY via stock `shutdown(1)` | Partial stock; Pass with app guard | Client opens 0,4,8,12,16; Server accepts 0,4 then `shutdown(1)`. Client decodes GOAWAY id 8 (the RFC first-unprocessed value). Stock h3 still hands stream 8 to the app (rejects only `> 8`), so 8 completes with 200 despite GOAWAY(8). Stream 12 gets `H3_REQUEST_REJECTED`. `accept()` returns `None` after rejecting 12 while 16 is still queued; an app that stops there and drops the connection leaves 16 with a connection close (`H3_NO_ERROR`) instead of a rejection. With an app guard (reject `id >= 8`) and continued `accept()` after `None`: 0,4 → 200; 8,12,16 → `H3_REQUEST_REJECTED`. After GOAWAY the client's `send_request` fails locally (`RemoteClosing`). `shutdown(0)` sends GOAWAY(last accepted), which declares an already-processed stream unprocessed. |
| 3 | `GET /v1/tunnel/events` (`text/event-stream`) | Partial | Initial state arrives immediately (`version:1`, 128-bit hex `generation`, `replacing:false`), then `: keepalive` comments, then a pushed `replacing:true`. The Client resets and the connection survives. Resubscribing on the same connection returns current state (`replacing:true`). Deviation: the Client's `stop_sending(H3_REQUEST_CANCELLED)` never reaches the wire. The Server sees `STOP_SENDING(0x0)`, Quinn's drop default ([hyperium/h3#361](https://github.com/hyperium/h3/issues/361)). Workaround verified: keep polling `recv_data` after `stop_sending`; the next keepalive completes the in-flight read and the Server sees `H3_REQUEST_CANCELLED`. The Server detects the reset only on its next write ([hyperium/h3#350](https://github.com/hyperium/h3/issues/350)). |
| 4a | Receive slots, plain CONNECT | Partial | Client gates on the initial event state, then pre-opens 4 slots (`CONNECT stock-h3.prototype:443`, no `:path`). Stock h3 accepts this without Extended CONNECT. On a Visitor, the Server sends response HEADERS plus one DATA frame (18 B PROXY stand-in + buffered ClientHello) with no Client round trip; the Client sees it about one one-way delay later. The Client replenishes each slot on assignment (4 idle again, 8 opened). Half-close works both ways: Client FIN first then Server keeps sending, and Server FIN first then Client keeps sending. Cancellation never affected other slots, the event stream, or the connection. RESET_STREAM with `H3_REQUEST_CANCELLED` arrives correctly in both directions. STOP_SENDING after any read is deferred (#361): Client-side it became `0x0` on drop; Server-side it applied only after the Server polled its stopped receive half again while the Client was still writing. 4 MiB through one slot works with default windows. |
| 4b | Receive slots, streaming POST `/v1/tunnel/slots` | Partial | Same behaviour as CONNECT. Dispatch by `:path` is more natural. The #361 deferral is timing-dependent: one run's Client-side cancel delivered the right code, another did not. |
| 5 | Withdrawal | Pass | Bodyless `PUT /v1/tunnel/withdrawal` + FIN. The Server commits, refuses further placement, and withholds the 204 while 1 Visitor is active (checked at 100 ms). Once the Visitor finishes, it sends a bodyless 204 + FIN about 0.03 ms after quiescence. The Client closes with `H3_NO_ERROR`; the Server observes `ApplicationClose(H3_NO_ERROR)`. |
| 6 | Stretch: replacement behind a tuple-pinned UDP forwarder | Pass | Servers A and B have different generations. The forwarder keys sessions on Client source address and pins the upstream at session creation. The primary on A receives `replacing:true`. Candidates 1 and 2, each on a new `Endpoint` (new UDP socket), land on A; the Client sees generation == primary and closes them before offering slots. A Visitor flows on the primary between attempts. After the toggle, candidate 3 lands on B (generation differs) and offers 2 slots. A drains: stock `shutdown(1)` → client decodes GOAWAY 20; the event stream ends with FIN; idle slots get `H3_REQUEST_REJECTED`; then the app closes QUIC with `H3_NO_ERROR`, because stock `accept()` never completes after the Server's own GOAWAY. The candidate becomes primary and carries a Visitor on B. |
| 7 | Hygiene | Pass | `cargo fmt --check` clean. `cargo clippy --all-targets --all-features -- -D warnings` clean: no Runewarp warnings, and Cargo shows no dependency warnings for git dependencies. `cargo test --all-features` passes. Lockfile: +2 packages (`h3`, `h3-quinn`), no new duplicate versions (the existing `rand`/`rcgen`/`x509-parser`/`asn1-rs`/`thiserror` duplicates predate this change). |

### Released crates (`h3 0.0.8` / `h3-quinn 0.0.10`)

The same example compiles unchanged against crates.io. Experiments 1–2 behave identically. Experiment 3 then panics: `h3-quinn-0.0.10/src/lib.rs:394` unwraps `None` in `stop_sending` while a read is in flight ([hyperium/h3#330](https://github.com/hyperium/h3/issues/330), fixed after release by #331, which introduced the #361 deferral). Code reading also finds these post-release fixes relevant here, but they were not run on 0.0.8: #360 (`finish` could truncate buffered DATA, and a cancelled send future could close the connection with `H3_INTERNAL_ERROR`), #365 (request tracking leaks when a resolver ends early), #357 (`recv_id` during an in-flight read). Released crates are not viable for this design; a git pin or the next release is required.

### Directional timings (loopback, one run each)

| Measurement | debug | release |
| --- | --- | --- |
| Authenticated QUIC + H3 setup | 1.8 ms | 0.44 ms |
| Event request → initial state | 2.7 ms | 0.87 ms |
| State push → Client parse | 0.61 ms | 0.29 ms |
| Slot pre-open ×4 → parked at Server | 1.1 ms | 0.3–0.9 ms |
| Server assign → Client has PROXY + ClientHello | 0.25–0.44 ms | 0.15–0.30 ms |
| 4 MiB Server → Client, one slot | 80 ms | 47 ms |
| Quiescence → 204 + FIN sent | 0.03 ms | 0.03 ms |

## API friction

1. **Deferred STOP_SENDING (#361, open upstream).** h3's `FrameStream::poll_data` starts a fresh QUIC read even when it returns buffered bytes. h3-quinn parks the Quinn stream inside that boxed read, so `stop_sending(code)` is stored and applied only when the app polls again and the read completes. In practice, almost every `recv_data` that returns data leaves a read in flight. If the peer is idle, the code is lost and Quinn's drop sends `STOP_SENDING(0)` (0 is not a valid H3 code). An app-level workaround exists only when the peer keeps sending. The upstream issue proposes a roughly 30-line h3-quinn fix, and the reporter has offered a PR.
2. **Peer STOP_SENDING is write-observable only (#350, open).** No pollable "stopped" notification. Idle event streams detect a Client reset at the next keepalive. Idle slots cannot detect Client STOP_SENDING at all. Client RESET (`stop_stream`) is detectable only if the Server holds a pending `recv_data` on the idle slot, and the prototype does not.
3. **GOAWAY boundary is inclusive in h3, exclusive in RFC 9114 §5.2.** `shutdown(n)` sends `last_accepted + n` but rejects only IDs `>` that value. Exact first-unprocessed semantics need an app guard and the last accepted ID. `RequestResolver` does not expose its stream ID before `resolve_request()` (`frame_stream` is `#[doc(hidden)] pub`), so the prototype resolves headers inline in the accept loop with a timeout. A slow header block can therefore stall accepts.
4. **Server `accept()` after its own GOAWAY.** It returns `None` only when a rejected stream arrives after in-flight requests complete, or after a Client GOAWAY. It can return `None` while more rejectable streams are queued, and calling it again rejects them. It never resolves when nothing more arrives. The app must track its own outstanding work and close QUIC itself. There is no Server `wait_idle`.
5. **The `accept()` → `None` path calls `shutdown(0)` internally.** Per the code, if `last_accepted` is below an earlier GOAWAY ID, this sends a lower GOAWAY that declares the last processed stream unprocessed. Not exercised; the guarded run accepted the boundary stream internally, so no second GOAWAY was sent.
6. **The Client cannot read the received GOAWAY ID.** `recv_closing` is private. The only signals are `send_request` → `RemoteClosing` and per-stream `H3_REQUEST_REJECTED`. The prototype observed the wire ID through h3's `tracing` output. Requests killed by a connection close are ambiguous for the app. That is harmless for idempotent slots, and withdrawal retries are already bounded by #226.
7. **`StreamError::RemoteClosing` and `StreamError::ConnectionError(_)` cannot be matched downstream.** They are `#[non_exhaustive]` unit/tuple variants, whose constructors are private. Only `RemoteTerminate { code, .. }` and `StreamError { code, .. }` are matchable; the rest needs `is_h3_no_error()` or Debug.
8. **Never race a send future in `select!`.** Fixed in main by #360. The prototype races only the trigger, then awaits `send_data` outside the select.
9. **Slot allocation.** Each idle slot holds one Client-initiated bidi stream against Quinn's `max_concurrent_bidi_streams` (default 100), shared with the event stream and withdrawal. The pool size and the Server's stream limit must be set together. Each replenish consumes a new stream ID. A slot has no deadline before assignment; the event-stream keepalives also keep the connection under Quinn's idle timeout.
10. **Plain CONNECT semantics.** Without `:protocol` or `:path`, dispatch is by method only, and `:authority` must name something. The prototype uses the Server's own `host:443`, i.e. "tunnel to the Server itself". Streaming POST keeps path-based dispatch and an indefinite request body; responding 200 before the request body ends is legal HTTP. h3 handled both identically.
11. **Server assignment is two awaits**: `send_response` then `send_data`. Both are buffered into the QUIC stream before the next flush, so the measured latency is one-way. A combined "response + first DATA" call does not exist and is not needed.

## What the redesign gives up versus the patched-h3 contract (#226)

- **H3-layer capability proof.** #226 requires bilateral `SETTINGS_RUNEWARP_SIGNALING = 1` and closes incompatible peers with `H3_SETTINGS_ERROR` before any request. Here, compatibility becomes application-level: an incompatible Server is detected by a failed or invalid `GET /v1/tunnel/events`, and an incompatible Client by never offering valid slots. There is no defined connection error code, and detection costs one request round trip after the handshake (SETTINGS arrive in the first flight). Version negotiation moves into the event `version` field.
- **Exact GOAWAY from the library.** Exactness becomes app policy layered on stock `shutdown(1)`: guard plus inline resolve plus explicit close. It works, but it is easy to get wrong, and the Client still cannot read the ID.
- **Extended CONNECT protocol token.** Plain CONNECT or POST loses explicit `:protocol` negotiation (`SETTINGS_ENABLE_CONNECT_PROTOCOL`). The Public QUIC carrier seam from #242 (Extended CONNECT + H3 Datagram + Capsules) was not re-tested on this design.
- **Bilateral gate symmetry.** The Client gate is the first valid event state, not peer SETTINGS. The Server gate is real slots, which is stronger than SETTINGS: a slot is concrete, usable availability.
- **Gained.** No h3 patch, no local-only dependency commits, +2 lock packages, Quinn/rustls unchanged, Runewarp-specific `generation` usable for replacement validation (Experiment 6).

## Verdict

An h3 fork is avoidable. Every signaling and carrier behaviour tested here runs on unmodified upstream `h3` main; exact GOAWAY needs only app-level policy, documented above. The remaining blocker is in `h3-quinn`, not `h3`: #361 means caller-selected STOP_SENDING codes are unreliable after any read. Runewarp then has three options: wait for or contribute the small upstream fix (the issue is open and a contributor offered a PR); accept `STOP_SENDING(0)` for idle-direction cancels (RESET codes and connection isolation already work); or own a small in-tree Quinn adapter through h3's `i-implement-a-third-party-backend-and-opt-into-breaking-changes` trait feature, which is a much smaller burden than an h3 fork. In every case Runewarp must pin an unreleased git revision until upstream publishes a release past `h3 0.0.8` / `h3-quinn 0.0.10`; the released crates panic in this design.

## Remaining gaps (untested)

- The #226 malformed and edge mapping: 421 for wrong authority, 400 for bodies, trailers, or bad content-length, duplicate concurrent withdrawals, GOAWAY-rejected withdrawal, timers and deadlines.
- GOAWAY lowering through the internal `shutdown(0)` path (item 5), and Client-initiated GOAWAY.
- Public QUIC seam: H3 Datagram, Capsules, and Datagram routing with plain CONNECT/POST.
- Detecting idle-slot cancellation (pending `recv_data` per idle slot) and its cost at scale; slot pool sizing versus stream limits; load and many concurrent Visitors; CPU and allocation.
- A real PROXY v2 header and a real TLS ClientHello; backend relay.
- Fixing #361 in-tree or upstream; the workaround covers only peers that keep sending.
- Multiple runs and variance; Linux; production-shaped module boundary (#239).
- On 0.0.8: Experiments 3–6 were not completed because of the panic.
