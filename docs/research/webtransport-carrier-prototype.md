# WebTransport Visitor carrier prototype

## Question and verdict

Can Core replace Client-preopened receive slots with one Server-opened WebTransport bidirectional stream per Visitor on the existing authenticated H3 Tunnel connection, if Runewarp owns the H3 source and its WebTransport client?

Yes. The throwaway implementation carries immediate Visitor bytes, preserves independent FINs and aborts, shares the connection with the event GET and a bodyless PUT, and bounds stream opens with QUIC credit. WebTransport was the better byte carrier in these loopback experiments. It removes idle Visitor requests and their replenishment, and the local delivery and burst numbers favor it. Neither carrier needs a per-Visitor Client acceptance round trip.

This does not yet establish that replacing receive slots is worth the whole-stack ownership. The enabling protocol patch is small, but Runewarp would own about 21.9k lines of H3, QPACK and extension code, a client and session lifecycle, security backports, and a test-suite port. The maintainer's willingness to own those removes an organizational objection; it does not remove those technical obligations. My recommendation is to keep the current production carrier until a separate decision explicitly chooses this ownership and funds the missing production checks. If Server-native streams are the desired long-term contract, this prototype makes that route credible. If the immediate goal is crates.io publication, vendoring the existing carrier is a separate, smaller decision.

This branch is evidence only. There is no runtime cutover, PR, merge, deployment, or change to any existing issue's decision.

## Revisions and boundaries

- Runewarp baseline: `f3e9a3aa599b3a85e820d2d329bb650fe194579f`, containing the H3 module from #247 and #249. The runtimes at this revision still use `runewarp/1`.
- Upstream source for all four modules: [`hyperium/h3@43745ad87e95b0c035ac9c547aad467303213425`](https://github.com/hyperium/h3/tree/43745ad87e95b0c035ac9c547aad467303213425). This retains the fixes absent from released `h3` 0.0.8 and `h3-quinn` 0.0.10.
- Prototype branch: [`dtcristo/prototype-webtransport-carrier`](https://github.com/runewarp/runewarp/tree/dtcristo/prototype-webtransport-carrier). Code lives in `src/vendor/`, `src/prototype_webtransport/`, and clearly named examples and scripts. Existing H3 code only gains vendored imports, crate-local visibility for reused helpers, and a unit-variant pattern adjustment. Neither production runtime uses WebTransport.
- Wire profile tested: the bounded bidi, Datagram and CLOSE subset of [draft-ietf-webtrans-http3-07](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-07), with max-sessions codepoint `0xc671706a`. This is an old draft profile, not a claim of current-draft or browser interoperability. The [current draft](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3) has advanced to draft-16 and has additional requirements.
- Environment: macOS `27.0.1` on a 10-CPU Apple M5 Pro virtual machine, aarch64, rustc `1.96.0`, Cargo `1.96.0`. All endpoints bind IPv4 loopback and use freshly generated, in-memory certificates. The existing Tunnel TLS constructors require pinned-identity mTLS, ALPN `h3`, and disable application 0-RTT. The fixture changes transport credit and enables a bounded Datagram receive buffer.

## Run

```sh
perl -e 'alarm 180; exec @ARGV' cargo run --release --example prototype_webtransport_carrier
perl -e 'alarm 120; exec @ARGV' cargo test --lib prototype_webtransport -- --nocapture
cargo fmt --check
perl -e 'alarm 180; exec @ARGV' cargo clippy --all-targets --all-features -- -D warnings
perl -e 'alarm 300; exec @ARGV' cargo test --all-features
perl -e 'alarm 180; exec @ARGV' ./scripts/audit-dependencies
perl -e 'alarm 180; exec @ARGV' cargo publish --dry-run --allow-dirty --locked
```

The example prints each assertion group and three sets of directional timing samples. Each async scenario has a five-second deadline; outer Perl alarms also bound compilation and the full command. There is no persisted certificate material, external backend, Docker dependency, or cloud resource.

For the warm-dependency build and executable comparison, run `python3 scripts/prototype_webtransport/build_comparison.py`. It extracts only named baseline files into a temporary directory, adds the same loopback fixture and slot timing loop, and compares that git-pinned executable against `examples/prototype_webtransport_timing.rs`. It does not switch branches or touch another worktree. It refreshes the current library source timestamp to force both package builds; dependencies remain cached. It leaves two timing binaries under `target/release/examples/`.

## Results matrix

| Experiment | Result | Evidence and limit |
| --- | --- | --- |
| 1. Vendoring shape | Partial | All four crates compile as modules inside the published package; dry-run publication passes; MIT notices are packaged; fmt, scoped Clippy and unsafe-code checks pass. Original upstream unit suites are retained but disabled pending a port. |
| 2. In-tree client | Pass | Bilateral SETTINGS, event gate, Extended CONNECT and bounded acceptance of Server bidi streams work. The client checks the `0x41` signal and full CONNECT Session ID before delivering a `TunnelStream`. This proves the minimal client, not full WebTransport conformance. |
| 3. Server and Visitor streams | Pass | Pinned mTLS identity is checked; Server sends the framing stand-in and buffered ClientHello stand-in immediately; independent FINs work in both orders; aborts reset in both directions; two-stream credit blocks a third open and recovers after release. |
| 4. Coexistence and lifecycle | Partial | Event GET, bodyless PUT/204 stand-in, session CLOSE in either direction, GOAWAY with active drain, connection loss, duplicate-session rejection and wrong-Session-ID rejection pass. Full withdrawal semantics, queued-request GOAWAY races and adversarial session cleanup are not established. |
| 5. Receive-slot comparison and Public QUIC seam | Partial | Real receive-slot module versus WT on loopback, idle counts, code/build/link costs, and Datagram exchange are recorded below. No production load, Client-wide multi-connection budget, or complete Public QUIC protocol is proved. |
| 6. Git-pin and security ownership | Pass | Source and publication experiments establish what vendoring changes for each named fix. Open security work remains unfixed in this throwaway branch and becomes Runewarp's responsibility. |

The full host suite passes with 733 tests and doctests, zero failures and one existing ignored test. This includes nine timed prototype scenarios and nine imported doctests. [Behavior and timing output](webtransport-carrier-prototype-evidence/behavior.log), [negative-to-positive evidence](webtransport-carrier-prototype-evidence/tdd.log), [packaging evidence](webtransport-carrier-prototype-evidence/packaging.log), [build evidence](webtransport-carrier-prototype-evidence/build.log), and [validation summaries](webtransport-carrier-prototype-evidence/checks.log) are checked in alongside this document.

## What the wire experiment does

Both endpoints advertise `ENABLE_CONNECT_PROTOCOL=1`, `H3_DATAGRAM=1`, and max WebTransport sessions `=1` using `0xc671706a`. QUIC Datagram support is enabled too. The settings patch uses the draft-07 max-sessions codepoint rather than sending the legacy enable/max pair. No Runewarp-specific SETTINGS marker is added.

The Client first completes the existing `GET /v1/tunnel/events` compatibility gate and validates the state version and generation encoding. It then sends Extended CONNECT with `:protocol=webtransport`, `:scheme=https`, the Server hostname as authority, and `/prototype/webtransport` as path. Both peers identify the session by CONNECT stream ID `4`, because the GET used stream `0`. Authentication comes from the connection's pinned Client identity; there is no bearer token or per-Visitor credential.

For a Visitor, the Server opens a bidi stream, emits the WebTransport signal and Session ID, then writes `PROXYv2+ClientHello` without waiting for a Client message. The timing payload appends an eight-byte assignment index. These are deliberate stand-ins, not valid PROXY v2 or TLS records. One stream carries one Visitor. The WT halves implement the existing `TunnelStream` traits, so the production write-behind, flush, independent half-close and reset-on-drop adapter is exercised rather than replaced.

The patched H3 client driver delivers raw extension streams through a bounded channel only after both endpoints' WebTransport, Datagram and Extended CONNECT support is established. Unnegotiated Server bidi streams still close H3 with `H3_STREAM_CREATION_ERROR`. Queue saturation resets/stops the rejected stream. The minimal client parses the signal and validates the live Session ID. A wrong ID rejects that stream while a later valid Visitor still works.

The Server's opener is detached from its H3 driver. The driver continues to accept ordinary HTTP requests while the session exists. A second session gets `429`, enforcing this prototype's one-session limit. A bodyless PUT receives bodyless `204`; this is only a coexistence stand-in. It does not implement placement withdrawal, delayed quiescence proof, retries, or terminal eligibility.

GOAWAY seals new Server placements, ends the event response, and stops Client request creation while an established Visitor drains. The existing application boundary check rejects request IDs at or above the first-unprocessed ID. This run verifies orderly observed-GOAWAY behavior; it does not independently establish every queued-request race or stock `accept()` shutdown-boundary interaction.

CLOSE uses the CONNECT DATA stream, a bounded Capsule decoder and FIN. Closing either side resets registered WT streams and prevents later placement while ordinary PUT remains usable. Closing the session is an abort for outstanding Visitor streams, so orderly shutdown drains Visitors before sending CLOSE. The decoder supports bounded unknown-capsule skipping, validates the CLOSE shape and UTF-8 reason, rejects data after CLOSE, and retains received bytes across select cancellation. It is not a complete general Capsule or current-draft lifecycle implementation. Buffered, partly classified streams and every close/open race still need production tests.

A separate scenario sends an RFC 9297 H3 Datagram in each direction on this session while a Visitor stream is active. The observed quarter-stream ID is `1`, identifying CONNECT stream `4`. This uses the vendored `h3-datagram` codec inside the prototype boundary and the existing Quinn connection. Session close uses reliable Capsules on that same CONNECT stream. There is no Public QUIC packet routing or Context ID implementation.

## Patch inventory and owned code

The [import script](../../scripts/prototype_webtransport/import_vendor.py) is the mechanical conversion. It rebases crate paths, exposes extension/backend internals, compiles Datagram support, disables optional dependency tracing, preserves Rust 2021 opaque-return captures inside the Rust 2024 host, adjusts one reference binding, makes VarInt construction safe, and fixes doctest package paths. It retains upstream unit-test source under inactive `cfg` gates. This last shortcut is an explicit reason vendoring readiness is Partial.

The [functional patch](../../scripts/prototype_webtransport/vendor.patch), measured after import and formatting, changes seven files with 124 added and 23 removed lines. It includes documentation and lint scoping. The core client driver accounts for 42 additions and two removals. The patch has no transport/TLS replacement, new QUIC frame, private transport parameter, or runtime-specific H3 fork outside `src/vendor/`.

| Patch | Purpose |
| --- | --- |
| `h3/client/builder.rs` | Advertise WT support and one session from the Client. |
| `h3/client/connection.rs` | Deliver negotiated Server bidi streams through a bounded channel; retain base-H3 rejection; add the resulting Send bound to driver doctests. |
| `h3/config.rs`, `h3/proto/frame.rs` | Use `0xc671706a`, infer WT support from a positive limit, expose the peer session limit, and stop sending the legacy enable flag. |
| `h3/webtransport/session_id.rs` | Use the full CONNECT stream ID instead of its index. The original conversion maps `4` to `1`; opening WT before every HTTP request would have hidden this bug. |
| `h3_webtransport/server.rs` | Return an error after rejecting invalid CONNECT, split driver/CONNECT/opener ownership, and remove the obsolete draft-02 response header. |
| `vendor/mod.rs` | Scope one upstream Clippy allowance and prohibit unsafe code. |

The Server-side split is about 45 added lines including its signature and opener. The upstream request validator fix is deliberately narrow; target, authority, gate and one-session policy remain in the prototype boundary. No changes are needed in h3-quinn or h3-datagram beyond import/format conversion. Application abort RESET uses the WT application-error-zero mapping, verified in both directions. The existing lost STOP_SENDING code behavior remains accepted, as in #246; it is a WT conformance gap, not a claim of exact error-code delivery.

| Source | Rust lines, including retained tests and comments |
| --- | ---: |
| Vendored h3 | 19,857 |
| Vendored h3-quinn | 712 |
| Vendored h3-datagram | 450 |
| Vendored h3-webtransport | 884 |
| Total vendored Rust | 21,903 |
| Prototype Rust, including fixture, scenarios, timings and module declarations | 1,268 |

About 641 of the new prototype lines are the client, Server driver, stream registry/adapter and CLOSE codec. The rest largely makes the experiment runnable and records behavior. These counts are gross source ownership, not an estimate that every prototype line should survive a production rewrite. The existing H3 module's receive-slot machinery remains present for comparison.

The source burden is larger than the functional patch. The module import makes QPACK, header decoding, flow control, error mapping, public extension internals, and test compatibility Runewarp-owned code. A small patch is not a small maintained stack.

## Packaging, licenses and lint burden

The baseline `cargo publish --dry-run` rejects the git-pinned dependency because it has no registry version requirement. Adding a registry version would strip the git source during packaging and resolve the released crate, losing the pinned fixes. It would not publish the pinned source.

A scratch package with a nested path-only child fails the same version requirement. Adding a version makes Cargo search crates.io for that child and fail because it is not published. This remains true even when the child sits beneath the parent package directory. Separate path crates are separate published packages, not bundled code. Cargo documents the dry-run package/rebuild process in [the publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html).

Embedding the four source trees as modules removes their Cargo dependency entries altogether. The prototype promotes three existing transitive dependencies to direct dependencies, adds no resolved packages, removes the two git packages, and dry-run packaging verifies the extracted Runewarp package successfully. A scratch Ruby process sets `PUBLISHING_PAUSE_REASON=nil` and the real `check-crates-io-publishing` command reports publishing enabled. The checked-in release switch remains paused; the experiment does not change release automation or claim a release is enabled on this branch.

Each copied module retains the complete upstream MIT notice, including copyright and permission text. The crate's package license expression is `Apache-2.0 AND MIT`; Runewarp's own `LICENSE` remains Apache-2.0. The package contains all four `LICENSE-MIT` files and the vendor README. This is source attribution needed by the copied licenses, not an assertion that the upstream code was relicensed.

Unmodified source inside Runewarp's lint boundary initially produces ten distinct Clippy errors: eight collapsible-if findings, a mechanical always-true cfg, and an existing unit-variant pattern exposed by changed visibility. The latter two are corrected. Only `clippy::collapsible_if` is allowed for the vendor directory; the local session-split signature separately allows `clippy::type_complexity`. Existing upstream allowances remain. Runewarp code outside the vendor directory receives no new lint exemption. Formatting the mechanically imported source changes 35 files, with 115 added and 135 removed lines.

Both crate and vendor roots use `forbid(unsafe_code)`. The sole upstream unsafe declaration, the unused `VarInt::from_u64_unchecked`, becomes a safe const function with a range assertion. No unsafe block or unsafe function remains in branch source. Vendored unit suites still need a port; the nine doctests compile and run after package-path fixes, a driver Send-bound update, and enabling Tokio's `io-std` dev feature.

The ordinary RustSec dependency audit passes, but the vendored stack no longer appears as four packages in Cargo.lock. That reduces automatic advisory visibility. A maintainer must monitor upstream and map security changes to these modules explicitly.

## Build and executable size

Warm dependencies, release profile, same machine, one sequential comparison with no concurrent Cargo build:

| Link target | Elapsed | User CPU | Executable bytes |
| --- | ---: | ---: | ---: |
| Git-pinned receive-slot timing executable | 5.08 s | 23.72 s | 5,182,816 |
| Vendored WT timing executable | 6.77 s | 26.62 s | 5,061,984 |
| WT minus slots | +1.69 s | +2.90 s | -120,832, about -2.33% |

The script forces each Runewarp library to rebuild while keeping dependency artifacts warm. This is not a cold-build result. The programs use the same fixture, payload and burst counts, but each includes its own carrier's connection/lifecycle code, so this measures the link targets rather than an isolated stream type. Repeats and differing cache states vary the times.

The ordinary CLI also measures 10,143,472 bytes at the baseline versus 10,141,600 on the prototype, a change of -1,872 bytes; cached package builds take 6.30 s and 7.10 s. These CLI figures are not useful evidence for a production carrier delta because neither runtime calls this H3 module yet. The carrier timing executables above are the relevant comparison.

## Directional latency and bursts

Three release-mode samples per count use real loopback Quinn connections. The receive-slot side calls the existing `ClientTunnelH3` and `ServerTunnelH3`, gives the keeper 100 ms to establish its 32 idle requests, and supplies a handler budget of 256. The WT side advertises 128 concurrent Server bidi streams. Both sides hold every measured stream until the batch is delivered, use the same 27-byte stand-in payload, and flush the existing `TunnelStream` adapter.

Placement is local elapsed time from starting an assignment through flushing its initial bytes. Delivery is elapsed time from that same start through Client read completion. Burst completion starts with the first assignment. There is no acknowledgment after each Visitor. Payload indices pair measurements even if receive-slot tasks deliver assignments out of order. Values below are minimum..maximum across the three samples, in microseconds.

| Visitors | Slot placement p95 | WT placement p95 | Slot delivery p50 | WT delivery p50 | Slot burst completion | WT burst completion |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 18..32 | 3..21 | 179..239 | 78..117 | 179..239 | 78..117 |
| 32 | 6..222 | 1..92 | 308..11,472 | 78..303 | 580..13,175 | 121..639 |
| 64 | 74..254 | 26..65 | 545..1,239 | 170..601 | 1,988..5,230 | 298..806 |
| 128 | 118..181 | 26..43 | 516..1,666 | 265..739 | 3,708..7,903 | 473..1,144 |

WT reduces local delivery work and the replenishment stalls visible in larger bursts. Local placement numbers overlap and sometimes favor slots. Both paths are already free of a per-Visitor acceptance RTT when availability exists. These results do not establish a WAN latency ratio, sustained throughput, CPU-per-byte, memory consumption, slow-reader fairness, or production scale. Sample order is fixed, the payload is tiny, and OS scheduling noise is visible. The full raw samples are retained, not reduced to a headline speedup.

| Concern | Receive slots | Server-opened WT |
| --- | --- | --- |
| Idle Visitor stream state at Server | Up to 32 held Client CONNECT request streams, plus common signaling | Zero idle Visitor streams; one persistent CONNECT session plus common signaling |
| Immediate burst availability | 32 idle slots, then Client replenishment within its handler budget | Advertised QUIC stream credit, 128 in the timing fixture; credit is permission, not 128 allocated idle streams |
| Bound when capacity is exhausted | Wait for a usable offered slot | `open_bi` waits for MAX_STREAMS credit; the two-stream test blocks a third open and recovers |
| Bytes for one Visitor | Per-slot response HEADERS, then DATA framing | WT signal and Session ID, then raw stream bytes |
| Capacity and handler accounting | Idle and assigned slots already hold Client-instance permits | Still needs a production reservation rule tying advertised credit to the shared Client-instance handler budget |
| Owned stack | Upstream pin plus existing Runewarp module | About 21.9k imported Rust lines, local patch and client/session maintenance |

Idle counts describe protocol objects, not an allocator measurement. QUIC credit alone cannot promise free handlers across several Tunnel connections. An adoption must reserve Client-wide start capacity before advertising credit, avoid allocating that same budget to multiple peers, and make withdrawal/placement atomic. Already advertised QUIC stream credit cannot simply be retracted. This prototype's single-connection fixture does not solve those production policies.

## Which upstream issues bite

Statuses were checked on 2026-10-24. The full-ID bug was found by this experiment in addition to the supplied blocker list.

| Issue | Observation and local response |
| --- | --- |
| [#349](https://github.com/hyperium/h3/issues/349), session close | Open. Bites directly: no usable send/receive session-close API. The in-tree bounded codec, session watcher and registry supply the exercised subset. Full close/open races and current-draft behavior remain work. |
| [#354](https://github.com/hyperium/h3/issues/354), invalid CONNECT | Open. Upstream returns a session after `400`. The local patch returns an error instead; target/authority validation happens before calling it. The normal boundary rejects invalid targets without transferring driver ownership. |
| [#355](https://github.com/hyperium/h3/issues/355), session limit | Open. Advertised limits are not enforced. The prototype's boundary enforces one session and tests a second request receiving `429`; no generic multi-session manager is implemented. |
| [#327](https://github.com/hyperium/h3/issues/327), connection ownership | Open. Bites when keeping ordinary H3 handling independent. The local `into_parts` plus session opener lets one driver retain ownership and process GET/PUT/GOAWAY. |
| [#374](https://github.com/hyperium/h3/pull/374), uni wakeup | Open. Not exercised because the prototype carries Visitors only on bidi streams. No patch is taken; adopting WT uni streams would require it or equivalent tests. |
| [#375](https://github.com/hyperium/h3/pull/375), protocol-selection response headers | Open. Not required for the fixed in-tree peer pair. There is no generic application-subprotocol negotiation; adding it later needs a response-header seam. |
| [#363](https://github.com/hyperium/h3/pull/363), RFC-track settings | Open. Bites directly. The prototype uses the max-sessions codepoint in draft-07. Unlike the proposed dual-dialect patch, this branch deliberately sends only that max-sessions dialect and does not claim browser compatibility. |
| Full Session ID conversion | Pinned upstream converts stream ID to its index. GET-before-CONNECT exposes `4 -> 1`. A one-line functional fix preserves full IDs; both endpoints and the wire classifier now assert session `4`. |
| [#361](https://github.com/hyperium/h3/issues/361), STOP_SENDING code | Existing accepted limitation remains. The prototype treats any stop/reset as termination, consistent with #246; it does not claim exact STOP_SENDING-code delivery. |

The original stock driver failure and full-ID failure are retained in the TDD evidence. Lifecycle tests also caught a prototype error from calling `finish()` twice; the session tasks now track whether FIN was sent. That was our integration bug, not a new upstream finding.

## What vendoring changes about the git pin

Vendoring the pinned revision preserves its fixes. Vendoring the old released sources would not. The reason to avoid the released versions remains correct; only the distribution and update mechanism changes.

| Fix or blocker | With the git pin | With modules in Runewarp |
| --- | --- | --- |
| [#330](https://github.com/hyperium/h3/issues/330), pending-read `stop_sending` panic | Fixed at the pin; released crates need a cancellation workaround | Fix retained. Runewarp owns regression coverage and future cancellation changes; copying source creates no new fix. |
| [#322](https://github.com/hyperium/h3/pull/322), standard CONNECT | Fixed at the pin; old releases do not provide the selected slot behavior reliably | Fix retained for the comparison and any plain-CONNECT use. WT uses Extended CONNECT but still depends on shared request validation. |
| [#360](https://github.com/hyperium/h3/pull/360), write cancellation and flush | Fixed upstream at the pin; the Runewarp adapter also preserves in-flight write ownership | Fix retained. H3 and WT framing still require cancellation discipline and explicit flush; vendoring does not make arbitrary mid-write cancellation safe. |
| [#365](https://github.com/hyperium/h3/pull/365), request tracking | Fixed at the pin | Fix retained. Ordinary GET, PUT and session CONNECT still need correct completion accounting even though Visitor bytes bypass H3 DATA. |
| [#344](https://github.com/hyperium/h3/pull/344), receive backpressure | Fixed at the pin | Fix retained for HTTP streams. Raw WT streams also need Quinn flow control and bounded dispatch; that does not prove process-wide memory or fairness. |
| Crates.io pause, [#369](https://github.com/hyperium/h3/issues/369) and Core [#248](https://github.com/runewarp/runewarp/pull/248) | Publishing waits for a registry release containing the needed fixes | Internal modules pass the packaging gate now. Enabling release automation would be separate approved work; future source upgrades no longer wait for a crate release. |
| [#366](https://github.com/hyperium/h3/pull/366), encoded frame limits | Open and absent from the pin | Still absent. It addresses buffered frame declarations and skipping unknown frames. Its review notes an ineffective default bound; copying it without addressing that would not establish a memory limit. |
| [#377](https://github.com/hyperium/h3/pull/377), decoded headers and frame ceiling | Open and absent from the pin | Still absent. Proposed finite defaults, fallible HeaderMap construction and frame buffering bounds need review/backport and regression tests owned by Runewarp. |
| [#378](https://github.com/hyperium/h3/pull/378), QPACK amplification | Open and absent from the pin | Still absent. Proposed finite decoded defaults and non-panicking HeaderMap conversion need review/backport. This is not a substitute for an encoded-frame intake bound. |

The prototype explicitly sets a 16 KiB decoded field-section limit on its H3 builders. That reduces decoded-header exposure in this fixture; it is not the complete security fix. Encoded HEADERS/control-frame buffering, fallible HeaderMap conversion under larger configurations, malicious peer behavior and fuzz coverage remain unproved. Required mTLS narrows exposure but does not make an authenticated peer's parser input safe.

Cargo update and RustSec scanning will no longer discover these source upgrades by package identity. Vendoring adds freedom to ship reviewed upstream fixes immediately, and responsibility to notice, review, port, test and document them. The open security PRs are alternatives with overlapping work; they should not be blindly stacked.

## Porting a future fix

Keep the upstream base and the local protocol patch distinct. The following commands operate only on a fresh scratch clone and temporary output:

```sh
git clone https://github.com/hyperium/h3 /tmp/runewarp-h3-upstream
git -C /tmp/runewarp-h3-upstream checkout 43745ad87e95b0c035ac9c547aad467303213425
python3 scripts/prototype_webtransport/import_vendor.py /tmp/runewarp-h3-upstream /tmp/runewarp-h3-old
rustfmt --edition 2024 /tmp/runewarp-h3-old/mod.rs
python3 scripts/prototype_webtransport/vendor_diff.py /tmp/runewarp-h3-upstream
# In the scratch clone, check out the reviewed upstream fix revision next.
# Pass its full SHA as argument 3 to import_vendor.py, with a different output directory.
# Format that output and diff it against /tmp/runewarp-h3-old before replaying vendor.patch.
```

`vendor_diff.py` regenerates the checked-in local patch and verifies exact replay against the normalized pin. It writes the patch file but not the vendored source. For a later upstream revision, review the normalized upstream diff, reconcile overlapping local patches, retain notices, update provenance and run the same integration, full-suite, lint, package and security checks. The script's optional revision argument permits this inspection without pretending a different HEAD is the original pin.

Before adoption, port the original upstream unit suites and establish a repeatable way to run them. Retaining their source under inactive cfg gates is a throwaway shortcut, not a maintenance strategy.

## Contract consequences and remaining decision

[#246](https://github.com/runewarp/runewarp/issues/246) selected plain-CONNECT receive slots. A WT adoption needs an explicit amendment selecting the extension, its draft/profile and session path, native stream-credit availability, Client-wide handler reservation, cancellation and withdrawal cleanup. The event GET gate can remain. [#239](https://github.com/runewarp/runewarp/issues/239) also explicitly selected an unmodified upstream module with no maintained fork, so owning this patched source is a new decision. Its later publishing comment chose to pause crates.io rather than change stack ownership. This experiment does not silently supersede either decision.

The surviving [#221](https://github.com/runewarp/runewarp/issues/221) invariants fit WT: mTLS once, one Visitor per stream, Server-authoritative placement, immediate initial bytes and no Client acceptance exchange. [#225](https://github.com/runewarp/runewarp/issues/225) subsequently replaced independent numeric capacity and re-placement with carrier-native availability and atomic terminal withdrawal. A WT implementation must still satisfy that newer contract. This stand-in PUT is not evidence that it does.

For [#175](https://github.com/runewarp/runewarp/issues/175), one WT session can technically carry reliable Visitor streams, H3 Datagrams and reliable Capsules on this H3 connection; the prototype demonstrates those mechanisms together. That does not select a Public QUIC carrier. Public QUIC would need its own activation, protocol/subprotocol, Context ID framing, routing, cleanup, admission and fairness decisions. Sharing a WT session would couple lifecycle and require demultiplexing packet associations and control Capsules. A separate narrow Extended CONNECT on the same H3 connection remains possible with the detached driver. The existing dormant seam need not commit to sharing a WT session.

The evidence changes “the stock client cannot do it” into “Runewarp can do it with a small core patch and an owned client.” It also changes “we must wait for upstream to publish” into “we can package source and port reviewed fixes ourselves.” It does not change the released code's defects, current security work, draft evolution, or the cost of maintaining that parser and extension implementation.

Stop here. The next step, if wanted, is a separate carrier/ownership decision and a production proof plan, not merging this throwaway code.
