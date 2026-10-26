# Visitor capacity benchmark

This is a historical research and diagnostic record for [#262](https://github.com/runewarp/runewarp/issues/262), not high-limit or performance acceptance for the alpha release. Benchmarking and stress investigations are deferred. Saturated single-release recovery remains a known alpha availability limitation in [#267](https://github.com/runewarp/runewarp/issues/267); unexplained historical burst losses remain deferred under [#268](https://github.com/runewarp/runewarp/issues/268). The current release retains stock Quinn, the existing H3 pin and the held/zero/held workaround. No transport fix, reliable saturated recovery or resolution of all burst losses is claimed. The baseline starts at parent `8abeabad2ed0798c0efdc6b3c3f6e6292b455931`, with the 1,024-permit Client-instance budget and original Server admission limits. The harness commit contains no capacity changes.

## Method

Run `python3 -m venv target/visitor-capacity-venv`, `target/visitor-capacity-venv/bin/pip install psutil`, then `target/visitor-capacity-venv/bin/python scripts/benchmark-visitor-capacity --output target/capacity-baseline-v4`. The script builds the ignored library test in release mode and starts separate role processes. Each runtime has four Tokio worker threads. Every Server uses `ServerRuntime`; one Client process uses `ClientRuntime`, including its real address workers and shared instance budget. One connection means one Server process; two connections means two Server processes and one Client instance dialing their distinct localhost UDP ports. This avoids confusing two independent Client budgets with two connections sharing one budget. An independent echo Local backend and Visitor load process use TCP loopback. Manual generated test certificates, pinned Client identity and exclusive CA trust exercise the production handshake. Configs and logs stay under the selected output directory; generated private test keys are never committed.

The Visitor sends a rustls-generated valid ClientHello with SNI `app.example.test`, followed by its index and 256 known bytes. The backend echoes bytes without completing TLS, so this measures passthrough admission and forwarding, not TLS application handshake cost. TTFB starts before TCP connect and ends at the first echoed byte; the complete echo must match before counting establishment. All successful sockets remain open until the entire launch settles, then hold for five seconds and exchange another unique probe. Working concurrency counts successful byte-validated connections, and post-hold probes detect failures. There is no admission bypass, guard suppression, retry, fake carrier or replacement of the role runtimes.

The 10,000-Visitor one- and two-connection scenarios launch batches of 32, sleeping 10 ms between batches. The burst launches all 2,000 tasks without pacing. Each establishment has an eight-second outer deadline; the Server's five-second open deadline remains unchanged. A 256-Visitor scenario gives a comparable below-budget latency measurement. The throughput scenario establishes 256 Visitors identically, holds them, then exchanges and validates one MiB each concurrently, reporting 256 MiB divided by transfer time. The slow-reader scenario establishes 128 Visitors, then attempts four MiB uploads whose echoed responses remain unread, bounds each write at 15 seconds, and probes 32 unrelated Visitors on the same Tunnel connection after five seconds. Unrelated probes have five-second deadlines. No established product proxy timeout is introduced.

Process RSS, open fd counts and user plus system CPU time are sampled through psutil every 250 ms, sequentially across processes. These are sampled peaks and last-observed CPU time, not OS high-water marks or exact exit CPU totals. Short-lived setup may finish between samples, reported as unavailable. Sampling duration and errors are retained per process; sequential collection adds skew and can miss transient peaks. RSS histories let the slow-reader observation be checked over time; a bounded observation cannot establish a whole-process memory bound. Python/psutil is a bounded exception to the repository's Ruby automation convention. psutil provides maintained, portable per-process RSS, fd and CPU collection; reimplementing that collection through platform-specific Ruby subprocesses would add complexity and skew. The runner prints plain-text build/scenario/results sections for manual use and preserves machine-readable JSON artifacts. Portable metadata omits output/executable locations and records the binary SHA-256, source HEAD, tracked dirty status and product-diff SHA-256. Historical environment files retain relative binary names because their original binary hashes were not captured.

Guard-reset counts increment directly at the no-permit guard branch before reset/stop; open-timeout counts increment directly on actual open deadline expiry. Admission counters count rejected work, independently of throttled warning output. All observation code compiles only in tests, with fixed counters and no per-Visitor metric allocation. The default suite excludes the ignored role test. The coordinator requests shutdown, then bounds cleanup with termination and kill fallbacks and waits for every child.

## Reference machine

The initial run used a local macOS VM, macOS Darwin 27.0.0 arm64, an Apple M5 Pro virtual CPU with 10 logical CPUs and 17,179,869,184 bytes of memory. Shell `RLIMIT_NOFILE` was 1,048,575 soft and unlimited hard. Exact Rust version, Python psutil version, platform, source HEAD, command, binary and limits are retained in `environment.json`. This is a local VM, not a deployment or a cloud provisioned benchmark host.

## Baseline at 1,024

Captured before any limit changes. Raw [environment](visitor-capacity/baseline/environment.json), per-scenario summaries and complete sampled process histories live in `visitor-capacity/baseline/`. Original generated configs, runtime stdout and build output remain in `target/capacity-baseline-v4/`; TDD and validation logs are in `target/visitor-capacity-logs/`. Earlier launch-only attempts `capacity-baseline` through `capacity-baseline-v3` failed on fixture config/material or localhost address-family mismatches. The harness now binds the Tunnel and Client endpoint to localhost's actual first resolver result; it does not alter production DNS selection.

| Scenario | Working established | Working after hold or unrelated slow-reader probes | TTFB p50 / p99 ms | Actual guards | Open timeouts | Admission rejections |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| subcapacity | 256 / 256 | 256 | 3.620 / 6.164 | 0 | 0 | 0 |
| hold-one | 1,024 / 10,000 | 1,024 | 3.676 / 5.491 | 0 | 1024 | 7952 |
| burst | 1,024 / 2,000 | 1,024 | 87.575 / 105.129 | 0 | 336 | 640 |
| hold-two | 1,024 / 10,000 | 1,024 | 4.335 / 8.360 | 0 | 2048 | 6928 |
| throughput | 256 / 256 | 256 | 3.700 / 8.466 | 0 | 0 | 0 |
| slow-reader | 128 / 128 | 0 | 3.309 / 4.778 | 0 | 32 | 0 |

| Scenario | Role process | Sampled peak RSS MiB | Sampled peak open fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| subcapacity | setup-0 | 0.03 | 3 | 0.0003 | 1 |
| subcapacity | backend-0 | 10.03 | 266 | 0.0311 | 23 |
| subcapacity | server-0 | 20.05 | 267 | 0.0774 | 23 |
| subcapacity | client-0 | 21.34 | 268 | 0.1359 | 22 |
| subcapacity | load-0 | 9.17 | 265 | 0.0465 | 20 |
| hold-one | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-one | backend-0 | 16.72 | 1034 | 0.1485 | 45 |
| hold-one | server-0 | 113.02 | 2066 | 1.1655 | 45 |
| hold-one | client-0 | 45.56 | 1036 | 0.4709 | 45 |
| hold-one | load-0 | 19.80 | 2089 | 1.2379 | 42 |
| burst | setup-0 | unavailable | unavailable | unavailable | 0 |
| burst | backend-0 | 16.69 | 1034 | 0.1271 | 42 |
| burst | server-0 | 49.70 | 1371 | 0.3934 | 42 |
| burst | client-0 | 46.17 | 1036 | 0.3575 | 42 |
| burst | load-0 | 14.38 | 2009 | 0.1832 | 39 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 16.50 | 1034 | 0.0912 | 47 |
| hold-two | server-0 | 63.44 | 1547 | 0.6993 | 47 |
| hold-two | server-1 | 63.41 | 1549 | 0.6952 | 47 |
| hold-two | client-0 | 45.84 | 1037 | 0.4641 | 47 |
| hold-two | load-0 | 21.58 | 3113 | 1.4228 | 44 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 10.19 | 266 | 1.8820 | 33 |
| throughput | server-0 | 35.66 | 267 | 4.9470 | 33 |
| throughput | client-0 | 39.22 | 268 | 4.9887 | 33 |
| throughput | load-0 | 475.91 | 265 | 1.5568 | 30 |
| slow-reader | setup-0 | unavailable | unavailable | unavailable | 0 |
| slow-reader | backend-0 | 9.12 | 138 | 0.7982 | 61 |
| slow-reader | server-0 | 110.88 | 171 | 2.9539 | 61 |
| slow-reader | client-0 | 113.88 | 140 | 3.9509 | 62 |
| slow-reader | load-0 | 523.16 | 169 | 0.2737 | 59 |

The baseline 10,000-Visitor workloads hit the expected 1,024 aggregate budget. The two-connection case still has one budget, not two independent Client instances. The held successes survived their post-hold byte probe. Failed attempts remain failures in the record. Zero guard resets is measured directly, independently of budget-maintenance saturation warnings. Open timeouts are expected baseline failures. The 256 MiB transfer completed in 2.552 seconds, 100.3 MiB/s. Window conclusions await the after comparison; the slow-reader result is a bounded availability observation, not a fairness or whole-process memory guarantee.

## Loopback port isolation and after-run constraint

The first after-run, `target/capacity-after/`, established only 7,909 of 10,000 Visitors on one connection. The load process directly recorded 1,977 macOS `EADDRNOTAVAIL` connect errors and 114 early EOFs. Actual guard resets, open timeouts and admission rejections were all zero. The following burst established only ten Visitors; repeated scenarios inherited the same host's exhausted automatic port pool. This failed run is preserved, not counted as acceptance. Capacity was not raised again in response.

The machine's automatic TCP port range is 49,152 through 65,535, only 16,384 ports. Its TCP MSL is 15 seconds. The original single-host harness used IPv4 for both the Visitor sockets and backend sockets, requiring two automatic source ports per Visitor and retaining TIME_WAIT between scenarios. A bounded independent socket probe successfully held 10,000 IPv4 connections plus 10,000 IPv6 connections simultaneously, 40,000 local socket descriptors including both accepted ends, in 1.117 seconds. The probe log is `target/visitor-capacity-logs/ephemeral-probe.log`. No host sysctl or admission setting changed.

The corrected harness keeps Visitors on IPv4 and binds the echo backend on IPv6 loopback. It uses the same real Server and Client runtimes, valid ClientHello, byte checks, counts, concurrency and launch pacing. A 32-second cooldown before each scenario exceeds twice the observed MSL and occurs before role processes start. This separates two load-generator source-port pools that would naturally be on different hosts in a deployment. It neither weakens the workload nor bypasses production admission. The runner records `--cooldown-seconds`; use the default 32 seconds on this reference machine.

For a comparable second baseline, an archive of harness-first commit `b5db7cae2718c3db53357a82c158f4c6df426f73` in `target/capacity-old-source/` received only the updated test harness and coordinator. All product code and limits remained at that commit. The additional per-admission-scope counter is omitted from its output because the old observation branch did not record it. Run from that archived directory with `RUNEWARP_BENCH_SOURCE_HEAD=b5db7cae2718c3db53357a82c158f4c6df426f73 CARGO_TARGET_DIR=target target/visitor-capacity-venv/bin/python scripts/benchmark-visitor-capacity --output target/capacity-baseline-isolated-v2`. An earlier archive launch used the wrong working directory and was interrupted before valid measurement; `capacity-baseline-isolated` is excluded. An overlapping after launch was also interrupted during its initial cooldown, before any role process started. The valid after capture starts after the corrected baseline completes, in `target/capacity-after-isolated-v2/`.

The shell reports soft nofile 1,048,575 and unlimited hard, but `kern.maxfilesperproc` is 61,440. `rlimit` 0.11.0's safe helper respects that stricter macOS ceiling. Server startup consequently reports configured `[4096, 4096, 65536]` and effective `[3384, 3384, 54160]`, after the 512-descriptor reserve. Those are the actual admission limits used by the after benchmark. Client startup reports effective 16,384. The Server is deliberately not allowed to plan 73,728 Visitor sockets against a 61,440 kernel ceiling.

## Round 1 Visitor-loss diagnosis

A new unchanged workload capture, `target/round1-observe-02/`, lost two of 10,000 Visitors across two Tunnel connections. Both losses incremented `no_active_route` before stream opening; actual `open_errors`, guards, open timeouts and admission rejections were zero. The live pool selector read atomic active-stream counts twice, first to compute the minimum and then to find a member equal to that old minimum. Another Visitor could increment even a sole member between those reads, leaving no match and returning no active connection. This explains a real route-selection rejection without a Tunnel disconnection or transport-open error.

The regression injects that exact one-member count change into the selection algorithm. It returns `None` on the original two-pass algorithm and `Some(0)` after the fix. Selection now observes each member once in round-robin order and retains the least loaded observation, preserving ties and always selecting from a nonempty pool. Existing real-connection placement, tie, churn and admission tests remain. This inherited placement defect is fixed within #266 as required for #262; neither the parent branch nor the lower PR is edited.

The same diagnostic burst also recorded 56 backend-connect rejections, separate from the two route-selection failures. A later diagnostic after the placement fix held and revalidated all 10,000 Visitors across two connections, but its 2,000 burst recorded 117 per-source admission rejections and zero route/open/guard errors. These failures remain failures. No capacity, window, retry, pacing, hold duration or byte check is changed to hide them. Bounded test-only counters now distinguish all failed opens, route selection, admission and backend-connect classifications. Production open diagnostics include only fixed classes and numeric protocol codes, never peer reason text or transport debug internals.

## Configured-budget regression and known recovery limitation

The active runtime regression configures 256 Visitors through real role runtimes, byte-validates all 256 and holds them. Visitor 257 remains pending until the real five-second Server open deadline; an admitted Visitor still exchanges bytes afterward. It runs in a dedicated child test process and directly snapshots the actual guard counter before and after admission and the deadline, asserting zero. Static and Managed preparation separately prove that their instance semaphore uses the configured value. This admission regression does not prove one-completion recovery.

Round 1 reproduced the recovery failure at both transport and runtime boundaries. With the pinned Quinn dependency unchanged, budgets 8, 16 and 256 strand a replacement after one completed exchange, with active/idle counts 7/1, 15/1 and 255/1 and zero guards. Budgets 1 and 7 resume. The real runtime probe fills configured capacity 256, starts Visitor 257 while full, exchanges and validates bytes, half-closes one Visitor, observes EOF and drops it. Visitor 257 still fails to resume within two seconds, before the unchanged five-second open deadline. Red-capable sources and logs remain private under `target/visitor-capacity-logs/round1-*recovery*`.

The failure is inherited from the parent and is accepted for the alpha release under [#267](https://github.com/runewarp/runewarp/issues/267). Quinn's `StreamsState::stream_freed` can call `ensure_remote_streams` after the final permit update and zero-target flush. `queue_max_stream_id` then withholds a difference of one at a configured target of eight or more. Neither the pinned h3-quinn send wrapper nor the WebTransport wrapper exposes Quinn's transport completion. Quinn's public `stopped()` also reports peer STOP before RESET acknowledgment, so it would not cover every free boundary even if exposed. Application Drop alone cannot prove transport freedom.

A private dependency probe changes only quinn-proto 0.11.19's advertisement condition from `diff > concurrency / 8` to `diff > 0`. All five single-release transport probes and the real Visitor-257 recovery pass, the runtime probe in 0.45 seconds, with byte/FIN and zero-guard assertions. The override and its sources stay under `target/`; Cargo pins and lockfile are unchanged in the delivered tree. This historical predicate-only experiment covers those FIN/local-abort probes, not every abort ordering. It does not establish general recovery: peer RESET with unread receive Drop last can also free the final transport half without scheduling credit. No experimental dependency change or timer approximation is shipped.

A future transport fix must promptly schedule positive replacement credit at the actual free boundary, including the known-final-offset receive-stop path after peer RESET, without granting early or unbacked credit. The current decision is to retain stock dependencies and the application workaround and prefer an official Quinn release for a future fix. Private prototypes and failing probes remain evidence for [#267](https://github.com/runewarp/runewarp/issues/267); reliable single-release recovery and high-limit performance are outside the current alpha acceptance scope.

## Corrected before and after captures

These tables retain failed attempts and repeat runs. A successful repeat does not explain a prior early EOF. Each raw capture includes the command and portable invocation metadata, all per-role counts, sampled peak RSS/fds, last observed CPU time, sampling errors and process histories. CPU samples exclude any time after the last successful sample. Setup that finishes between samples is unavailable. No scenario requires forced child cleanup in these captures.

### baseline-isolated

Raw files are in [`visitor-capacity/baseline-isolated/`](visitor-capacity/baseline-isolated/). Local complete logs and generated configs are in `target/capacity-baseline-isolated-v2/`.

| Scenario | Validated established / attempted | Post-hold working or slow-reader probes | TTFB p50 / p99 ms | Actual guards | Open timeouts | Admission rejections |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| subcapacity | 256 / 256 | 256 | 2.279 / 2.867 | 0 | 0 | 0 |
| hold-one | 1,024 / 10,000 | 1,024 | 2.166 / 7.338 | 0 | 1024 | 7952 |
| burst | 1,024 / 2,000 | 1,024 | 80.157 / 98.812 | 0 | 326 | 650 |
| hold-two | 1,024 / 10,000 | 1,024 | 4.173 / 19.890 | 0 | 2048 | 6928 |
| throughput | 256 / 256 | 256 | 1.934 / 2.448 | 0 | 0 | 0 |
| slow-reader | 128 / 128 | 0 | 3.273 / 4.332 | 0 | 32 | 0 |

| Scenario | Role process | Sampled peak RSS MiB | Sampled peak open fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| subcapacity | setup-0 | 0.03 | 3 | 0.0005 | 1 |
| subcapacity | backend-0 | 10.17 | 266 | 0.0267 | 23 |
| subcapacity | server-0 | 20.25 | 267 | 0.0484 | 23 |
| subcapacity | client-0 | 21.53 | 268 | 0.0826 | 22 |
| subcapacity | load-0 | 8.95 | 265 | 0.0224 | 20 |
| hold-one | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-one | backend-0 | 16.67 | 1034 | 0.0765 | 44 |
| hold-one | server-0 | 113.30 | 2068 | 1.0850 | 45 |
| hold-one | client-0 | 45.70 | 1036 | 0.3851 | 45 |
| hold-one | load-0 | 19.77 | 2089 | 1.1573 | 42 |
| burst | setup-0 | unavailable | unavailable | unavailable | 0 |
| burst | backend-0 | 16.88 | 1034 | 0.1432 | 42 |
| burst | server-0 | 49.83 | 1361 | 0.3953 | 42 |
| burst | client-0 | 46.11 | 1036 | 0.3709 | 41 |
| burst | load-0 | 14.56 | 2009 | 0.1712 | 39 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 16.66 | 1034 | 0.1287 | 47 |
| hold-two | server-0 | 64.08 | 1551 | 0.8654 | 48 |
| hold-two | server-1 | 63.69 | 1549 | 0.7081 | 47 |
| hold-two | client-0 | 46.34 | 1037 | 0.5603 | 47 |
| hold-two | load-0 | 21.52 | 3113 | 1.3226 | 44 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 10.36 | 266 | 1.6549 | 32 |
| throughput | server-0 | 35.89 | 267 | 4.3381 | 32 |
| throughput | client-0 | 47.73 | 268 | 4.5742 | 31 |
| throughput | load-0 | 518.50 | 265 | 1.4173 | 30 |
| slow-reader | setup-0 | unavailable | unavailable | unavailable | 0 |
| slow-reader | backend-0 | 9.27 | 138 | 1.1890 | 62 |
| slow-reader | server-0 | 113.94 | 171 | 4.7171 | 62 |
| slow-reader | client-0 | 117.20 | 140 | 5.5525 | 61 |
| slow-reader | load-0 | 523.19 | 169 | 0.3237 | 59 |

The complete 256 MiB transfer took 2.438365 seconds, 104.99 MiB/s.

### after-port-exhaustion

Raw files are in [`visitor-capacity/after-port-exhaustion/`](visitor-capacity/after-port-exhaustion/). Local complete logs and generated configs are in `target/capacity-after/`.

| Scenario | Validated established / attempted | Post-hold working or slow-reader probes | TTFB p50 / p99 ms | Actual guards | Open timeouts | Admission rejections |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| subcapacity | 256 / 256 | 256 | 3.865 / 5.232 | 0 | 0 | 0 |
| hold-one | 7,909 / 10,000 | 7,909 | 3.840 / 18.776 | 0 | 0 | 0 |
| burst | 10 / 2,000 | 10 | 21.447 / 248.026 | 0 | 0 | 0 |
| hold-two | 2 / 10,000 | 2 | 8.648 / 8.648 | 0 | 0 | 0 |
| throughput | 0 / 256 | 0 | unavailable | 0 | 0 | 0 |
| slow-reader | 128 / 128 | 0 | 3.634 / 5.806 | 0 | 0 | 0 |

| Scenario | Role process | Sampled peak RSS MiB | Sampled peak open fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| subcapacity | setup-0 | 0.03 | 3 | 0.0002 | 1 |
| subcapacity | backend-0 | 10.05 | 266 | 0.0311 | 23 |
| subcapacity | server-0 | 20.20 | 267 | 0.0725 | 23 |
| subcapacity | client-0 | 21.48 | 268 | 0.1332 | 22 |
| subcapacity | load-0 | 9.19 | 265 | 0.0458 | 20 |
| hold-one | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-one | backend-0 | 74.98 | 7919 | 0.8580 | 46 |
| hold-one | server-0 | 227.36 | 7947 | 2.0602 | 46 |
| hold-one | client-0 | 259.48 | 7922 | 2.7605 | 47 |
| hold-one | load-0 | 24.20 | 7949 | 3.5593 | 44 |
| burst | setup-0 | unavailable | unavailable | unavailable | 0 |
| burst | backend-0 | 7.94 | 20 | 0.0175 | 24 |
| burst | server-0 | 14.44 | 36 | 0.0354 | 24 |
| burst | client-0 | 13.98 | 22 | 0.0859 | 23 |
| burst | load-0 | 11.02 | 40 | 0.6416 | 22 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 7.92 | 12 | 0.0166 | 38 |
| hold-two | server-0 | 14.50 | 14 | 0.0443 | 38 |
| hold-two | server-1 | 13.62 | 14 | 0.0208 | 38 |
| hold-two | client-0 | 14.08 | 15 | 0.1318 | 37 |
| hold-two | load-0 | 17.00 | 16 | 2.9972 | 36 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 7.64 | 10 | 0.0161 | 22 |
| throughput | server-0 | 13.72 | 12 | 0.0287 | 23 |
| throughput | client-0 | 13.61 | 13 | 0.0820 | 23 |
| throughput | load-0 | 9.11 | 13 | 0.1248 | 20 |
| slow-reader | setup-0 | unavailable | unavailable | unavailable | 0 |
| slow-reader | backend-0 | 9.44 | 170 | 1.3331 | 61 |
| slow-reader | server-0 | 113.41 | 171 | 4.4133 | 61 |
| slow-reader | client-0 | 112.61 | 172 | 5.4273 | 62 |
| slow-reader | load-0 | 523.06 | 169 | 0.3558 | 59 |

### after-isolated

Raw files are in [`visitor-capacity/after-isolated/`](visitor-capacity/after-isolated/). Local complete logs and generated configs are in `target/capacity-after-isolated-v2/`.

| Scenario | Validated established / attempted | Post-hold working or slow-reader probes | TTFB p50 / p99 ms | Actual guards | Open timeouts | Admission rejections |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| subcapacity | 256 / 256 | 256 | 2.280 / 3.469 | 0 | 0 | 0 |
| hold-one | 10,000 / 10,000 | 10,000 | 3.881 / 12.670 | 0 | 0 | 0 |
| burst | 1,999 / 2,000 | 1,999 | 104.070 / 148.924 | 0 | 0 | 0 |
| hold-two | 9,999 / 10,000 | 9,999 | 3.989 / 17.181 | 0 | 0 | 0 |
| throughput | 256 / 256 | 256 | 3.617 / 5.705 | 0 | 0 | 0 |
| slow-reader | 128 / 128 | 0 | 3.284 / 4.400 | 0 | 32 | 0 |

| Scenario | Role process | Sampled peak RSS MiB | Sampled peak open fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| subcapacity | setup-0 | 0.03 | 3 | 0.0011 | 1 |
| subcapacity | backend-0 | 10.34 | 266 | 0.0436 | 23 |
| subcapacity | server-0 | 20.42 | 267 | 0.0882 | 22 |
| subcapacity | client-0 | 21.83 | 268 | 0.1433 | 22 |
| subcapacity | load-0 | 9.05 | 265 | 0.0247 | 19 |
| hold-one | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-one | backend-0 | 92.70 | 10010 | 1.0857 | 41 |
| hold-one | server-0 | 280.41 | 10011 | 2.3663 | 41 |
| hold-one | client-0 | 323.22 | 10012 | 2.9861 | 41 |
| hold-one | load-0 | 26.02 | 10009 | 1.3683 | 39 |
| burst | setup-0 | unavailable | unavailable | unavailable | 0 |
| burst | backend-0 | 25.06 | 2009 | 0.1867 | 23 |
| burst | server-0 | 68.14 | 2010 | 0.4552 | 23 |
| burst | client-0 | 76.50 | 2011 | 0.4209 | 22 |
| burst | load-0 | 14.58 | 2009 | 0.1497 | 20 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 92.75 | 10009 | 0.9039 | 41 |
| hold-two | server-0 | 147.08 | 5011 | 1.3436 | 42 |
| hold-two | server-1 | 146.98 | 5010 | 1.3332 | 42 |
| hold-two | client-0 | 323.69 | 10012 | 2.7746 | 41 |
| hold-two | load-0 | 26.16 | 10008 | 1.3374 | 38 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 10.33 | 266 | 2.0546 | 33 |
| throughput | server-0 | 36.14 | 267 | 4.9341 | 33 |
| throughput | client-0 | 44.23 | 268 | 5.1929 | 33 |
| throughput | load-0 | 520.44 | 265 | 1.5910 | 31 |
| slow-reader | setup-0 | unavailable | unavailable | unavailable | 0 |
| slow-reader | backend-0 | 9.27 | 138 | 1.2883 | 61 |
| slow-reader | server-0 | 114.52 | 171 | 4.4749 | 61 |
| slow-reader | client-0 | 118.09 | 140 | 5.7826 | 61 |
| slow-reader | load-0 | 523.09 | 169 | 0.3148 | 59 |

The complete 256 MiB transfer took 2.683272 seconds, 95.41 MiB/s.

### after-diagnostic

Raw files are in [`visitor-capacity/after-diagnostic/`](visitor-capacity/after-diagnostic/). Local complete logs and generated configs are in `target/capacity-after-diagnostic/`.

| Scenario | Validated established / attempted | Post-hold working or slow-reader probes | TTFB p50 / p99 ms | Actual guards | Open timeouts | Admission rejections |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| burst | 2,000 / 2,000 | 2,000 | 110.196 / 152.551 | 0 | 0 | 0 |
| hold-two | 10,000 / 10,000 | 10,000 | 4.276 / 15.278 | 0 | 0 | 0 |
| throughput | 256 / 256 | 256 | 3.019 / 3.980 | 0 | 0 | 0 |

| Scenario | Role process | Sampled peak RSS MiB | Sampled peak open fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| burst | setup-0 | 0.03 | 3 | 0.0013 | 1 |
| burst | backend-0 | 25.11 | 2010 | 0.2284 | 24 |
| burst | server-0 | 67.52 | 2011 | 0.3551 | 22 |
| burst | client-0 | 76.72 | 2013 | 0.5237 | 23 |
| burst | load-0 | 14.53 | 2009 | 0.1843 | 20 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 92.78 | 10010 | 1.1234 | 42 |
| hold-two | server-0 | 147.11 | 5011 | 1.4343 | 42 |
| hold-two | server-1 | 147.06 | 5011 | 1.3681 | 41 |
| hold-two | client-0 | 323.73 | 10013 | 3.1109 | 42 |
| hold-two | load-0 | 26.22 | 10009 | 1.4438 | 39 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 10.36 | 266 | 2.1225 | 33 |
| throughput | server-0 | 35.39 | 267 | 4.7957 | 33 |
| throughput | client-0 | 48.20 | 268 | 5.1374 | 32 |
| throughput | load-0 | 513.34 | 265 | 1.5783 | 31 |

The complete 256 MiB transfer took 2.684876 seconds, 95.35 MiB/s.

### baseline-control

Raw files are in [`visitor-capacity/baseline-control/`](visitor-capacity/baseline-control/). Local complete logs and generated configs are in `target/capacity-baseline-control/`.

| Scenario | Validated established / attempted | Post-hold working or slow-reader probes | TTFB p50 / p99 ms | Actual guards | Open timeouts | Admission rejections |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| throughput | 256 / 256 | 256 | 3.557 / 4.893 | 0 | 0 | 0 |

| Scenario | Role process | Sampled peak RSS MiB | Sampled peak open fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| throughput | setup-0 | 0.03 | 3 | 0.0012 | 1 |
| throughput | backend-0 | 10.38 | 266 | 2.2003 | 34 |
| throughput | server-0 | 35.84 | 267 | 4.6357 | 32 |
| throughput | client-0 | 33.73 | 268 | 5.2875 | 33 |
| throughput | load-0 | 499.89 | 265 | 1.4403 | 30 |

The complete 256 MiB transfer took 2.743613 seconds, 93.31 MiB/s.

## Capacity and window decisions

The configured Client default is 16,384, with a file-config range of 256 through 1,048,576. Static and Managed instance preparation share this value and then apply Unix fd sizing once. The Server's fixed maxima become 65,536 active routed streams and 4,096 pending opens. Pending Visitors remain 4,096, per-source intake remains 256, and QUIC handshakes remain 256. The corrected 10,000-Visitor runs and the successful 2,000 burst recorded zero admission rejections, so there is no evidence to raise those other maxima. The actual Server limits on this machine are lower after fd sizing, as recorded above. There is no bypass in the harness and no further capacity increase followed the failed or slower runs.

The successful one-connection run held and revalidated all 10,000 Visitors, TTFB p50/p99 3.881/12.670 ms, with zero actual guard resets and open timeouts. The successful two-connection repeat also held and revalidated all 10,000 with one shared Client instance, p50/p99 4.276/15.278 ms, with zero guards and open timeouts. The successful burst repeat held and revalidated 2,000, p50/p99 110.196/152.551 ms. The earlier corrected burst and two-connection runs each lost one Visitor to an unexplained early EOF, 1,999/2,000 and 9,999/10,000 respectively. Their guard, open-timeout and admission counters were zero; their logs contain a Server route-unavailable event. A diagnostic repeat with a fixed maximum of 16 captured stream-open errors and a no-active-route counter did not reproduce those failures. Those repeats are evidence of complete workloads, not an explanation of the earlier failures or a guarantee against intermittent loss.

The initial corrected old-limit 256 MiB transfer took 2.438365 seconds, 104.99 MiB/s. Two new-limit transfers took 2.683272 and 2.684876 seconds, about 95.4 MiB/s, activating the regression stop condition. No further limit or window change was made. A final old-limit control then took 2.743613 seconds, 93.31 MiB/s, slower than either new-limit repeat. Old and new measurements overlap across the observed host variation; this is not evidence of a consistent capacity-change throughput regression, and no throughput improvement is claimed. The original pre-change IPv4 run took 2.551880 seconds. Commands, data and every role's sampled resources remain above rather than selecting only the fastest measurement.

Both receive windows remain unchanged: 64 MiB per connection and 1,250,000 bytes per stream. The successful 10,000 single-connection run sampled approximately 280 MiB Server RSS and 323 MiB Client RSS. In the corrected 128-slow-reader observations, the Server peaked at 113.9 MiB before and 114.5 MiB after, and the Client at 117.2 MiB before and 118.1 MiB after. All 32 unrelated probes failed at the actual Server open deadline in both cases. These bounded observations reproduce shared-window starvation and show no reason to increase its buffering budget. They do not establish per-Visitor isolation, signaling fairness, a whole-process memory bound, or behavior for arbitrarily longer or larger uploads. Proxy, stream/task, TLS, allocator and kernel TCP state remain additional costs. Constants document this retained-window rationale.

## Validation and reproducibility

The harness-first commit is `b5db7cae2718c3db53357a82c158f4c6df426f73`; it contains the initial baseline while Client capacity is still 1,024, pending opens 1,024 and active routed streams 4,096. Before that commit, both `cargo test` and `cargo test --all-features` passed 747 tests with two ignored, including the existing ignored test and the new opt-in role harness. `cargo fmt --check`, strict all-target/all-feature Clippy and `./scripts/audit-dependencies` passed. This preserves the benchmark-before-limit-change boundary independently of the later port-isolated control.

TDD logs under `target/visitor-capacity-logs/` preserve the ClientHello harness red/green, config default/parse/bounds red/green, Client and Server injected fit/clamp red/green, warning-once red/green, static/Managed configured-budget red/green, Server-limit red/green, and configured runtime wait test. The parsing red rejects the initially unknown key; bounds red accepts zero before validation; runtime red observes the old 1,024 budget instead of configured 512. The OS calculations cover fit, no raising of smaller limits, clamping below T and below the reserve, zero capacities and overflow-sized inputs. The runtime test holds 256 real working Visitors, observes the real open deadline for the excess Visitor and checks continued forwarding. The additional one-completion experiment described above remains a failed experiment, not a passing recovery claim.

`rlimit` 0.11.0 was the latest crates.io release when checked. Its [official safe API](https://docs.rs/rlimit/0.11.0/rlimit/) documents `Resource::NOFILE` and `increase_nofile_limit`; the implementation's macOS kernel-ceiling behavior was inspected in the downloaded crate source. The dependency is declared only for Unix. Runewarp contains no unsafe code for this adjustment, and non-Unix branches reference no `rlimit` API. No workflow file, cloud resource, deployment, Docker context or 1Password material is used by this work.

The after captures were run with the capacity implementation still uncommitted above harness-first HEAD `b5db7ca`, so their `environment.json` HEAD identifies the prior commit, not the whole dirty source tree. The subsequent capacity implementation commit contains the runtime used for those captures. Later differences are documentation, test-only bounded failure capture and the coordinator's sampling-registration ordering; no further production capacity or window value changed. Reproduce from the PR head using the checked-in runner; generated test material is recreated independently for each scenario.

Final implementation validation ran `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo test --all-features`, `./scripts/test-automation` and `./scripts/audit-dependencies`. The first final automation run exposed the public-script allowlist missing `benchmark-visitor-capacity`; that failure is preserved as `final-automation.log` and the allowlist was updated to include the new entry point. No workflow file or release mechanic changed.

The final pre-publication Rust suites each passed 757 tests with two ignored. Strict all-target/all-feature Clippy and fmt passed. Automation passed 85 runs and 562 assertions after adding the benchmark entry point to its allowlist. The dependency audit passed with 251 resolved crate packages. Logs are `commit-full-test.log`, `commit-all-features.log`, `commit-clippy.log`, `commit-automation.log` and `commit-audit.log` under `target/visitor-capacity-logs/`. This record does not claim independent review or remote CI results.

## Round 1 committed-source captures

Product source for all `round1-clean-*` captures is commit `285552ebba415547ae9b93cb5c566ac21b822e7a`. Every environment records tracked source clean and the SHA-256 of an empty product diff, plus a binary SHA-256. The later harness-only commit `51eb5b6593e4a5a69c51b5d1271ee2796d500aaa` adds compiled-source verification and freezes the measured executable; its separate final capture appears below. The evidence commit changes only documentation/data. Visitor runtime source remains unchanged after `285552e`. These captures include the placement/privacy fixes and the unchanged pinned-Quinn recovery defect. They are not full #262 acceptance.

The first capture runs every original scenario. Nine additional captures repeat the unchanged 2,000 burst and 10,000 two-connection workloads, giving ten committed-source runs of each. Two additional throughput controls quantify variation. IPv4 Visitor/IPv6 backend separation, four workers per role, 32-second cooldown, original pacing, five-second holds, byte validation and no retry remain unchanged. All failed Visitors and process samples are retained.

Early `round1-observe-*` captures are diagnostics above the original head with uncommitted observability/placement work, not clean-source acceptance. Their original generator did not record a product-diff hash, so their source cannot be reconstructed from HEAD metadata alone. `round1-fixed-diagnostic` records its actual product-diff hash. The first `round1-loss-observe-01` diagnostic reused the pre-fix binary through a shared Cargo target; its binary SHA-256 matches the original-head control, so its provenance is corrected to that original head and it is not treated as instrumented fixed-source evidence. The v2 attempt was rejected by an explicit stage-counter check before load. The valid v3 diagnostics use a separate build directory and verify stage fields before load. Early diagnostic open-error counts observe the session opener only; complete failed-open counts and backend-connect counters are available in the committed-source captures. Unrecorded backend counters are marked unavailable, never inferred as zero. Build-only failures `round1-observe-01`, `round1-observe-08` and `round1-placement-fixed-diagnostic` produced no valid load capture; their raw build failure logs remain private. No failed workload is excluded from the tables below.

| Capture | Scenario | Established / attempted | Working or slow probes | Launch failures | Route selection | Open errors | Guards | Open timeouts | Admission | Backend connect | TTFB p50 / p99 ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| [round1-observe-02](visitor-capacity/round1-observe-02/) | burst | 1,944 / 2,000 | 1,944 | 56 | 0 | 0 | 0 | 0 | 0 | unavailable | 108.865 / 150.712 |
| [round1-observe-02](visitor-capacity/round1-observe-02/) | hold-two | 9,998 / 10,000 | 9,998 | 2 | 2 | 0 | 0 | 0 | 0 | unavailable | 3.973 / 17.628 |
| [round1-observe-03](visitor-capacity/round1-observe-03/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 116.700 / 161.368 |
| [round1-observe-03](visitor-capacity/round1-observe-03/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 3.941 / 18.460 |
| [round1-observe-04](visitor-capacity/round1-observe-04/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 109.126 / 155.281 |
| [round1-observe-04](visitor-capacity/round1-observe-04/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 4.053 / 13.647 |
| [round1-observe-05](visitor-capacity/round1-observe-05/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 114.051 / 156.046 |
| [round1-observe-05](visitor-capacity/round1-observe-05/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 3.883 / 14.913 |
| [round1-observe-06](visitor-capacity/round1-observe-06/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 106.930 / 151.258 |
| [round1-observe-06](visitor-capacity/round1-observe-06/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 4.098 / 10.904 |
| [round1-observe-07](visitor-capacity/round1-observe-07/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 106.541 / 153.684 |
| [round1-observe-07](visitor-capacity/round1-observe-07/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | unavailable | 3.947 / 15.899 |
| [round1-fixed-diagnostic](visitor-capacity/round1-fixed-diagnostic/) | burst | 1,883 / 2,000 | 1,883 | 117 | 0 | 0 | 0 | 0 | 117 | 0 | 100.651 / 141.648 |
| [round1-fixed-diagnostic](visitor-capacity/round1-fixed-diagnostic/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.109 / 16.191 |
| [round1-clean-01](visitor-capacity/round1-clean-01/) | burst | 1,998 / 2,000 | 1,998 | 2 | 0 | 0 | 0 | 0 | 2 | 0 | 106.645 / 155.497 |
| [round1-clean-01](visitor-capacity/round1-clean-01/) | hold-one | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.893 / 17.937 |
| [round1-clean-01](visitor-capacity/round1-clean-01/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.004 / 14.865 |
| [round1-clean-01](visitor-capacity/round1-clean-01/) | slow-reader | 128 / 128 | 0 | 0 | 0 | 32 | 0 | 32 | 0 | 0 | 3.113 / 4.112 |
| [round1-clean-01](visitor-capacity/round1-clean-01/) | subcapacity | 256 / 256 | 256 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.556 / 4.863 |
| [round1-clean-01](visitor-capacity/round1-clean-01/) | throughput | 256 / 256 | 256 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.122 / 4.605 |
| [round1-clean-02](visitor-capacity/round1-clean-02/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 111.684 / 157.600 |
| [round1-clean-02](visitor-capacity/round1-clean-02/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.070 / 16.916 |
| [round1-clean-03](visitor-capacity/round1-clean-03/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 103.790 / 149.871 |
| [round1-clean-03](visitor-capacity/round1-clean-03/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.847 / 16.727 |
| [round1-clean-04](visitor-capacity/round1-clean-04/) | burst | 1,988 / 2,000 | 1,988 | 12 | 0 | 0 | 0 | 0 | 12 | 0 | 112.554 / 159.900 |
| [round1-clean-04](visitor-capacity/round1-clean-04/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.479 / 17.852 |
| [round1-clean-05](visitor-capacity/round1-clean-05/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 113.611 / 162.937 |
| [round1-clean-05](visitor-capacity/round1-clean-05/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.079 / 9.631 |
| [round1-clean-06](visitor-capacity/round1-clean-06/) | burst | 1,796 / 2,000 | 1,796 | 204 | 0 | 0 | 0 | 0 | 176 | 0 | 89.815 / 134.440 |
| [round1-clean-06](visitor-capacity/round1-clean-06/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.249 / 14.796 |
| [round1-clean-07](visitor-capacity/round1-clean-07/) | burst | 1,935 / 2,000 | 1,935 | 65 | 0 | 0 | 0 | 0 | 7 | 0 | 105.457 / 145.134 |
| [round1-clean-07](visitor-capacity/round1-clean-07/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.768 / 11.814 |
| [round1-clean-08](visitor-capacity/round1-clean-08/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 96.620 / 140.608 |
| [round1-clean-08](visitor-capacity/round1-clean-08/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.969 / 13.181 |
| [round1-clean-09](visitor-capacity/round1-clean-09/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 111.601 / 154.996 |
| [round1-clean-09](visitor-capacity/round1-clean-09/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.311 / 14.759 |
| [round1-clean-10](visitor-capacity/round1-clean-10/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 121.721 / 167.780 |
| [round1-clean-10](visitor-capacity/round1-clean-10/) | hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4.354 / 16.820 |
| [round1-clean-throughput-01](visitor-capacity/round1-clean-throughput-01/) | throughput | 256 / 256 | 256 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.863 / 5.213 |
| [round1-clean-throughput-02](visitor-capacity/round1-clean-throughput-02/) | throughput | 256 / 256 | 256 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3.098 / 4.582 |
| [round1-original-throughput-01](visitor-capacity/round1-original-throughput-01/) | throughput | 256 / 256 | 256 | 0 | 0 | unavailable | 0 | 0 | 0 | unavailable | 3.862 / 5.499 |
| [round1-original-throughput-02](visitor-capacity/round1-original-throughput-02/) | throughput | 256 / 256 | 256 | 0 | 0 | unavailable | 0 | 0 | 0 | unavailable | 2.703 / 5.212 |
| [round1-loss-observe-01](visitor-capacity/round1-loss-observe-01/) | burst | 1,999 / 2,000 | 1,999 | 1 | 1 | unavailable | 0 | 0 | 0 | unavailable | 109.172 / 162.945 |
| [round1-loss-observe-v3-01](visitor-capacity/round1-loss-observe-v3-01/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 107.323 / 148.614 |
| [round1-loss-observe-v3-02](visitor-capacity/round1-loss-observe-v3-02/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 104.459 / 151.309 |
| [round1-loss-observe-v3-03](visitor-capacity/round1-loss-observe-v3-03/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 113.933 / 158.235 |
| [round1-loss-observe-v3-04](visitor-capacity/round1-loss-observe-v3-04/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 110.082 / 156.955 |
| [round1-loss-observe-v3-05](visitor-capacity/round1-loss-observe-v3-05/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 107.373 / 152.787 |
| [round1-loss-pressure-01](visitor-capacity/round1-loss-pressure-01/) | burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 82.960 / 126.541 |

The `round1-original-throughput-*` controls use a source archive of the original PR head `09a09b84e676e9ae63bc11278f386430afd82e0f`, with no Rust changes and the committed coordinator copied in for portable metadata/manual output. Their source HEAD is an explicit archive-source override, not the surrounding worktree HEAD. The valid `round1-loss-observe-v3-*` and `round1-loss-pressure-*` captures use an archive of the fixed product source with bounded test-only stage counters, whose exact patch SHA-256 is recorded. They are diagnostic instrumentation and do not replace the ten clean-source repetitions.

Every capture directory contains environment metadata, complete summaries with failure classes and bounded first-error details, and per-role process histories with sampled peak RSS/fds, CPU, sample counts and cleanup outcomes. The following table summarizes every role in the first committed-source capture. The other process histories remain in their adjacent `*-processes.json` files.

| Scenario | Process | Peak RSS MiB | Peak fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| burst | setup-0 | unavailable | unavailable | unavailable | 0 |
| burst | backend-0 | 24.95 | 2008 | 0.2031 | 23 |
| burst | server-0 | 68.27 | 2009 | 0.5404 | 23 |
| burst | client-0 | 76.47 | 2010 | 0.4641 | 23 |
| burst | load-0 | 14.53 | 2009 | 0.1763 | 20 |
| hold-one | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-one | backend-0 | 92.67 | 10010 | 1.0632 | 41 |
| hold-one | server-0 | 280.47 | 10011 | 2.2810 | 41 |
| hold-one | client-0 | 323.03 | 10012 | 2.9517 | 41 |
| hold-one | load-0 | 26.00 | 10009 | 1.3594 | 38 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 92.62 | 10010 | 1.0430 | 41 |
| hold-two | server-0 | 147.00 | 5011 | 1.2839 | 41 |
| hold-two | server-1 | 146.86 | 5011 | 1.2957 | 40 |
| hold-two | client-0 | 323.91 | 10013 | 2.8483 | 41 |
| hold-two | load-0 | 26.05 | 10009 | 1.3432 | 38 |
| slow-reader | setup-0 | unavailable | unavailable | unavailable | 0 |
| slow-reader | backend-0 | 9.14 | 138 | 1.1145 | 61 |
| slow-reader | server-0 | 113.70 | 171 | 4.3402 | 61 |
| slow-reader | client-0 | 113.91 | 140 | 5.3963 | 61 |
| slow-reader | load-0 | 523.14 | 169 | 0.3552 | 59 |
| subcapacity | setup-0 | 0.03 | 3 | 0.0011 | 1 |
| subcapacity | backend-0 | 10.03 | 266 | 0.0316 | 23 |
| subcapacity | server-0 | 20.19 | 267 | 0.0664 | 22 |
| subcapacity | client-0 | 21.84 | 268 | 0.1768 | 23 |
| subcapacity | load-0 | 8.98 | 265 | 0.0417 | 20 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 10.22 | 266 | 1.6660 | 34 |
| throughput | server-0 | 35.64 | 267 | 5.3230 | 34 |
| throughput | client-0 | 42.84 | 268 | 5.3416 | 33 |
| throughput | load-0 | 501.36 | 265 | 1.9177 | 31 |

The round1-clean-01 throughput control validated 268,435,456 bytes in 2.971369 seconds, 86.16 MiB/s.

The round1-clean-throughput-01 throughput control validated 268,435,456 bytes in 2.495986 seconds, 102.56 MiB/s.

The round1-clean-throughput-02 throughput control validated 268,435,456 bytes in 2.562931 seconds, 99.89 MiB/s.

The round1-original-throughput-01 throughput control validated 268,435,456 bytes in 2.759128 seconds, 92.78 MiB/s.

The round1-original-throughput-02 throughput control validated 268,435,456 bytes in 2.599112 seconds, 98.50 MiB/s.


## Round 1 conclusions and current disposition

The one-pass selector fixes the demonstrated live-pool race, and the ten committed-source two-connection repetitions revalidate all 100,000 attempted Visitors with zero route-selection failures, failed opens, guards or open timeouts. The one-connection case also revalidates all 10,000. The ten bursts revalidate 19,717 of 20,000; all 283 failures remain in the record. Per-source admission counters account for 197, while 86 losses in two captures remain unaccounted for by the captured counters. These unexplained losses remain deferred under [#268](https://github.com/runewarp/runewarp/issues/268); the placement fix does not clear all possible Visitor loss, and these workloads are not current alpha acceptance gates.

Five instrumented repeats add bounded test-only counters at TCP acceptance, successful Server open, Client handoff and handler start. All five complete 2,000/2,000 with matching counts at every stage. One additional diagnostic adds four external CPU workers for at most 0.8 seconds each around launch; it also completes with matching counts. That diagnostic is explicitly separate from performance/acceptance measurements. These successful diagnostics do not explain the earlier 86 losses or justify attributing them to H3, the TCP listener, or the echo fixture. The exact instrumentation patch and raw system-stat snapshots remain private with the diagnostic sources and logs. No counter, cap, pacing, retry or assertion was adjusted to manufacture acceptance.

The fixed-source 256 MiB controls take 2.971369, 2.495986 and 2.562931 seconds. Adjacent original-head controls take 2.759128 and 2.599112 seconds, using an archive of the original Rust source and the portable coordinator. The distributions overlap, so this evidence establishes neither a consistent fix-related throughput regression nor an improvement. The first slower fixed-source result remains included. The slow-reader observation still times out all 32 unrelated probes at the actual open deadline, at sampled Server/Client RSS of 113.7/113.9 MiB. No receive window or capacity was raised, and no fairness or whole-process memory bound is claimed.

The earlier H3 accessor and retained-lease proposal is withdrawn. The recovery gaps are below H3, in Quinn stream-credit scheduling. No observer API, completion queue, fork or dependency pin change is shipped. [#267](https://github.com/runewarp/runewarp/issues/267) records the known alpha limitation and future transport-fix requirements; [#268](https://github.com/runewarp/runewarp/issues/268) retains the separate unexplained burst-loss investigation. Both investigations are deferred, with no additional benchmark or diagnostic campaign authorized by this record.

The tree-level privacy repair removes the private hostname and absolute machine paths from committed evidence, preserves all historical metrics/failures, and adds portable metadata generation with a focused absolute-output/binary-path regression. Old non-secret metadata remains in historical Git objects; no history rewrite is claimed. The source/failure boundary remains explicit: passing ordinary suites and successful workload repeats do not resolve the known Quinn recovery limitation or the 86 unexplained burst losses.

## Final verified-binary capture

Commit `51eb5b6593e4a5a69c51b5d1271ee2796d500aaa` changes only the benchmark harness/coordinator after the tested Visitor runtime fixes. The runner now rejects stale binaries, verifies a compiler-tracked Rust-source fingerprint and freezes the executable before starting measured roles. See [the provenance contract](visitor-capacity-provenance.md). Its real stale-binary regression rejects an original-head executable before any scenario starts. The public [compiled proof](visitor-capacity/round1-verified-final/build-provenance.json) matches the [environment fingerprint](visitor-capacity/round1-verified-final/environment.json); source is committed and clean, with an empty product diff. This capture reruns every scenario, including all three required workloads, without changing runtime limits, windows, pacing, holds or byte checks.

The ten earlier committed-source repetitions remain the failure-rate sample. This final successful capture does not erase their 86 unexplained losses or resolve the known single-release recovery limitation. Preflight provenance checking happens before measured role startup; its private log/executable stay under target.

| Scenario | Established / attempted | Working or slow probes | Launch failures | Route selection | Open errors | Guards | Open timeouts | Admission | TTFB p50 / p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| burst | 2,000 / 2,000 | 2,000 | 0 | 0 | 0 | 0 | 0 | 0 | 106.592 / 152.291 |
| hold-one | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 3.843 / 16.031 |
| hold-two | 10,000 / 10,000 | 10,000 | 0 | 0 | 0 | 0 | 0 | 0 | 4.208 / 14.838 |
| slow-reader | 128 / 128 | 0 | 0 | 0 | 32 | 0 | 32 | 0 | 3.533 / 5.385 |
| subcapacity | 256 / 256 | 256 | 0 | 0 | 0 | 0 | 0 | 0 | 3.802 / 5.695 |
| throughput | 256 / 256 | 256 | 0 | 0 | 0 | 0 | 0 | 0 | 3.887 / 5.887 |

| Scenario | Process | Peak RSS MiB | Peak fds | Last sampled CPU seconds | Samples |
| --- | --- | ---: | ---: | ---: | ---: |
| burst | setup-0 | unavailable | unavailable | unavailable | 0 |
| burst | backend-0 | 24.94 | 2010 | 0.2012 | 23 |
| burst | server-0 | 68.00 | 2011 | 0.5091 | 23 |
| burst | client-0 | 76.67 | 2012 | 0.4502 | 22 |
| burst | load-0 | 14.36 | 2009 | 0.1750 | 20 |
| hold-one | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-one | backend-0 | 92.62 | 10010 | 1.1206 | 41 |
| hold-one | server-0 | 280.48 | 10011 | 2.4374 | 41 |
| hold-one | client-0 | 323.39 | 10012 | 3.0628 | 41 |
| hold-one | load-0 | 25.97 | 10009 | 1.3735 | 38 |
| hold-two | setup-0 | unavailable | unavailable | unavailable | 0 |
| hold-two | backend-0 | 92.56 | 10010 | 1.1589 | 42 |
| hold-two | server-0 | 147.12 | 5011 | 1.4220 | 42 |
| hold-two | server-1 | 147.06 | 5011 | 1.4486 | 42 |
| hold-two | client-0 | 323.58 | 10013 | 3.1413 | 41 |
| hold-two | load-0 | 25.98 | 10009 | 1.4873 | 38 |
| slow-reader | setup-0 | unavailable | unavailable | unavailable | 0 |
| slow-reader | backend-0 | 9.12 | 138 | 1.1255 | 61 |
| slow-reader | server-0 | 113.44 | 171 | 4.4695 | 61 |
| slow-reader | client-0 | 120.94 | 140 | 5.5030 | 61 |
| slow-reader | load-0 | 523.12 | 169 | 0.3194 | 59 |
| subcapacity | setup-0 | unavailable | unavailable | unavailable | 0 |
| subcapacity | backend-0 | 10.17 | 266 | 0.0555 | 23 |
| subcapacity | server-0 | 20.39 | 267 | 0.1139 | 23 |
| subcapacity | client-0 | 21.62 | 268 | 0.1812 | 22 |
| subcapacity | load-0 | 8.94 | 265 | 0.0401 | 20 |
| throughput | setup-0 | unavailable | unavailable | unavailable | 0 |
| throughput | backend-0 | 10.19 | 266 | 2.5224 | 34 |
| throughput | server-0 | 36.36 | 267 | 5.3659 | 34 |
| throughput | client-0 | 37.78 | 268 | 5.7137 | 34 |
| throughput | load-0 | 493.61 | 265 | 1.5871 | 31 |

The final transfer validates 268,435,456 bytes in 2.915130 seconds. This is another overlapping-host control, not evidence that the harness-only provenance change alters Visitor throughput. All 32 slow-reader probes still time out; those expected limitation results remain distinct from the required held-load scenarios.

## Final validation

Before each implementation/harness commit and again before the evidence commit, both full Rust suites pass. The final runs cover 760 parent test cases plus the isolated guard-test child run, with two ignored tests. Strict all-target/all-feature Clippy, fmt, automation with 87 tests and 569 assertions, the 251-package dependency audit and git diff checking pass. Five bounded serial carrier-suite repetitions also pass 22 tests each. These scopes retain the existing full-budget, guard, concurrent completion, drop, loss and drain tests and do not certify single-release recovery, a known limitation tracked in [#267](https://github.com/runewarp/runewarp/issues/267).

The final source audit also reruns stronger private transport regressions at budgets 8 and 256. They assert exact request/echo bytes, FIN/EOF, actual zero guards, a waiting excess open, two-second single-completion recovery and replacement echo/FIN. Both fail on the pin at active/idle 7/1 and 255/1, and pass in 0.09 seconds under only the private zero-batching dependency experiment. The isolated real-runtime 256/257 case fails on the pin and passes in 0.44 seconds under that same experiment. Initial compilation mistakes in preparing those probes are retained separately and are not treated as behavior failures. No dependency override is shipped. The unsupported recovery probes remain private rather than becoming active or ignored alpha acceptance tests; the limitation is explicitly deferred under [#267](https://github.com/runewarp/runewarp/issues/267).

Privacy checking scans 204 research files and finds zero private hostname or absolute machine-path matches. All 62 historical JSON measurements still match the original PR head after comparing around only the two sanitized path-metadata fields. The final evidence adds 55 workload summaries with every role's sampled histories, including failed workloads and the corrected stale-binary capture. Source revisions, dirty/diff provenance, binary hashes, sampling limits, known starvation, unresolved losses and the known recovery limitation remain explicit. This record does not claim remote CI or independent review results.
