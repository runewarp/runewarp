# Visitor capacity benchmark

This record implements the benchmark-first requirement of [#262](https://github.com/runewarp/runewarp/issues/262). The baseline starts at parent `8abeabad2ed0798c0efdc6b3c3f6e6292b455931`, with the 1,024-permit Client-instance budget and original Server admission limits. The harness commit contains no capacity changes.

## Method

Run `python3 -m venv target/visitor-capacity-venv`, `target/visitor-capacity-venv/bin/pip install psutil`, then `target/visitor-capacity-venv/bin/python scripts/benchmark-visitor-capacity --output target/capacity-baseline-v4`. The script builds the ignored library test in release mode and starts separate role processes. Each runtime has four Tokio worker threads. Every Server uses `ServerRuntime`; one Client process uses `ClientRuntime`, including its real address workers and shared instance budget. One connection means one Server process; two connections means two Server processes and one Client instance dialing their distinct localhost UDP ports. This avoids confusing two independent Client budgets with two connections sharing one budget. An independent echo Local backend and Visitor load process use TCP loopback. Manual generated test certificates, pinned Client identity and exclusive CA trust exercise the production handshake. Configs and logs stay under the selected output directory; generated private test keys are never committed.

The Visitor sends a rustls-generated valid ClientHello with SNI `app.example.test`, followed by its index and 256 known bytes. The backend echoes bytes without completing TLS, so this measures passthrough admission and forwarding, not TLS application handshake cost. TTFB starts before TCP connect and ends at the first echoed byte; the complete echo must match before counting establishment. All successful sockets remain open until the entire launch settles, then hold for five seconds and exchange another unique probe. Working concurrency counts successful byte-validated connections, and post-hold probes detect failures. There is no admission bypass, guard suppression, retry, fake carrier or replacement of the role runtimes.

The 10,000-Visitor one- and two-connection scenarios launch batches of 32, sleeping 10 ms between batches. The burst launches all 2,000 tasks without pacing. Each establishment has an eight-second outer deadline; the Server's five-second open deadline remains unchanged. A 256-Visitor scenario gives a comparable below-budget latency measurement. The throughput scenario establishes 256 Visitors identically, holds them, then exchanges and validates one MiB each concurrently, reporting 256 MiB divided by transfer time. The slow-reader scenario establishes 128 Visitors, then attempts four MiB uploads whose echoed responses remain unread, bounds each write at 15 seconds, and probes 32 unrelated Visitors on the same Tunnel connection after five seconds. Unrelated probes have five-second deadlines. No established product proxy timeout is introduced.

Process RSS, open fd counts and user plus system CPU time are sampled through psutil every 250 ms, sequentially across processes. These are sampled peaks and last-observed CPU time, not OS high-water marks or exact exit CPU totals. Short-lived setup may finish between samples, reported as unavailable. Sampling duration and errors are retained per process; sequential collection adds skew and can miss transient peaks. RSS histories let the slow-reader observation be checked over time; a bounded observation cannot establish a whole-process memory bound. Guard-reset counts increment directly at the no-permit guard branch before reset/stop; open-timeout counts increment directly on actual open deadline expiry. Admission counters count rejected work, independently of throttled warning output. All observation code compiles only in tests, with fixed counters and no per-Visitor metric allocation. The default suite excludes the ignored role test. The coordinator requests shutdown, then bounds cleanup with termination and kill fallbacks and waits for every child.

## Reference machine

The initial run used `daedalus.local`, macOS Darwin 27.0.0 arm64, an Apple M5 Pro virtual CPU with 10 logical CPUs and 17,179,869,184 bytes of memory. Shell `RLIMIT_NOFILE` was 1,048,575 soft and unlimited hard. Exact Rust version, Python psutil version, platform, source HEAD, command, binary and limits are retained in `environment.json`. This is a local VM, not a deployment or a cloud provisioned benchmark host.

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
