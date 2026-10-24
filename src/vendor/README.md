# Throwaway vendored HTTP/3 stack

This directory is prototype source, not a production stack decision. All four modules come from hyperium/h3 revision `43745ad87e95b0c035ac9c547aad467303213425`. Each module retains the upstream MIT copyright and permission notice in `LICENSE-MIT`. Runewarp's own code remains Apache-2.0; this prototype package declares `Apache-2.0 AND MIT` because it includes both.

The import script converts crate paths, feature gates, Rust 2021 return-type captures and one reference pattern for the Rust 2024 host. It turns the unused unchecked VarInt constructor into a safe, range-checked constructor. It retains upstream unit-test source under disabled `cfg` gates; those suites need a separate port before adoption. All nine upstream doctests run against the host package. Dependency tracing instrumentation is disabled, and Datagram support is always compiled.

Only `clippy::collapsible_if` is allowed at this directory's boundary. One local session-splitting signature allows `clippy::type_complexity`. Other upstream allowances remain as imported. No allow applies to Runewarp code outside this directory. The crate and this directory forbid unsafe code.

The functional patch is [vendor.patch](../../scripts/prototype_webtransport/vendor.patch), measured after mechanical import and formatting. See [the results](../../docs/research/webtransport-carrier-prototype.md) for replay instructions, limitations and ownership estimates. Do not copy this into a release without the recorded follow-up work.
