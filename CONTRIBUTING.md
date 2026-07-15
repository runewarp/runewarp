# Contributing

Runewarp welcomes focused changes to the open-source Client, Server, protocols, tooling, and documentation. Track requested work in [GitHub Issues](https://github.com/runewarp/runewarp/issues); pull requests are implementation and review surfaces, not feature-request substitutes.

## Before changing code

- read [`AGENTS.md`](AGENTS.md) for repository rules
- use [`CONTEXT.md`](CONTEXT.md) and [`docs/adr/`](docs/adr/) for canonical vocabulary and architectural decisions
- start with [`docs/architecture.md`](docs/architecture.md), then read the protocol, security, and configuration documents relevant to the change

## Validate changes

Run the full Rust checks before committing:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
./scripts/audit-dependencies
```

For repository automation changes, also run:

```bash
./scripts/test-automation
./scripts/lint-workflows
```

The dependency audit treats vulnerabilities and informational RustSec findings as failures. Any checked-in exception belongs under `[advisories].ignore` in `.cargo/audit.toml` with its advisory ID, rationale, owner, and removal condition; do not blanket-ignore advisory classes.

## Documentation and pull requests

- keep all documents except the roadmap evergreen and synchronized with implementation
- preserve the domain vocabulary in [`CONTEXT.md`](CONTEXT.md); record durable architectural trade-offs in [`docs/adr/`](docs/adr/)
- update `CHANGELOG.md` for user-facing changes, following Keep a Changelog and referencing the introducing PR; omit internal-only refactors
- keep commits focused and PR descriptions explicit about behavior, tests, and documentation

Repository workflow conventions are in [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md), [`docs/agents/triage-labels.md`](docs/agents/triage-labels.md), and [`docs/agents/domain.md`](docs/agents/domain.md). Maintainer publication procedures live in the [release guide](docs/release-guide.md); automation mechanics live in [release automation](docs/release-automation.md).
