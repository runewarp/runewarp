# Release automation

This document describes the current repository automation for release preparation. It covers the CI contract that backs Runewarp's supported install surfaces and the release-gate workflow that controls signed release tags and dry-run rehearsals.

## CI contract

The `CI` workflow is the required aggregate check for normal changes. It currently validates:

- release metadata structure through `scripts/validate-release-metadata.sh ci`
- Linux Cargo install from source through `scripts/validate-install-surfaces.sh cargo-install`
- macOS Cargo install from source through the same install-surface script
- crate packaging readiness through `scripts/validate-install-surfaces.sh package-readiness`
- Rust formatting, Clippy, tests, and docs
- Docker image build plus `--version` startup through `scripts/validate-install-surfaces.sh docker-image`
- the end-to-end Docker example smoke test
- workflow syntax with `actionlint`

These checks are unconditional across pull requests and `main` pushes and roll up into one required `CI` status.

## Release workflow

The `Release` workflow has two entry paths:

- pushing a stable `vX.Y.Z` tag for the real release gate
- `workflow_dispatch` with a `release_tag` input for non-publishing rehearsal on the selected ref

### Signed tag gate

For tag pushes, the workflow:

1. validates release metadata against the checked-out repository state
2. verifies the SSH-signed tag against `.github/release-allowed-signers`
3. verifies that the tagged commit already has a successful aggregate `CI` check run
4. renders the changelog-driven release notes preview

Protected release tags are enforced as a GitHub-side prerequisite through repository rules or rulesets rather than re-checked at workflow runtime.

### Rehearsal mode

For manual rehearsal, the workflow:

1. uses the selected ref from the dispatch target
2. requires a stable `release_tag` input that matches `Cargo.toml`
3. validates release metadata and release-notes rendering
4. skips signed-tag and protected-tag enforcement because rehearsal happens before the irreversible tag is created

The workflow does not publish to crates.io or Docker Hub yet. That distribution work is wired by later release slices.
