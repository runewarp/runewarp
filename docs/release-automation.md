# Release automation

This document describes the current repository automation for release preparation and publication. It covers the CI contract that backs Runewarp's supported install surfaces and the release workflow that controls signed release tags, dry-run rehearsals, and real release-channel publication. For the maintainer-facing operating sequence and recovery guidance, see [`release-guide.md`](release-guide.md).

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
- `workflow_dispatch` with `mode` plus `release_tag`, where `mode=rehearsal` validates the current `main` candidate without publishing and `mode=publish` runs the current release automation against an existing stable tag

### Signed tag gate

For tag pushes and manual `publish`, the workflow:

1. validates release metadata against the selected release source tree
2. verifies that the tagged commit is already reachable from `origin/main`, so release tags cannot publish branch-only commits
3. verifies the SSH-signed tag against `.github/release-allowed-signers`
4. verifies that the tagged commit already has a successful aggregate `CI` check run
5. renders the changelog-driven release notes preview
6. checks whether the crates.io version already exists; if it does, the real publish step is skipped, otherwise it publishes the crate
7. checks whether the bare Docker release tag `X.Y.Z` already exists; if it does, the Docker publish and signing steps are skipped, otherwise it builds native `amd64` and `arm64` images separately, pushes them by digest, then publishes the public Docker tags only after both architectures succeed
8. signs a newly published Docker manifest list keylessly with Sigstore and publishes build provenance through the Docker release job
9. checks whether the GitHub Release already exists and then upserts the release title plus notes after the crates.io and Docker jobs succeed

The GitHub Release title is the bare semantic version string (for example `0.1.0`), not a prefixed product name.

Protected release tags are enforced as a GitHub-side prerequisite through repository rules or rulesets rather than re-checked at workflow runtime.

### Rehearsal mode

For manual `rehearsal`, the workflow:

1. runs the current workflow definition and scripts from `main`
2. requires a stable `release_tag` input that matches `Cargo.toml`
3. validates release metadata and release-notes rendering
4. skips signed-tag and protected-tag enforcement because rehearsal happens before the irreversible tag is created
5. runs `cargo publish --dry-run` against the tagged release source tree
6. builds native `amd64` and `arm64` Docker release images without pushing them
7. summarizes the workflow ref, release source ref, release commit, exact Docker tags, and rendered release notes that the real release would use
8. skips Docker Hub publication, Sigstore signing, and GitHub Release mutation

### Manual publish mode

For manual `publish`, the workflow:

1. runs the current workflow definition and scripts from `main`
2. checks out the selected existing `vX.Y.Z` tag as the release source tree
3. applies the same signed-tag, trusted-commit, and prior-green-`CI` checks as the tag-driven publish path
4. skips any already-published crates.io, Docker Hub, or GitHub release surface instead of mutating it
5. publishes only the still-missing crate or Docker surfaces for that tag
6. always refreshes the GitHub Release title and notes from the current workflow checkout on `main`, so release-note fixes can be replayed for an existing tag without rebuilding artifacts from a new commit

## Release job boundaries

The workflow keeps GitHub-specific orchestration and idempotent publish checks in YAML, while repo-owned scripts keep the release gate and release-notes rules:

- `scripts/validate-release-gates.sh` owns rehearsal/tag gate validation
- `scripts/validate-release-metadata.sh` owns changelog and version validation for both rehearsal and release mode
- `scripts/render-release-notes.sh` owns changelog-driven release-body rendering, including exact release-entry selection, validation of the requested entry's changelog subsection headings, and promotion of those subsection headings to release-note H2 headings
- release-time idempotency checks for crates.io, Docker Hub, and GitHub Releases live in the workflow because they are GitHub-hosted orchestration decisions rather than reusable local install-surface validation
- per-architecture Docker builds and manifest publication live in the workflow because runner selection, registry login, and digest promotion are GitHub-hosted orchestration concerns
- post-publish install-surface probes are enforced in `CI`, not repeated in the release workflow

## Release environment and secrets

Real publish jobs run in the GitHub `release` environment. The current workflow expects:

| Secret | Purpose |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | `cargo publish` authentication for crates.io |
| `DOCKER_USERNAME` | Docker Hub login username |
| `DOCKER_TOKEN` | Docker Hub access token |

For dress rehearsals, the workflow still rebuilds the crate and both Docker release images, but it does not push to registries, sign images, or mutate the GitHub Release.

Before the first real tag release, the `release` environment should allow rehearsal dispatches, manual publish dispatches, and stable `v*` tags, while the repo-owned gate keeps real publish paths constrained to commits already reachable from `origin/main`.

## Docker release contract

- release images are built for `linux/amd64` and `linux/arm64`
- the `linux/arm64` release build runs on GitHub's native `ubuntu-24.04-arm` runner instead of QEMU emulation
- published tags are `X.Y.Z`, `X.Y`, `X`, and `latest`
- the bare release tag `X.Y.Z` remains immutable; if it already exists, a manual publish rerun skips Docker publication instead of mutating that version
- public Docker tags are created from a manifest-merge step only after both architecture builds succeed
- `latest` only moves on stable releases
- the released manifest list is signed keylessly with Sigstore
- provenance is published as part of the Docker release job
- base images stay pinned by digest in `Dockerfile`; refreshing those digests is an intentional release-prep review step
