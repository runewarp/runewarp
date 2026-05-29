# Release automation

This document describes the current repository automation for release preparation and publication. It covers the CI contract that backs Runewarp's supported install surfaces and the release workflow that controls signed release tags, dry-run rehearsals, and real release-channel publication.

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
- `workflow_dispatch` with a `release_tag` input for non-publishing rehearsal on a checked-out commit that must already be reachable from `origin/main`

### Signed tag gate

For tag pushes, the workflow:

1. validates release metadata against the checked-out repository state
2. verifies that the tagged commit is already reachable from `origin/main`, so release tags cannot publish branch-only commits
3. verifies the SSH-signed tag against `.github/release-allowed-signers`
4. verifies that the tagged commit already has a successful aggregate `CI` check run
5. renders the changelog-driven release notes preview
6. verifies that the bare release image tag `X.Y.Z` does not already exist on Docker Hub, so a rerun cannot mutate a published version
7. publishes the multi-arch Docker Hub image set for the release version plus the stable aliases `X.Y`, `X`, and `latest`
8. signs the released Docker manifest list keylessly with Sigstore and publishes build provenance through the Docker release job
9. verifies the public Docker Hub install surface by pulling the version tag and checking `runewarp --version`
10. publishes the crate to crates.io
11. verifies the public crates.io install surface by installing the released version from crates.io with retries for registry propagation
12. creates the GitHub Release only after the Docker and crates.io release jobs succeed; reruns for the same version fail forward instead of mutating the existing release record

Protected release tags are enforced as a GitHub-side prerequisite through repository rules or rulesets rather than re-checked at workflow runtime.

### Rehearsal mode

For manual rehearsal, the workflow:

1. uses the dispatch target only when its checked-out commit is already reachable from `origin/main`; branch-only commits fail the gate
2. requires a stable `release_tag` input that matches `Cargo.toml`
3. validates release metadata and release-notes rendering
4. skips signed-tag and protected-tag enforcement because rehearsal happens before the irreversible tag is created
5. summarizes the exact Docker tags and release version that the real release would publish
6. skips Docker Hub publication, Sigstore signing, crates.io publication, and GitHub Release creation

## Release job boundaries

The workflow keeps GitHub-specific orchestration in YAML and keeps install-surface validation in repo-owned scripts:

- `scripts/validate-release-gates.sh` owns rehearsal/tag gate validation
- `scripts/render-release-notes.sh` owns changelog-driven release-body rendering
- `scripts/validate-install-surfaces.sh docker-registry-tag-absent` owns the Docker Hub preflight check that keeps the bare release tag immutable
- `scripts/validate-install-surfaces.sh registry-install` owns post-publish crates.io verification, including retrying until the registry surface is visible
- `scripts/validate-install-surfaces.sh docker-registry-image` owns post-publish Docker Hub verification, including retrying until the released image is pullable

## Release environment and secrets

Real publish jobs run in the GitHub `release` environment. The current workflow expects:

| Secret | Purpose |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | `cargo publish` authentication for crates.io |
| `DOCKER_USERNAME` | Docker Hub login username |
| `DOCKER_TOKEN` | Docker Hub access token |

For dress rehearsals, `workflow_dispatch` runs only the gate job and does not consume release secrets, but it still rejects candidates outside `origin/main`.

Before the first real tag release, the `release` environment should allow rehearsal dispatches and stable `v*` tags, while the repo-owned gate keeps both entry paths constrained to commits already reachable from `origin/main`.

## Docker release contract

- release images are built for `linux/amd64` and `linux/arm64`
- published tags are `X.Y.Z`, `X.Y`, `X`, and `latest`
- the bare release tag `X.Y.Z` must not exist before publish; if it already exists, the workflow fails and recovery happens with a new patch version
- `latest` only moves on stable releases
- the released manifest list is signed keylessly with Sigstore
- provenance is published as part of the Docker release job
- base images stay pinned by digest in `Dockerfile`; refreshing those digests is an intentional release-prep review step
