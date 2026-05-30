# Release automation

This document describes the repository automation for release preparation and publication. It covers the CI checks behind the supported distribution paths and the release workflow for signed tags, rehearsals, and real publication. For the maintainer procedure and recovery steps, see [`release-guide.md`](release-guide.md).

## CI coverage

The `CI` workflow is the required aggregate check for normal changes. It currently validates:

- release metadata structure through `./scripts/validate-release-metadata ci`
- release metadata resolution, Docker Hub lookup, release gates, distribution checks, and workflow contracts through `./scripts/test-automation`
- Linux Cargo install from source through `./scripts/check-distribution cargo-install`
- macOS Cargo install from source through the same distribution-check script
- crate packaging readiness through `./scripts/check-distribution package-readiness`
- Rust formatting, Clippy, tests, and docs
- Docker image build plus `--version` startup through `./scripts/check-distribution docker-image`
- the end-to-end Docker example smoke test
- workflow syntax through `./scripts/lint-workflows`

These checks run on both pull requests and `main` pushes and roll up into one required `CI` status.

Local workflow edits can run `./scripts/lint-workflows` directly, and `./scripts/test-automation` exercises the repository-owned Ruby workflow helpers against the same public entry points used by CI.

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
7. checks whether the bare Docker release tag `X.Y.Z` already exists through the shared Docker Hub lookup seam; if it does, the Docker publish and signing steps are skipped, otherwise it builds native `amd64` and `arm64` images separately, pushes them by digest, then publishes the public Docker tags only after both architectures succeed
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

## Workflow boundaries

The workflow keeps GitHub-specific orchestration and publish-job boundaries in YAML. Repo-owned Ruby entry points keep the rules and reusable adapters:

- `scripts/lib/runewarp/release_metadata.rb` owns stable release-tag parsing plus derived release metadata, and `scripts/resolve-release-metadata` is the GitHub Actions adapter that writes those results into the gate job environment and outputs
- `scripts/lib/runewarp/docker_hub.rb` owns Docker Hub tag URL resolution plus HTTP status lookups, `scripts/check-docker-hub-tag` is the workflow adapter for outputs, and `scripts/check-distribution docker-registry-tag-absent` reuses the same lookup seam for local distribution checks
- `scripts/lib/runewarp/release_docs.rb` owns changelog and version validation plus changelog-driven release-body rendering
- `scripts/lib/runewarp/release_gates.rb` owns rehearsal/tag gate validation
- `scripts/lib/runewarp/workflow_helpers.rb` owns the GitHub API, crates.io API, Docker manifest merge, release-summary, and GitHub Release upsert helpers that the release workflow shells out to through Ruby entry points
- per-architecture Docker builds and manifest publication still live in the workflow because runner selection, registry login, and digest promotion are GitHub-hosted orchestration concerns
- post-publish distribution-path probes are enforced in `CI`, not repeated in the release workflow

## Release environment and secrets

Real publish jobs run in the GitHub `release` environment. The current workflow expects:

| Secret | Purpose |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | `cargo publish` authentication for crates.io |
| `DOCKER_USERNAME` | Docker Hub login username |
| `DOCKER_TOKEN` | Docker Hub access token |

For dress rehearsals, the workflow still rebuilds the crate and both Docker release images, but it does not push to registries, sign images, or mutate the GitHub Release.

Before the first real tag release, the `release` environment should allow rehearsal dispatches, manual publish dispatches, and stable `v*` tags. The repo-owned gate still keeps real publish paths constrained to commits already reachable from `origin/main`.

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
