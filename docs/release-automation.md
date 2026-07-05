# Release automation

This document describes the repository automation for release preparation and publication. It covers the CI checks behind the supported distribution paths and the release workflow for signed tags, rehearsals, and real publication. For the maintainer procedure and recovery steps, see [`release-guide.md`](release-guide.md).

## CI coverage

The repository now uses three top-level workflows:

- `CI` validates source changes on pull requests and `main` pushes without publishing trusted artifacts.
- `Images` runs only after a successful `CI` workflow completion for a push to `main`, publishes the trusted `main` image lineage, and smoke tests that published lineage on both release architectures.
- `Release` promotes one already-published trusted `main` image lineage into stable Docker tags for a signed stable tag.

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

CI cache scope stays intentionally split by trust level:

- pull request runs share Rust dependency and Docker Buildx layer caches only with later runs of that same pull request
- trusted `main` pushes use their own Rust dependency and Docker Buildx layer caches
- release jobs do not read from the CI cache namespace

## Images workflow

The `Images` workflow is the trusted mainline publication stage. It:

1. triggers only from successful `CI` completion on a push to `main`
2. validates release metadata in `images` mode from the trusted commit checkout
3. publishes a multi-architecture Docker Hub lineage for that exact commit
4. tags that lineage as mutable `main` plus immutable bare 12-character commit tag
5. smoke tests the published lineage on `linux/amd64` and `linux/arm64`
6. runs both startup/version smoke and the full Docker example smoke against the published image on each release architecture

The immutable 12-character commit tag is the release handoff artifact. The later stable release does not rebuild Docker images; it promotes that exact already-smoke-tested lineage.

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
5. verifies that the tagged commit already has a successful `Images` workflow run, so release cannot promote a lineage whose publish-time smoke failed or never completed
6. renders the changelog-driven release notes preview
7. checks whether the crates.io version already exists; if it does, the real publish step is skipped, otherwise it publishes the crate
8. resolves the immutable bare 12-character commit-tag image lineage for the tagged release commit, verifies that the stable `X.Y.Z` Docker tag does not already exist, verifies that the trusted source lineage exists on Docker Hub, and probes that published image's `--version` output to confirm it still reports the tagged commit's baked-in 12-character SHA
9. promotes that exact already-published manifest to the public Docker tags `X.Y.Z`, `X.Y`, `X`, and `latest` without rebuilding either architecture
10. signs a newly promoted Docker manifest list keylessly with Sigstore
11. checks whether the GitHub Release already exists and then upserts the release title plus notes after the crates.io and Docker jobs succeed

The GitHub Release title is the bare semantic version string (for example `0.1.0`), not a prefixed product name.

Protected release tags are enforced as a GitHub-side prerequisite through repository rules or rulesets rather than re-checked at workflow runtime.

### Rehearsal mode

For manual `rehearsal`, the workflow:

1. runs the current workflow definition and scripts from `main`
2. requires a stable `release_tag` input that matches `Cargo.toml`
3. validates release metadata and release-notes rendering
4. checks whether the crates.io version already exists through the same repo-owned probe used by the real publish path
5. skips signed-tag and protected-tag enforcement because rehearsal happens before the irreversible tag is created
6. runs `cargo publish --dry-run` against the tagged release source tree
7. summarizes the workflow ref, release source ref, release commit, source image lineage, exact stable Docker tags, and rendered release notes that the real release would use
8. skips Docker Hub publication, Sigstore signing, and GitHub Release mutation

Rehearsal still writes into the trusted release cache scope for the selected `release_tag`, so the later real publish for that same tag can reuse the warmed Rust and Docker build state.

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

- `scripts/lib/runewarp/release_metadata.rb` owns stable release-tag parsing, main-image commit-tag derivation, and derived release metadata, and `scripts/resolve-release-metadata` is the GitHub Actions adapter that writes those results into the gate job environment and outputs
- `scripts/lib/runewarp/docker_hub.rb` owns Docker Hub tag URL resolution plus HTTP status lookups, `scripts/check-docker-hub-tag` is the workflow adapter for outputs, and `scripts/check-distribution docker-registry-tag-absent` reuses the same lookup seam for local distribution checks
- `scripts/lib/runewarp/release_docs.rb` owns changelog and version validation plus changelog-driven release-body rendering
- `scripts/lib/runewarp/release_gates.rb` owns rehearsal/tag gate validation
- `scripts/lib/runewarp/workflow_helpers.rb` owns the GitHub API, crates.io API, Docker manifest promotion, release-summary, and GitHub Release upsert helpers that the workflows shell out to through Ruby entry points
- multi-architecture Docker publication still lives in `Images` because runner selection, registry login, and trusted artifact publication are GitHub-hosted orchestration concerns
- post-publish distribution-path probes live primarily in `Images`, while `Release` re-probes the source image's version metadata to confirm the promoted lineage still matches the tagged commit

## Cache boundaries

The repository uses cache scope as part of the automation trust boundary:

- Rust CI caches are keyed separately for pull requests and trusted `main` pushes
- CI Docker builds use Buildx GHA cache scopes that are likewise split between pull requests and trusted `main` pushes
- release rehearsal and release publish share only the release-scoped caches for the selected stable tag
- release jobs do not consume PR artifacts and do not rebuild Docker images

## Release environment and secrets

The trusted `Images` publish job and the real `Release` publish jobs run in the GitHub `release` environment. The current workflow expects:

| Secret | Purpose |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | `cargo publish` authentication for crates.io |
| `DOCKER_USERNAME` | Docker Hub login username for trusted main-image publication and stable-tag promotion |
| `DOCKER_TOKEN` | Docker Hub access token for trusted main-image publication and stable-tag promotion |

For dress rehearsals, the workflow still rehearses the crate publish path, but it does not push to registries, promote Docker tags, sign images, or mutate the GitHub Release.

Before the first real tag release, the `release` environment should allow rehearsal dispatches, manual publish dispatches, and stable `v*` tags. The repo-owned gate still keeps real publish paths constrained to commits already reachable from `origin/main`.

## Docker release contract

- trusted main images are published for `linux/amd64` and `linux/arm64`
- the `Images` workflow smoke tests the published lineage on both native architectures
- published tags are `X.Y.Z`, `X.Y`, `X`, and `latest`
- trusted main tags are mutable `main` plus immutable bare 12-character commit tag
- the bare release tag `X.Y.Z` remains immutable; if it already exists, a manual publish rerun skips Docker publication instead of mutating that version
- stable public Docker tags are created by promoting the exact trusted commit-tag manifest
- `latest` only moves on stable releases
- the released manifest list is signed keylessly with Sigstore
- base images stay pinned by digest in `Dockerfile`; refreshing those digests is an intentional release-prep review step
