# Maintainer release guide

This guide documents the maintainer-facing release path for stable Runewarp releases. It covers the human workflow, the workflow trust boundaries, and the recovery rules around partial publication. For the automation contract that the repository currently enforces, see [`release-automation.md`](release-automation.md).

## Canonical release model

Runewarp treats a stable release as one deliberate sequence:

1. Open a **Release-prep PR** that prepares the versioned release metadata.
2. Merge that PR to `main` and wait for the aggregate `CI` check to finish green on the release commit.
3. Optionally run a **Release rehearsal** through `workflow_dispatch` to prove the candidate release metadata and gates without publishing.
4. Create and push an SSH-signed `vX.Y.Z` **Release tag** on that green `main` commit.
5. Let the `Release` workflow publish Docker Hub and crates.io, then finalize the GitHub Release.
6. Move `main` forward in a follow-up change to the next minor `-dev` version and reopen `CHANGELOG.md` with `Unreleased`.

Normal release work flows through the release-prep PR. Direct pushes to `main` remain an escape hatch for repository recovery, not a second release path.

## Prerequisites

Before cutting a stable release, make sure all of these are already true:

| Requirement | What must be true |
| --- | --- |
| Signing | Your local Git setup can create an SSH-signed release tag that verifies against `.github/release-allowed-signers`. |
| Release environment | The GitHub environment is named `release`. |
| Release secrets | The `release` environment contains `CARGO_REGISTRY_TOKEN`, `DOCKER_USERNAME`, and `DOCKER_TOKEN`. |
| Registry ownership | The maintainer account can publish `runewarp` on crates.io and `runewarp/runewarp` on Docker Hub. |
| Candidate commit | The release commit is already reachable from `origin/main`. |
| CI | The aggregate `CI` check is green on the release commit before the release tag is pushed. |

## Workflow trust boundaries

The release workflow is intentionally narrow about what can cross from untrusted changes into privileged publish jobs.

| Surface | Current trust rule | Why it matters |
| --- | --- | --- |
| Fork and PR code | PR validation runs in `CI` on `pull_request`; it does not publish and does not unlock release secrets. | Untrusted contributions can exercise the normal contract without crossing into privileged automation. |
| Secrets | Real publication secrets exist only in the GitHub `release` environment and are consumed only by the publish jobs. | Ordinary CI jobs do not need registry credentials. |
| OIDC | Only the Docker publish job requests `id-token: write`, and only for the real tag-driven release path. | Sigstore signing stays scoped to the job that actually publishes images. |
| Caches | Rust CI caches are split between PR runs and trusted branch runs, and the release workflow rebuilds from the trusted repository state instead of consuming PR artifacts. | Cache poisoning and artifact handoff do not bridge the untrusted-to-trusted boundary. |
| Allowed actions | Workflow dependencies stay intentionally curated and third-party actions are pinned to full commit SHAs. | The workflow dependency surface does not drift through mutable action tags. |
| Release tags | Real publication starts only from an SSH-signed stable `vX.Y.Z` tag, and the workflow also verifies the tagged commit already passed `CI` and is reachable from `origin/main`. | A tag alone is not enough; it still has to point at a trusted, already-validated release commit. |
| Token permissions | Each workflow declares minimal job permissions instead of inheriting broad defaults. | A compromised job gets the smallest GitHub API surface that still lets it do its work. |

## Release-prep PR

The release-prep PR is the canonical place to make the release candidate reviewable.

1. Update `Cargo.toml` and `Cargo.lock` to the target stable version.
2. Move curated notes out of `Unreleased` into the versioned `CHANGELOG.md` entry.
3. Review the release-facing docs and examples so they match the release claims.
4. Review `Dockerfile` base-image digests deliberately. Refresh them only when you intend to ship the newer base image in this release.
5. Merge the PR to `main` only after the aggregate `CI` check is green.

If the repo is already on a stable version because the post-release rollover has not happened yet, do the rollover first and then prepare the next stable release from the resulting `-dev` state.

## Release rehearsal

Use the `Release` workflow's `workflow_dispatch` entry path when you want a non-publishing rehearsal on a real candidate commit.

1. Choose the green release candidate commit on `main`.
2. Run the `Release` workflow manually with `release_tag` set to the stable tag you intend to cut, in `vX.Y.Z` form.
3. Confirm the workflow summary shows rehearsal mode, the expected release version, and the exact Docker tags that the real release would publish.
4. Treat any rehearsal failure as a release-prep problem. Fix the candidate on `main`, let `CI` go green again, and rerun the rehearsal.

Rehearsal validates release metadata and gates, but it does not publish Docker images, publish the crate, sign images, or create the GitHub Release.

## Real tag release

Once the candidate is green, cut the real stable release:

1. Check out the exact green `main` commit you want to publish.
2. Create an SSH-signed tag in `vX.Y.Z` form on that commit.
3. Push the tag.
4. Watch the `Release` workflow until all publish jobs finish.
5. Confirm the public surfaces now agree on the released version:
   - Docker Hub has the released `X.Y.Z`, `X.Y`, `X`, and `latest` tags.
   - crates.io serves the released `runewarp` version.
   - GitHub shows the release record only after the publish jobs complete successfully.

The stable tag is the only real publish trigger. Manual dispatch stays rehearsal-only.

## Recovery playbooks

### Rehearsal failed

If rehearsal fails, nothing public has been published yet.

1. Fix the release-prep problem on `main`.
2. Wait for `CI` to go green again.
3. Rerun the rehearsal with the same candidate tag value.

Typical causes are changelog structure mistakes, version/tag mismatch, or other release-gate failures.

### Tag gate failed before publication

If the pushed release tag fails in the gate stage before Docker Hub or crates.io publication begins, treat it as a trusted-candidate problem rather than a public-release problem.

1. Fix the cause on `main`.
2. Wait for `CI` to go green again on the new release commit.
3. Cut a fresh SSH-signed release tag for the intended version only after the corrected commit is ready.

The key distinction is that no public artifact has been published yet, so you are still repairing the candidate rather than recovering from a shipped release.

### Publication failed after a public side effect

If Docker Hub or crates.io publication has already succeeded but the workflow still fails overall, do not mutate the published version in place.

1. Treat the version as spent.
2. Fix the underlying problem on `main`.
3. Prepare a new patch release with a new version.
4. Rehearse that new version if needed, then cut a new signed stable tag.

This is the fail-forward rule: once a public artifact exists for a version, recovery happens through the next patch release rather than by rewriting the existing release.

## Post-release follow-up

After a stable release succeeds, move `main` forward explicitly:

1. Open a follow-up PR that bumps the crate to the next minor `-dev` version.
2. Reopen `CHANGELOG.md` with an `Unreleased` section at the top.
3. Merge that PR so future work lands against post-release development state instead of the already-published version.

This keeps the release history clean and makes the next release-prep PR start from the same documented pattern.
