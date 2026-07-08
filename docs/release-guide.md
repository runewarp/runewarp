# Maintainer release guide

This guide covers the maintainer release path for stable Runewarp releases: the human workflow, the trust boundaries around publication, and the recovery rules for partial publication. For the automation contract enforced by the repository, see [`release-automation.md`](release-automation.md).

## Release flow

Runewarp treats a stable release as one sequence:

1. Open a **Release-prep PR** that prepares the versioned release metadata.
2. Merge that PR to `main` and wait for the aggregate `CI` check to finish green on the release commit.
3. Optionally run a **Release rehearsal** through `workflow_dispatch` to prove the candidate release metadata and gates without publishing.
4. Create and push an SSH-signed `vX.Y.Z` **Release tag** on that green `main` commit.
5. Let the `Release` workflow run the repo-owned Ruby release helpers from `main`, publish crates.io first, then promote the already-published trusted main-image lineage into the stable Docker tags, then finalize the GitHub Release.
6. If a trusted existing release tag needs a recovery rerun, use manual **Release publish** through `workflow_dispatch` with the same tag; already-published surfaces are skipped instead of being mutated.
7. Move `main` forward in a follow-up change to the next minor `-dev` version and reopen `CHANGELOG.md` with `Unreleased`.

Normal release work goes through the release-prep PR. Direct pushes to `main` remain an escape hatch for repository recovery, not a second release path.

## Prerequisites

Before cutting a stable release, make sure all of these are already true:

| Requirement | What must be true |
| --- | --- |
| Signing | Your local Git setup can create an SSH-signed release tag that verifies against `.github/release-allowed-signers`. |
| Release environment | The GitHub environment is named `release`. |
| Release secrets | The `release` environment contains `CARGO_REGISTRY_TOKEN`, `DOCKER_USERNAME`, and `DOCKER_TOKEN`, and those secrets are consumed by the trusted `Images` publish job plus the `Release` publish jobs. |
| Registry ownership | The maintainer account can publish `runewarp` on crates.io and `runewarp/runewarp` on Docker Hub. |
| Candidate commit | The release commit is already reachable from `origin/main`. |
| CI | The aggregate `CI` check is green on the release commit before the release tag is pushed. |
| Images | The `Images` workflow already published and smoke tested the immutable 12-character commit-tag image lineage for that release commit, and `Release` will re-check that lineage against the tagged commit before promotion. |

## Trust boundaries

The release workflow is intentionally narrow about what can cross from untrusted changes into privileged publish jobs.

| Surface | Current trust rule | Why it matters |
| --- | --- | --- |
| Fork and PR code | PR validation runs in `CI` on `pull_request`; it does not publish and does not unlock release secrets. | Untrusted contributions can exercise the normal contract without crossing into privileged automation. |
| Secrets | Real publication secrets exist only in the GitHub `release` environment and are consumed only by the publish jobs. | Ordinary CI jobs do not need registry credentials. |
| OIDC | Only the Docker publish job requests `id-token: write`, and only for the real tag-driven release path. | Sigstore signing stays scoped to the job that actually publishes images. |
| Caches | Rust and Docker caches are split between PR CI, trusted `main` CI, and trusted release scopes. Trusted `main` CI warms the shared trusted-`main` Docker cache that `Images` reuses for publish-time builds, while release rehearsal warms only the separate release Rust cache for the selected tag. Release publish still promotes trusted mainline images instead of consuming PR artifacts. | Cache poisoning and artifact handoff do not bridge the untrusted-to-trusted boundary. |
| Allowed actions | Workflow dependencies stay intentionally curated and third-party actions are pinned to full commit SHAs. | The workflow dependency surface does not drift through mutable action tags. |
| Release tags | Real publication starts only from an SSH-signed stable `vX.Y.Z` tag, and the workflow also verifies the tagged commit already passed `CI` and is reachable from `origin/main`. | A tag alone is not enough; it still has to point at a trusted, already-validated release commit. |
| Token permissions | Each workflow declares minimal job permissions instead of inheriting broad defaults. | A compromised job gets the smallest GitHub API surface that still lets it do its work. |

## Release-prep PR

The release-prep PR is where the release candidate becomes reviewable.

1. Update `Cargo.toml` and `Cargo.lock` to the target stable version.
2. Move curated, user-facing notes out of `Unreleased` into the versioned `CHANGELOG.md` entry, keeping "Keep a Changelog" categories and a PR reference on each retained bullet.
3. Review the release-facing docs and examples so they match the release claims.
4. Review `Dockerfile` base-image digests deliberately. Refresh them only when you intend to ship the newer base image in this release.
5. Merge the PR to `main` only after the aggregate `CI` check is green.

If the repo is already on a stable version because the post-release rollover has not happened yet, do the rollover first and then prepare the next stable release from the resulting `-dev` state.

## Release rehearsal

Use the `Release` workflow's manual form when you want a non-publishing rehearsal on the current `main` release candidate.

1. Make sure the current `main` release candidate is green.
2. Run the `Release` workflow manually with `mode` set to `rehearsal`.
3. Set `release_tag` to the stable tag you intend to cut, in `vX.Y.Z` form.
4. Confirm the workflow summary shows rehearsal mode, the workflow ref, the release source ref, the release commit, the trusted source image lineage, the exact stable Docker tags, and the rendered release notes preview.
5. Confirm the crates.io existence probe completed as part of the rehearsal run before the dry-run publish step.
6. Treat any rehearsal failure as a release-prep problem. Fix the candidate on `main`, let `CI` go green again, and rerun the rehearsal.

Rehearsal validates release metadata and gates, runs `cargo publish --dry-run`, and resolves the trusted source image lineage that real publish would promote, but it does not push Docker images, publish the crate, promote Docker tags, sign images, or create the GitHub Release.

## Real tag release

Once the candidate is green, cut the real stable release:

1. Check out the exact green `main` commit you want to publish.
2. Create an SSH-signed tag in `vX.Y.Z` form on that commit.
3. Push the tag.
4. Watch the `Release` workflow until the crates.io publish completes, the Docker tag promotion follows, and all publish jobs finish.
5. Confirm the public surfaces now agree on the released version:
   - Docker Hub has the released `X.Y.Z`, `X.Y`, `X`, and `latest` tags.
   - crates.io serves the released `runewarp` version.
   - GitHub shows the release record only after the publish jobs complete successfully.

The pushed stable tag remains the primary publish trigger. Manual dispatch also supports a real `publish` mode for rerunning the current release automation against an existing trusted tag.

## Manual publish recovery

Use manual publish when the tag already exists and you need the current release automation on `main` to finish or retry public release work for that exact version.

1. Make sure the target `vX.Y.Z` tag already exists and points at a trusted commit that is reachable from `origin/main`.
2. Run the `Release` workflow manually with `mode` set to `publish`.
3. Set `release_tag` to the existing stable tag you want to recover.
4. Watch the workflow summary to confirm it is in publish mode and targeting the expected tag.
5. Let the workflow skip any surface that is already published and complete any missing surface that is still absent.

Manual publish applies the same signed-tag, trusted-commit, prior-green-`CI`, successful-`Images`, and trusted-image-lineage checks as the normal tag-driven release path. The workflow definition, Ruby release helpers, and release notes come from the current `main`, while crate publication still targets the selected release tag's source tree and Docker promotion still targets that tag's previously published commit-lineage image after re-verifying its baked-in 12-character commit SHA. If the GitHub release already exists, the workflow updates its title and notes to match the current rendered changelog entry for that version.

## Recovery playbooks

### Rehearsal failed

If rehearsal fails, nothing public has been published yet.

1. Fix the release-prep problem on `main`.
2. Wait for `CI` to go green again.
3. Rerun the rehearsal with the same candidate tag value.

Typical causes are changelog structure mistakes, version/tag mismatch, or other release-gate failures.

### Tag gate failed before publication

If the pushed release tag fails in the gate stage before Docker Hub or crates.io publication begins, decide whether the problem is the candidate itself or only the automation around it.

1. If the release candidate metadata or trust requirements are wrong, fix the cause on `main`, wait for `CI` to go green again on the new release commit, and cut a fresh SSH-signed release tag for the intended version only after the corrected commit is ready.
2. If the release candidate is still correct but the workflow or scripts on `main` needed a recovery fix, rerun the `Release` workflow manually in `publish` mode against the existing tag after that fix lands on `main`.

The key distinction is that no public artifact has been published yet, so you can either repair the candidate and recut the tag or repair the automation and rerun publish against the same trusted tag.

### Publication failed after a public side effect

If Docker Hub or crates.io publication has already succeeded but the workflow still fails overall, first decide whether the already-published artifact is acceptable.

1. If the already-published crate or image is correct and the missing work is only the remaining release surfaces, fix the workflow on `main` if needed and rerun manual `publish` for the same tag. The workflow skips the surfaces that already exist and completes the missing ones.
2. If any already-published public artifact is itself wrong, treat the version as spent.
3. Fix the underlying problem on `main`.
4. Prepare a new patch release with a new version.
5. Rehearse that new version if needed, then cut a new signed stable tag.

The fail-forward rule still applies when a published artifact is wrong. The new manual publish path only changes the recovery story for incomplete releases whose already-published surfaces are still valid and can be left untouched.

## Post-release follow-up

After a stable release succeeds, move `main` forward explicitly:

1. Open a follow-up PR that bumps the crate to the next minor `-dev` version.
2. Reopen `CHANGELOG.md` with an `Unreleased` section at the top.
3. Keep new `Unreleased` notes limited to user-facing changes, grouped under the appropriate "Keep a Changelog" headings, with one PR reference on each bullet.
4. Merge that PR so future work lands against post-release development state instead of the already-published version.

This keeps the release history clean and makes the next release-prep PR start from the same documented pattern.
