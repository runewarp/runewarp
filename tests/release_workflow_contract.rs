use std::fs;
use std::path::Path;

fn release_workflow() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".github")
            .join("workflows")
            .join("release.yml"),
    )
    .unwrap()
}

fn ci_workflow() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".github")
            .join("workflows")
            .join("ci.yml"),
    )
    .unwrap()
}

fn pre_commit_hook() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".githooks")
            .join("pre-commit"),
    )
    .unwrap()
}

#[test]
fn release_workflow_uses_shared_release_metadata_resolver() {
    let workflow = release_workflow();

    assert!(workflow.contains("IMAGE_REPOSITORY: docker.io/runewarp/runewarp"));
    assert!(workflow.contains("run: ./scripts/resolve-release-metadata.sh"));
    assert!(!workflow.contains("workflow_mode_input=\"${WORKFLOW_MODE:-}\""));
}

#[test]
fn release_workflow_checks_docker_release_status_before_arch_build_push() {
    let workflow = release_workflow();

    let guard = workflow
        .find("Check whether Docker release already exists")
        .expect("docker release status check should be present");
    let publish = workflow
        .find("Build and push amd64 release image by digest")
        .expect("docker publish step should be present");

    assert!(guard < publish);
    assert!(
        workflow
            .contains("run: ./scripts/check-docker-hub-tag.sh --image-ref \"$PRIMARY_IMAGE_REF\"")
    );
    assert!(!workflow.contains("https://hub.docker.com/v2/namespaces/runewarp/repositories/runewarp/tags/${RELEASE_VERSION}"));
}

#[test]
fn release_workflow_publishes_crate_before_split_docker_release() {
    let workflow = release_workflow();

    assert!(
        workflow.contains(
            "docker-release-amd64:\n    name: Publish Docker Hub amd64 release\n    needs:\n      - gate\n      - crate-release"
        ),
        "amd64 docker release should depend on the completed crates.io release"
    );
    assert!(
        workflow.contains(
            "docker-release-arm64:\n    name: Publish Docker Hub arm64 release\n    needs:\n      - gate\n      - crate-release"
        ),
        "arm64 docker release should depend on the completed crates.io release"
    );
}

#[test]
fn release_workflow_upserts_github_release_notes_with_version_title() {
    let workflow = release_workflow();

    assert!(workflow.contains("gh release view"));
    assert!(workflow.contains("gh release create"));
    assert!(workflow.contains("gh release edit"));
    assert!(
        workflow
            .contains("GITHUB_RELEASE_EXISTS: ${{ steps.github-release-status.outputs.exists }}")
    );
    assert!(workflow.contains("if [[ \"$GITHUB_RELEASE_EXISTS\" == \"true\" ]]; then"));
    assert!(workflow.contains("--title \"$RELEASE_VERSION\""));
    assert!(!workflow.contains("--title \"Runewarp $RELEASE_VERSION\""));
}

#[test]
fn pinned_workflow_actions_include_inline_version_comments() {
    for (workflow_name, workflow) in [
        ("ci.yml", ci_workflow()),
        ("release.yml", release_workflow()),
    ] {
        for line in workflow.lines().filter(|line| line.contains("uses: ")) {
            if line.contains('@') {
                assert!(
                    line.contains(" # "),
                    "{workflow_name} pinned action should include an inline version comment: {line}"
                );
            }
        }
    }
}

#[test]
fn ci_contract_runs_docker_hub_shell_seam() {
    let workflow = ci_workflow();

    assert!(workflow.contains("./scripts/test-docker-hub-tag.sh"));
}

#[test]
fn ci_workflow_uses_shared_workflow_lint_script() {
    let workflow = ci_workflow();

    assert!(workflow.contains("run: ./scripts/lint-workflows.sh"));
    assert!(workflow.contains("./scripts/test-lint-workflows.sh"));
    assert!(!workflow.contains("run: actionlint -color"));
    assert!(!workflow.contains("Install actionlint"));
}

#[test]
fn release_workflow_uses_safe_printf_for_hyphen_prefixed_summary_lines() {
    let workflow = release_workflow();

    assert!(workflow.contains("printf -- '- Mode: %s\\n'"));
}

#[test]
fn release_workflow_summary_reports_workflow_and_release_source_details_and_notes_preview() {
    let workflow = release_workflow();

    assert!(workflow.contains("printf -- \"- Workflow ref: \\`%s\\`\\n\" \"$GITHUB_REF\""));
    assert!(
        workflow
            .contains("printf -- \"- Release source ref: \\`%s\\`\\n\" \"$RELEASE_SOURCE_REF\"")
    );
    assert!(
        workflow.contains("RELEASE_COMMIT: ${{ steps.release-source.outputs.release_commit }}")
    );
    assert!(workflow.contains("printf -- \"- Release commit: \\`%s\\`\\n\" \"$RELEASE_COMMIT\""));
    assert!(!workflow.contains("${tag#${IMAGE_REPOSITORY}:}"));
    assert!(workflow.contains("cat /tmp/release-notes.md >> \"$GITHUB_STEP_SUMMARY\""));
    assert!(!workflow.contains("Publish status:"));
}

#[test]
fn release_workflow_renders_release_notes_from_workflow_checkout() {
    let workflow = release_workflow();

    assert!(
        workflow
            .matches("./scripts/render-release-notes.sh")
            .count()
            >= 2
    );
    assert!(!workflow.contains("./scripts/render-release-notes.sh --repo-root release-source"));
    assert!(
        workflow.contains("run: ./scripts/render-release-notes.sh --version \"$RELEASE_VERSION\" > /tmp/release-notes.md")
    );
    assert!(!workflow.contains(
        "run: ./scripts/render-release-notes.sh --version \"${{ needs.gate.outputs.release_version }}\" > /tmp/release-notes.md"
    ));
}

#[test]
fn release_workflow_dispatch_exposes_mode_and_release_tag_inputs() {
    let workflow = release_workflow();

    assert!(workflow.contains("workflow_dispatch:"));
    assert!(workflow.contains("mode:"));
    assert!(workflow.contains("options:\n          - rehearsal\n          - publish"));
    assert!(workflow.contains("release_tag:"));
    assert!(workflow.contains("vX.Y.Z"));
}

#[test]
fn release_workflow_manual_publish_path_still_runs_crate_then_docker_then_github_release() {
    let workflow = release_workflow();

    assert!(workflow.contains("crate-release:\n    name: Publish crates.io release"));
    assert!(workflow.contains(
        "docker-release-manifest:\n    name: Publish Docker Hub release manifest\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - docker-release-amd64\n      - docker-release-arm64"
    ));
    assert!(workflow.contains(
        "github-release:\n    name: Finalize GitHub release\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - crate-release\n      - docker-release-manifest"
    ));
}

#[test]
fn release_workflow_skips_already_published_surfaces_and_drops_post_publish_probes() {
    let workflow = release_workflow();

    assert!(workflow.contains("Check whether crates.io version already exists"));
    assert!(
        workflow
            .contains("cargo publish --dry-run --locked --manifest-path release-source/Cargo.toml")
    );
    assert!(
        workflow
            .contains("if: github.event_name != 'workflow_dispatch' || inputs.mode == 'publish'")
    );
    assert!(workflow.contains("Check whether Docker release already exists"));
    assert!(workflow.contains("push-by-digest=true"));
    assert!(workflow.contains("docker buildx imagetools create"));
    assert!(workflow.contains("Check whether GitHub release already exists"));
    assert!(!workflow.contains("Verify published crate install surface"));
    assert!(!workflow.contains("Verify published Docker image"));
}

#[test]
fn release_workflow_uses_tagged_release_source_for_publish_work_while_dispatch_runs_from_main() {
    let workflow = release_workflow();

    assert!(workflow.contains(
        "ref: ${{ github.event_name == 'workflow_dispatch' && 'refs/heads/main' || github.ref }}"
    ));
    assert!(workflow.contains("path: release-source"));
    assert!(workflow.contains("ref: ${{ needs.gate.outputs.release_source_ref }}"));
    assert!(workflow.contains("cargo publish --locked --manifest-path release-source/Cargo.toml"));
    assert!(workflow.contains("context: ./release-source"));
    assert!(workflow.contains("file: ./release-source/Dockerfile"));
}

#[test]
fn release_workflow_rehearses_crate_and_native_multi_arch_docker_builds_without_push() {
    let workflow = release_workflow();

    assert!(
        workflow
            .contains("cargo publish --dry-run --locked --manifest-path release-source/Cargo.toml")
    );
    assert!(workflow.contains("docker-release-amd64:\n    name: Publish Docker Hub amd64 release"));
    assert!(workflow.contains("runs-on: ubuntu-latest"));
    assert!(workflow.contains("docker-release-arm64:\n    name: Publish Docker Hub arm64 release"));
    assert!(workflow.contains("runs-on: ubuntu-24.04-arm"));
    assert!(workflow.contains("Build amd64 release image rehearsal"));
    assert!(workflow.contains("Build arm64 release image rehearsal"));
    assert!(!workflow.contains("Set up QEMU"));
}

#[test]
fn release_workflow_publishes_docker_tags_only_after_both_arch_builds_succeed() {
    let workflow = release_workflow();

    assert!(
        workflow
            .contains("docker-release-manifest:\n    name: Publish Docker Hub release manifest")
    );
    assert!(workflow.contains(
        "needs:\n      - gate\n      - docker-release-amd64\n      - docker-release-arm64"
    ));
    assert!(workflow.contains("Sign released image"));
    assert!(workflow.contains("IMAGE_DIGEST: ${{ steps.merge-manifest.outputs.digest }}"));
}

#[test]
fn pre_commit_hook_lints_staged_workflow_changes() {
    let hook = pre_commit_hook();

    assert!(hook.contains("./scripts/lint-workflows.sh --staged"));
}
