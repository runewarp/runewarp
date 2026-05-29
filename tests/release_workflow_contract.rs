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

#[test]
fn release_workflow_checks_docker_release_status_before_build_push() {
    let workflow = release_workflow();

    let guard = workflow
        .find("Check whether Docker release already exists")
        .expect("docker release status check should be present");
    let publish = workflow
        .find("uses: docker/build-push-action")
        .expect("docker publish step should be present");

    assert!(guard < publish);
}

#[test]
fn release_workflow_publishes_crate_before_docker_release() {
    let workflow = release_workflow();

    assert!(
        workflow.contains(
            "docker-release:\n    name: Publish Docker Hub release\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - crate-release"
        ),
        "docker release should depend on the completed crates.io release"
    );
}

#[test]
fn release_workflow_uses_view_then_create_github_release_flow() {
    let workflow = release_workflow();

    assert!(workflow.contains("gh release view"));
    assert!(workflow.contains("gh release create"));
    assert!(!workflow.contains("gh release edit"));
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
fn release_workflow_uses_safe_printf_for_hyphen_prefixed_summary_lines() {
    let workflow = release_workflow();

    assert!(workflow.contains("printf -- '- Mode: %s\\n'"));
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

    assert!(workflow.contains(
        "crate-release:\n    name: Publish crates.io release\n    if: github.event_name == 'push' || inputs.mode == 'publish'"
    ));
    assert!(workflow.contains(
        "docker-release:\n    name: Publish Docker Hub release\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - crate-release"
    ));
    assert!(workflow.contains(
        "github-release:\n    name: Finalize GitHub release\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - docker-release\n      - crate-release"
    ));
}

#[test]
fn release_workflow_skips_already_published_surfaces_and_drops_post_publish_probes() {
    let workflow = release_workflow();

    assert!(workflow.contains("Check whether crates.io version already exists"));
    assert!(workflow.contains("if: steps.crate-status.outputs.exists != 'true'"));
    assert!(workflow.contains("Check whether Docker release already exists"));
    assert!(workflow.contains("if: steps.docker-status.outputs.exists != 'true'"));
    assert!(workflow.contains("Check whether GitHub release already exists"));
    assert!(workflow.contains("if: steps.github-release-status.outputs.exists != 'true'"));
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
    assert!(workflow.contains("render-release-notes.sh --repo-root \"$PWD/release-source\""));
}
