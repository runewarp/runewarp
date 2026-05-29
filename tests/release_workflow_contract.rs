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
fn release_workflow_checks_docker_version_tag_immutability_before_push() {
    let workflow = release_workflow();

    let guard = workflow
        .find("validate-install-surfaces.sh docker-registry-tag-absent")
        .expect("docker immutability guard should be present");
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
            "docker-release:\n    name: Publish Docker Hub release\n    if: github.event_name == 'push'\n    needs:\n      - gate\n      - crate-release"
        ),
        "docker release should depend on the completed crates.io release"
    );
}

#[test]
fn release_workflow_uses_create_only_github_release_flow() {
    let workflow = release_workflow();

    assert!(workflow.contains("gh release create"));
    assert!(!workflow.contains("gh release edit"));
    assert!(!workflow.contains("gh release view"));
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
