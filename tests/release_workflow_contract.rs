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
fn release_workflow_uses_create_only_github_release_flow() {
    let workflow = release_workflow();

    assert!(workflow.contains("gh release create"));
    assert!(!workflow.contains("gh release edit"));
    assert!(!workflow.contains("gh release view"));
}
