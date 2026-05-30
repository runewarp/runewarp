# frozen_string_literal: true

require_relative "support/test_helper"

class WorkflowContractTest < Minitest::Test
  def ci_workflow
    @ci_workflow ||= File.read(File.join(REPO_ROOT, ".github", "workflows", "ci.yml"), encoding: "utf-8")
  end

  def release_workflow
    @release_workflow ||= File.read(File.join(REPO_ROOT, ".github", "workflows", "release.yml"), encoding: "utf-8")
  end

  def test_ci_workflow_uses_ruby_entry_points
    assert_includes(ci_workflow, "run: ./scripts/lint_workflows")
    assert_includes(ci_workflow, "run: ./scripts/test_automation")
    refute_includes(ci_workflow, ".sh")
  end

  def test_release_workflow_uses_ruby_release_helpers
    assert_includes(release_workflow, "run: ./scripts/resolve_release_metadata")
    assert_includes(release_workflow, "run: ./scripts/check_github_check_run")
    assert_includes(release_workflow, "run: ./scripts/render_release_notes --version \"$RELEASE_VERSION\" > /tmp/release-notes.md")
    assert_includes(release_workflow, "run: ./scripts/write_release_summary")
    assert_includes(release_workflow, "run: ./scripts/check_docker_hub_tag --image-ref \"$PRIMARY_IMAGE_REF\"")
    assert_includes(release_workflow, "run: ./scripts/merge_docker_manifest")
    assert_includes(release_workflow, "run: ./scripts/upsert_github_release")
    refute_includes(release_workflow, "python - <<'PY'")
  end

  def test_release_workflow_preserves_publish_ordering
    assert_includes(release_workflow, "docker-release-amd64:\n    name: Publish Docker Hub amd64 release\n    needs:\n      - gate\n      - crate-release")
    assert_includes(release_workflow, "docker-release-arm64:\n    name: Publish Docker Hub arm64 release\n    needs:\n      - gate\n      - crate-release")
    assert_includes(release_workflow, "github-release:\n    name: Finalize GitHub release\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - crate-release\n      - docker-release-manifest")
  end

  def test_workflows_keep_pinned_actions_with_inline_version_comments
    { "ci.yml" => ci_workflow, "release.yml" => release_workflow }.each do |name, workflow|
      workflow.lines.grep(/uses: /).each do |line|
        next unless line.include?("@")

        assert_includes(line, " # ", "#{name} pinned action should include an inline version comment: #{line}")
      end
    end
  end

  def test_git_hooks_are_removed_from_repo_contracts
    refute(File.exist?(File.join(REPO_ROOT, ".githooks", "pre-commit")))
    refute_includes(ci_workflow, ".githooks")
    refute_includes(release_workflow, ".githooks")
  end
end
