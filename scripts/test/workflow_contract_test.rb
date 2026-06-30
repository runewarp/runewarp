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
    assert_includes(ci_workflow, "run: ./scripts/lint-workflows")
    assert_includes(ci_workflow, "run: ./scripts/validate-release-metadata ci")
    assert_includes(ci_workflow, "run: ./scripts/test-automation")
    assert_includes(ci_workflow, "./scripts/check-distribution cargo-install")
    assert_includes(ci_workflow, "run: ./scripts/check-distribution package-readiness")
    assert_includes(ci_workflow, "./scripts/check-distribution docker-image")
    assert_includes(ci_workflow, "run: ./scripts/docker-example smoke")
    refute_includes(ci_workflow, ".sh")
  end

  def test_release_workflow_uses_ruby_release_helpers
    assert_includes(release_workflow, "run: ./scripts/resolve-release-metadata")
    assert_includes(release_workflow, "run: ./scripts/validate-release-gates rehearsal")
    assert_includes(release_workflow, "run: ./scripts/validate-release-gates tag")
    assert_includes(release_workflow, "run: ./scripts/check-github-check-run")
    assert_includes(release_workflow, "run: ./scripts/render-release-notes --version \"$RELEASE_VERSION\" > /tmp/release-notes.md")
    assert_includes(release_workflow, "run: ./scripts/write-release-summary")
    assert_includes(release_workflow, "run: ./scripts/check-crates-io-release")
    assert_includes(release_workflow, "run: ./scripts/check-docker-hub-tag --image-ref \"$PRIMARY_IMAGE_REF\"")
    assert_includes(release_workflow, "run: ./scripts/merge-docker-manifest")
    assert_includes(release_workflow, "run: ./scripts/upsert-github-release")
    refute_includes(release_workflow, "python - <<'PY'")
  end

  def test_release_rehearsal_exercises_the_crates_io_release_probe
    assert_includes(release_workflow, "- name: Check whether crates.io version already exists")
    assert_includes(release_workflow, "id: crate-status")
    assert_includes(release_workflow, "RELEASE_VERSION: ${{ needs.gate.outputs.release_version }}")
    refute_includes(release_workflow, "if: github.event_name != 'workflow_dispatch' || inputs.mode == 'publish'\n        env:\n          CRATE_NAME: runewarp")
  end

  def test_public_script_entrypoints_are_kebab_case_without_extensions
    expected_entrypoints = %w[
      check-crates-io-release
      check-distribution
      check-docker-hub-tag
      check-github-check-run
      ci
      docker-example
      docker-image
      lint-workflows
      merge-docker-manifest
      render-release-notes
      resolve-release-metadata
      test-automation
      upsert-github-release
      validate-release-gates
      validate-release-metadata
      write-release-summary
    ]
    scripts_dir = File.join(REPO_ROOT, "scripts")
    public_entrypoints = Dir.children(scripts_dir).select { |entry| File.file?(File.join(scripts_dir, entry)) }.sort

    assert_equal(expected_entrypoints, public_entrypoints)
    refute(public_entrypoints.any? { |entry| entry.include?("_") || entry.end_with?(".rb") })
  end

  def test_release_workflow_preserves_publish_ordering
    assert_includes(release_workflow, "docker-release-amd64:\n    name: Publish Docker Hub amd64 release\n    needs:\n      - gate\n      - crate-release")
    assert_includes(release_workflow, "docker-release-arm64:\n    name: Publish Docker Hub arm64 release\n    needs:\n      - gate\n      - crate-release")
    assert_includes(release_workflow, "docker-release-manifest:\n    name: Publish Docker Hub release manifest")
    assert_includes(release_workflow, "steps:\n      - name: Check out the repository\n        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2")
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
