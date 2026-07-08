# frozen_string_literal: true

require_relative "support/test_helper"

class WorkflowContractTest < Minitest::Test
  def ci_workflow
    @ci_workflow ||= File.read(File.join(REPO_ROOT, ".github", "workflows", "ci.yml"), encoding: "utf-8")
  end

  def images_workflow
    @images_workflow ||= File.read(File.join(REPO_ROOT, ".github", "workflows", "images.yml"), encoding: "utf-8")
  end

  def release_workflow
    @release_workflow ||= File.read(File.join(REPO_ROOT, ".github", "workflows", "release.yml"), encoding: "utf-8")
  end

  def dockerfile
    @dockerfile ||= File.read(File.join(REPO_ROOT, "Dockerfile"), encoding: "utf-8")
  end

  def test_ci_workflow_uses_ruby_entry_points
    assert_includes(ci_workflow, "run: ./scripts/lint-workflows")
    assert_includes(ci_workflow, "run: ./scripts/validate-release-metadata ci")
    assert_includes(ci_workflow, "run: ./scripts/test-automation")
    assert_includes(ci_workflow, "./scripts/check-distribution cargo-install")
    assert_includes(ci_workflow, "run: ./scripts/check-distribution package-readiness")
    assert_includes(ci_workflow, "./scripts/check-distribution docker-image")
    assert_includes(ci_workflow, "run: ./scripts/docker-example smoke")
    refute_match(/run:\s+\S+\.sh\b/, ci_workflow)
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

  def test_images_workflow_uses_repo_owned_entry_points
    assert_includes(images_workflow, "name: Images")
    assert_includes(images_workflow, "workflows:\n      - CI")
    assert_includes(images_workflow, "run: ./scripts/validate-release-metadata images")
    assert_includes(images_workflow, "./scripts/check-distribution docker-registry-image")
    assert_includes(images_workflow, "run: ./scripts/docker-example smoke --image-ref")
    refute_match(/run:\s+\S+\.sh\b/, images_workflow)
  end

  def test_images_workflow_only_runs_after_successful_main_ci_pushes
    assert_includes(images_workflow, "workflow_run:")
    assert_includes(images_workflow, "types:\n      - completed")
    assert_includes(images_workflow, "branches:\n      - main")
    assert_includes(images_workflow, "if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'")
  end

  def test_images_workflow_scopes_docker_publish_secrets_to_release_environment
    assert_includes(images_workflow, "publish-amd64:\n    name: Publish Docker Hub amd64 image")
    assert_includes(images_workflow, "publish-arm64:\n    name: Publish Docker Hub arm64 image")
    assert_includes(images_workflow, "merge:\n    name: Merge trusted Docker Hub image lineage")
    assert_includes(images_workflow, "timeout-minutes: 60\n    environment: release")
    assert_includes(images_workflow, "timeout-minutes: 30\n    environment: release")
    assert_includes(images_workflow, "username: ${{ secrets.DOCKER_USERNAME }}")
    assert_includes(images_workflow, "password: ${{ secrets.DOCKER_TOKEN }}")
  end

  def test_images_workflow_splits_native_publish_by_architecture_before_merge
    assert_includes(images_workflow, "publish-amd64:\n    name: Publish Docker Hub amd64 image")
    assert_includes(images_workflow, "publish-arm64:\n    name: Publish Docker Hub arm64 image")
    assert_includes(images_workflow, "merge:\n    name: Merge trusted Docker Hub image lineage")
    assert_includes(images_workflow, "publish-amd64:\n    name: Publish Docker Hub amd64 image\n    if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'\n    runs-on: ubuntu-26.04")
    assert_includes(images_workflow, "publish-arm64:\n    name: Publish Docker Hub arm64 image\n    if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'\n    runs-on: ubuntu-26.04-arm")
    assert_includes(images_workflow, "tags: |\n            ${{ env.COMMIT_IMAGE_REF }}-amd64")
    assert_includes(images_workflow, "tags: |\n            ${{ env.COMMIT_IMAGE_REF }}-arm64")
    assert_includes(images_workflow, "smoke-amd64:\n    name: Smoke published amd64 image\n    if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'\n    needs:\n      - publish-amd64")
    assert_includes(images_workflow, "smoke-arm64:\n    name: Smoke published arm64 image\n    if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'\n    needs:\n      - publish-arm64")
    assert_includes(images_workflow, "merge:\n    name: Merge trusted Docker Hub image lineage\n    if: github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'\n    needs:\n      - smoke-amd64\n      - smoke-arm64")
    assert_includes(images_workflow, "run: ./scripts/merge-docker-manifest")
  end

  def test_linux_workflows_use_ubuntu_26_04_runner_labels
    assert_includes(ci_workflow, "runs-on: ubuntu-26.04")
    refute_includes(ci_workflow, "runs-on: ubuntu-latest")
    assert_includes(images_workflow, "runs-on: ubuntu-26.04")
    assert_includes(images_workflow, "runs-on: ubuntu-26.04-arm")
    refute_includes(images_workflow, "runs-on: ubuntu-latest")
    refute_includes(images_workflow, "runs-on: ubuntu-24.04-arm")
    assert_includes(release_workflow, "runs-on: ubuntu-26.04")
    refute_includes(release_workflow, "runs-on: ubuntu-latest")
  end

  def test_ci_and_images_share_the_trusted_main_docker_cache_scope
    assert_includes(ci_workflow, "TRUSTED_MAIN_DOCKER_CACHE_FROM: type=gha,scope=main-docker")
    assert_includes(ci_workflow, "TRUSTED_MAIN_DOCKER_CACHE_TO: type=gha,scope=main-docker,mode=max")
    assert_includes(ci_workflow, "- name: Derive Docker cache flags")
    assert_includes(ci_workflow, "printf 'RUNEWARP_DOCKER_BUILD_FLAGS=--cache-from type=gha,scope=pr-%s-docker --cache-to type=gha,scope=pr-%s-docker,mode=max\\n'")
    assert_includes(ci_workflow, "printf 'RUNEWARP_DOCKER_BUILD_FLAGS=--cache-from %s --cache-to %s\\n'")
    assert_includes(ci_workflow, "\"$TRUSTED_MAIN_DOCKER_CACHE_FROM\"")
    assert_includes(ci_workflow, "\"$TRUSTED_MAIN_DOCKER_CACHE_TO\"")

    assert_includes(images_workflow, "cache-from: ${{ env.TRUSTED_MAIN_DOCKER_CACHE_FROM }}")
    assert_includes(images_workflow, "cache-to: ${{ env.TRUSTED_MAIN_DOCKER_CACHE_TO }}")
  end

  def test_ci_rust_caches_stay_split_between_pull_requests_and_trusted_main
    assert_includes(ci_workflow, "RUST_CACHE_SCOPE: ${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || 'trusted-main' }}")
    assert_includes(ci_workflow, "key: ${{ runner.os }}-rust-ci-${{ env.RUST_CACHE_SCOPE }}-${{ hashFiles('Cargo.lock') }}")
    assert_includes(ci_workflow, "${{ env.RUST_DEPENDENCY_CACHE_PATHS }}")
  end

  def test_release_rust_cache_stays_in_the_separate_release_scope
    assert_includes(release_workflow, "RUST_CACHE_SCOPE: ${{ format('release-{0}', needs.gate.outputs.release_tag) }}")
    assert_includes(release_workflow, "key: ${{ runner.os }}-rust-release-${{ env.RUST_CACHE_SCOPE }}-${{ hashFiles('release-source/Cargo.lock') }}")
    assert_includes(release_workflow, "${{ env.RUST_DEPENDENCY_CACHE_PATHS }}")
    refute_includes(release_workflow, "TRUSTED_MAIN_DOCKER_CACHE_FROM")
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
    assert_includes(release_workflow, "steps:\n      - name: Check out the repository\n        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2")
    assert_includes(release_workflow, "crate-release:\n    name: Publish crates.io release\n    needs:\n      - gate")
    assert_includes(release_workflow, "docker-release:\n    name: Promote Docker Hub release tags\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - crate-release")
    assert_includes(release_workflow, "github-release:\n    name: Finalize GitHub release\n    if: github.event_name == 'push' || inputs.mode == 'publish'\n    needs:\n      - gate\n      - crate-release\n      - docker-release")
  end

  def test_release_workflow_promotes_prebuilt_main_images_without_rebuilding
    assert_includes(release_workflow, "run: ./scripts/check-docker-hub-tag --image-ref \"$SOURCE_IMAGE_REF\"")
    assert_includes(release_workflow, "run: ./scripts/merge-docker-manifest")
    refute_includes(release_workflow, "docker/build-push-action")
    refute_includes(release_workflow, "Build amd64 release image")
    refute_includes(release_workflow, "Build arm64 release image")
  end

  def test_release_workflow_requires_successful_images_proof_for_the_release_commit
    assert_includes(release_workflow, "- name: Verify prior successful Images workflow")
    assert_includes(release_workflow, "CHECK_NAME: Images")
    assert_includes(release_workflow, "COMMIT_SHA: ${{ steps.release-source.outputs.release_commit }}")
    assert_includes(release_workflow, "run: ./scripts/check-github-check-run")
  end

  def test_release_workflow_verifies_the_source_image_lineage_matches_the_release_commit
    assert_includes(release_workflow, "- name: Verify source image lineage matches the release commit")
    assert_includes(release_workflow, "SOURCE_IMAGE_REF: ${{ needs.gate.outputs.source_image_ref }}")
    assert_includes(release_workflow, "SOURCE_IMAGE_COMMIT: ${{ needs.gate.outputs.release_commit }}")
    assert_includes(release_workflow, "./scripts/check-distribution docker-registry-image")
    assert_includes(release_workflow, "expected_commit_tag=\"$(printf '%s' \"$SOURCE_IMAGE_COMMIT\" | cut -c1-12)\"")
    assert_includes(release_workflow, "--expected-text \"$expected_commit_tag\"")
    assert_includes(release_workflow, "--probe-arg --version")
  end

  def test_dockerfile_copies_build_script_for_dev_source_builds
    assert_includes(dockerfile, "COPY Cargo.toml Cargo.lock build.rs ./")
    assert_includes(dockerfile, "COPY src ./src")
  end

  def test_workflows_keep_pinned_actions_with_inline_version_comments
    { "ci.yml" => ci_workflow, "images.yml" => images_workflow, "release.yml" => release_workflow }.each do |name, workflow|
      workflow.lines.grep(/uses: /).each do |line|
        next unless line.include?("@")

        assert_includes(line, " # ", "#{name} pinned action should include an inline version comment: #{line}")
      end
    end
  end

  def test_git_hooks_are_removed_from_repo_contracts
    refute(File.exist?(File.join(REPO_ROOT, ".githooks", "pre-commit")))
    refute_includes(ci_workflow, ".githooks")
    refute_includes(images_workflow, ".githooks")
    refute_includes(release_workflow, ".githooks")
  end
end
