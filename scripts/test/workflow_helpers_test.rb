# frozen_string_literal: true

require_relative "support/test_helper"
require_relative "../lib/runewarp"

class WorkflowHelpersTest < Minitest::Test
  def test_merge_docker_manifest_accepts_multiple_source_refs
    helper_singleton = Runewarp::WorkflowHelpers.singleton_class
    shell_singleton = Runewarp::Shell.singleton_class
    original_run = shell_singleton.instance_method(:run!)
    original_capture = shell_singleton.instance_method(:capture!)
    captured_command = nil

    shell_singleton.define_method(:run!) do |*command|
      captured_command = command
      true
    end
    shell_singleton.define_method(:capture!) do |*_command|
      '{"schemaVersion":2}'
    end

    Dir.mktmpdir do |temp_dir|
      output_path = File.join(temp_dir, "github-output")

      Runewarp::WorkflowHelpers.merge_docker_manifest!(
        docker_tags: "docker.io/runewarp/runewarp:main\ndocker.io/runewarp/runewarp:1234567890ab\n",
        image_repository: "docker.io/runewarp/runewarp",
        release_version: "main",
        source_image_ref: "docker.io/runewarp/runewarp:1234567890ab-amd64\ndocker.io/runewarp/runewarp:1234567890ab-arm64\n",
        github_output: output_path
      )

      assert_equal(
        [
          "docker", "buildx", "imagetools", "create",
          "-t", "docker.io/runewarp/runewarp:main",
          "-t", "docker.io/runewarp/runewarp:1234567890ab",
          "docker.io/runewarp/runewarp:1234567890ab-amd64",
          "docker.io/runewarp/runewarp:1234567890ab-arm64"
        ],
        captured_command
      )
    end
  ensure
    shell_singleton.define_method(:run!, original_run)
    shell_singleton.define_method(:capture!, original_capture)
  end

  def test_verify_prior_green_ci_uses_the_requested_check_name
    helper_singleton = Runewarp::WorkflowHelpers.singleton_class
    original_fetch_json = helper_singleton.instance_method(:fetch_json)
    captured_uri = nil
    captured_request = nil

    helper_singleton.define_method(:fetch_json) do |uri, request, _label|
      captured_uri = uri
      captured_request = request
      { "check_runs" => [{ "name" => "Images", "conclusion" => "success" }] }
    end

    Runewarp::WorkflowHelpers.verify_prior_green_ci!(
      repository: "runewarp/runewarp",
      commit_sha: "1234567890abcdef1234567890abcdef12345678",
      token: "test-token",
      check_name: "Images"
    )

    assert_includes(captured_uri.to_s, "check_name=Images")
    assert_equal("Bearer test-token", captured_request["Authorization"])
  ensure
    helper_singleton.define_method(:fetch_json, original_fetch_json)
  end

  def test_crates_io_release_exists_sets_the_data_access_user_agent
    helper_singleton = Runewarp::WorkflowHelpers.singleton_class
    original_http_response = helper_singleton.instance_method(:http_response)
    captured_request = nil

    helper_singleton.define_method(:http_response) do |_uri, request, _label|
      captured_request = request
      Struct.new(:code, :message).new("404", "Not Found")
    end

    exists = Runewarp::WorkflowHelpers.crates_io_release_exists?(crate_name: "runewarp", release_version: "0.2.0")

    refute(exists)
    assert_equal("application/json", captured_request["Accept"])
    assert_equal("runewarp-release-check (+https://github.com/runewarp/runewarp)", captured_request["User-Agent"])
  ensure
    helper_singleton.define_method(:http_response, original_http_response)
  end
end
