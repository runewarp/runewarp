# frozen_string_literal: true

require_relative "support/test_helper"
require_relative "../lib/runewarp"

class DockerHubTest < Minitest::Test
  def test_missing_tag_writes_exists_false
    Dir.mktmpdir do |temp_dir|
      github_output = File.join(temp_dir, "github-output")

      result = run_command(
        "ruby",
        ruby_script("scripts", "check-docker-hub-tag"),
        "--image-ref",
        "docker.io/runewarp/runewarp:0.1.0",
        env: {
          "GITHUB_OUTPUT" => github_output,
          "RUNEWARP_DOCKER_HUB_STATUS_OVERRIDE" => "404"
        }
      )

      assert(result.success?, result.stderr)
      assert_file_has_line(github_output, "exists=false")
      assert_equal("exists=false\n", result.stdout)
    end
  end

  def test_existing_tag_writes_exists_true
    Dir.mktmpdir do |temp_dir|
      github_output = File.join(temp_dir, "github-output")

      result = run_command(
        "ruby",
        ruby_script("scripts", "check-docker-hub-tag"),
        "--image-ref",
        "docker.io/runewarp/runewarp:0.1.0",
        env: {
          "GITHUB_OUTPUT" => github_output,
          "RUNEWARP_DOCKER_HUB_STATUS_OVERRIDE" => "200"
        }
      )

      assert(result.success?, result.stderr)
      assert_file_has_line(github_output, "exists=true")
      assert_equal("exists=true\n", result.stdout)
    end
  end
end
