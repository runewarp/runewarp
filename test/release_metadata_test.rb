#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "support/test_helper"

class ReleaseMetadataTest < Minitest::Test
  def test_push_tag_publish_outputs
    Dir.mktmpdir do |temp_dir|
      env_output = File.join(temp_dir, "github-env")
      step_output = File.join(temp_dir, "github-output")

      result = run_command(
        "ruby",
        ruby_script("scripts", "resolve-release-metadata.rb"),
        env: {
          "EVENT_NAME" => "push",
          "PUSH_TAG" => "v1.2.3",
          "IMAGE_REPOSITORY" => "docker.io/runewarp/runewarp",
          "GITHUB_ENV" => env_output,
          "GITHUB_OUTPUT" => step_output
        }
      )

      assert(result.success?, result.stderr)
      assert_file_has_line(env_output, "WORKFLOW_MODE=publish")
      assert_file_has_line(env_output, "RELEASE_TAG=v1.2.3")
      assert_file_has_line(env_output, "RELEASE_VERSION=1.2.3")
      assert_file_has_line(env_output, "RELEASE_SOURCE_REF=v1.2.3")
      assert_file_has_line(env_output, "IMAGE_REPOSITORY=docker.io/runewarp/runewarp")
      assert_file_has_line(env_output, "PRIMARY_IMAGE_REF=docker.io/runewarp/runewarp:1.2.3")

      assert_file_has_line(step_output, "workflow_mode=publish")
      assert_file_has_line(step_output, "release_tag=v1.2.3")
      assert_file_has_line(step_output, "release_version=1.2.3")
      assert_file_has_line(step_output, "release_source_ref=v1.2.3")
      assert_file_has_line(step_output, "image_repository=docker.io/runewarp/runewarp")
      assert_file_has_line(step_output, "primary_image_ref=docker.io/runewarp/runewarp:1.2.3")
      assert_equal(
        [
          "docker_tags<<EOF",
          "docker.io/runewarp/runewarp:1.2.3",
          "docker.io/runewarp/runewarp:1.2",
          "docker.io/runewarp/runewarp:1",
          "docker.io/runewarp/runewarp:latest",
          "EOF"
        ],
        File.readlines(step_output, chomp: true, encoding: "utf-8").slice(6, 6)
      )
    end
  end

  def test_rehearsal_dispatch_targets_main
    Dir.mktmpdir do |temp_dir|
      env_output = File.join(temp_dir, "github-env")
      step_output = File.join(temp_dir, "github-output")

      result = run_command(
        "ruby",
        ruby_script("scripts", "resolve-release-metadata.rb"),
        env: {
          "EVENT_NAME" => "workflow_dispatch",
          "WORKFLOW_MODE" => "rehearsal",
          "WORKFLOW_TAG" => "v1.2.3",
          "IMAGE_REPOSITORY" => "docker.io/runewarp/runewarp",
          "GITHUB_ENV" => env_output,
          "GITHUB_OUTPUT" => step_output
        }
      )

      assert(result.success?, result.stderr)
      assert_file_has_line(env_output, "WORKFLOW_MODE=rehearsal")
      assert_file_has_line(env_output, "RELEASE_SOURCE_REF=refs/heads/main")
      assert_file_has_line(step_output, "workflow_mode=rehearsal")
      assert_file_has_line(step_output, "release_source_ref=refs/heads/main")
    end
  end

  def test_publish_dispatch_uses_release_tag_as_source_ref
    Dir.mktmpdir do |temp_dir|
      env_output = File.join(temp_dir, "github-env")
      step_output = File.join(temp_dir, "github-output")

      result = run_command(
        "ruby",
        ruby_script("scripts", "resolve-release-metadata.rb"),
        env: {
          "EVENT_NAME" => "workflow_dispatch",
          "WORKFLOW_MODE" => "publish",
          "WORKFLOW_TAG" => "v10.20.3",
          "IMAGE_REPOSITORY" => "docker.io/runewarp/runewarp",
          "GITHUB_ENV" => env_output,
          "GITHUB_OUTPUT" => step_output
        }
      )

      assert(result.success?, result.stderr)
      assert_file_has_line(env_output, "WORKFLOW_MODE=publish")
      assert_file_has_line(env_output, "RELEASE_SOURCE_REF=v10.20.3")
      assert_file_has_line(step_output, "release_version=10.20.3")
      assert_file_has_line(step_output, "docker.io/runewarp/runewarp:10.20.3")
      assert_file_has_line(step_output, "docker.io/runewarp/runewarp:10.20")
      assert_file_has_line(step_output, "docker.io/runewarp/runewarp:10")
    end
  end

  def test_non_stable_release_tag_is_rejected
    Dir.mktmpdir do |temp_dir|
      env_output = File.join(temp_dir, "github-env")
      step_output = File.join(temp_dir, "github-output")

      result = run_command(
        "ruby",
        ruby_script("scripts", "resolve-release-metadata.rb"),
        env: {
          "EVENT_NAME" => "push",
          "PUSH_TAG" => "v1.2.3-rc.1",
          "IMAGE_REPOSITORY" => "docker.io/runewarp/runewarp",
          "GITHUB_ENV" => env_output,
          "GITHUB_OUTPUT" => step_output
        }
      )

      refute(result.success?)
      assert(!File.exist?(env_output) || File.zero?(env_output))
      assert(!File.exist?(step_output) || File.zero?(step_output))
      assert_includes(result.stderr, "stable release tag is required")
    end
  end
end
