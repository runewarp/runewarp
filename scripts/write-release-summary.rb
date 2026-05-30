#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

Runewarp::Core.run_cli do
  Runewarp::WorkflowHelpers.write_release_summary!(
    step_summary_path: ENV.fetch("GITHUB_STEP_SUMMARY"),
    workflow_mode: ENV.fetch("WORKFLOW_MODE"),
    release_tag: ENV.fetch("RELEASE_TAG"),
    release_version: ENV.fetch("RELEASE_VERSION"),
    github_ref: ENV.fetch("GITHUB_REF"),
    release_source_ref: ENV.fetch("RELEASE_SOURCE_REF"),
    release_commit: ENV.fetch("RELEASE_COMMIT"),
    image_repository: ENV.fetch("IMAGE_REPOSITORY"),
    docker_tags: ENV.fetch("DOCKER_TAGS"),
    release_notes_path: ENV.fetch("RELEASE_NOTES_PATH")
  )
end
