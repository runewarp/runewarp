#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

Runewarp::Core.run_cli do
  Runewarp::WorkflowHelpers.merge_docker_manifest!(
    amd64_digest: ENV.fetch("AMD64_DIGEST"),
    arm64_digest: ENV.fetch("ARM64_DIGEST"),
    docker_tags: ENV.fetch("DOCKER_TAGS"),
    image_repository: ENV.fetch("IMAGE_REPOSITORY"),
    release_version: ENV.fetch("RELEASE_VERSION"),
    github_output: ENV.fetch("GITHUB_OUTPUT")
  )
end
