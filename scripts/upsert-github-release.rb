#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

Runewarp::Core.run_cli do
  Runewarp::WorkflowHelpers.upsert_github_release!(
    tag: ENV.fetch("RELEASE_TAG"),
    version: ENV.fetch("RELEASE_VERSION"),
    repository: ENV.fetch("REPOSITORY"),
    notes_path: ENV.fetch("RELEASE_NOTES_PATH")
  )
end
