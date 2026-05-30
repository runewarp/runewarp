#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

Runewarp::Core.run_cli do
  exists = Runewarp::WorkflowHelpers.crates_io_release_exists?(
    crate_name: ENV.fetch("CRATE_NAME"),
    release_version: ENV.fetch("RELEASE_VERSION")
  )

  Runewarp::Core.write_github_output(ENV.fetch("GITHUB_OUTPUT"), "exists", exists ? "true" : "false")
end
