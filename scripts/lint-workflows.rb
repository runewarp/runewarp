#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

repo_root = ENV["RUNEWARP_REPO_ROOT"] || File.expand_path("..", __dir__)
arguments = ARGV.dup
staged_only = false
requested_paths = []

Runewarp::Core.run_cli do
  until arguments.empty?
    argument = arguments.shift
    case argument
    when "--staged"
      Runewarp::Core.usage_error("lint-workflows.rb [--staged] [PATH ...]") if staged_only
      staged_only = true
    when "--help", "-h"
      Runewarp::Core.usage_error("lint-workflows.rb [--staged] [PATH ...]")
    when /\A--/
      Runewarp::Core.usage_error("lint-workflows.rb [--staged] [PATH ...]")
    else
      requested_paths << argument
    end
  end

  Runewarp::WorkflowLint.lint(repo_root: repo_root, staged_only: staged_only, requested_paths: requested_paths)
end
