#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../../scripts/lib/runewarp"

Runewarp::Core.run_cli do
  Runewarp::Core.usage_error("smoke.rb") unless ARGV.empty?

  example_dir = __dir__
  repo_root = File.expand_path("../..", example_dir)
  Runewarp::DockerExample.smoke(example_dir: example_dir, repo_root: repo_root)
end
