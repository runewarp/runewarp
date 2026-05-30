#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../../scripts/lib/runewarp"

Runewarp::Core.run_cli do
  reset_requested = ARGV == ["--reset"]
  Runewarp::Core.usage_error("prepare.rb [--reset]") unless ARGV.empty? || reset_requested

  example_dir = __dir__
  repo_root = File.expand_path("../..", example_dir)
  Runewarp::DockerExample.prepare(example_dir: example_dir, repo_root: repo_root, reset_requested: reset_requested)
end
