#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

test_dir = File.expand_path("../test", __dir__)
$LOAD_PATH.unshift(test_dir)

Runewarp::Core.run_cli do
  Dir.glob(File.join(test_dir, "*_test.rb")).sort.each do |path|
    require path
  end
end
