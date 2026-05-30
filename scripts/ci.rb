#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "lib/runewarp"

Runewarp::Core.run_cli do
  repo_root = File.expand_path("..", __dir__)
  Dir.chdir(repo_root) do
    Runewarp::Core.section("Linting workflows")
    Runewarp::Shell.run!("ruby", "./scripts/lint-workflows.rb")

    Runewarp::Core.section("Running Ruby automation tests")
    Runewarp::Shell.run!("ruby", "./scripts/test-automation.rb")

    Runewarp::Core.section("Validating release metadata")
    Runewarp::Shell.run!("ruby", "./scripts/validate-release-metadata.rb", "ci")

    Runewarp::Core.section("Checking source install surface")
    Runewarp::Shell.run!("ruby", "./scripts/validate-install-surfaces.rb", "cargo-install", "--bin-name", "runewarp", "--probe-arg", "--help", "--expected-text", "Usage: runewarp")

    Runewarp::Core.section("Checking package readiness")
    Runewarp::Shell.run!("ruby", "./scripts/validate-install-surfaces.rb", "package-readiness")

    Runewarp::Core.section("Checking Rust formatting")
    Runewarp::Shell.run!("cargo", "fmt", "--check")

    Runewarp::Core.section("Running Clippy")
    Runewarp::Shell.run!("cargo", "clippy", "--all-targets", "--", "-D", "warnings")

    Runewarp::Core.section("Running Rust tests")
    Runewarp::Shell.run!("cargo", "test", "--quiet")

    Runewarp::Core.section("Building documentation")
    Runewarp::Shell.run!("cargo", "doc", "--no-deps")

    Runewarp::Core.section("Running Docker smoke test")
    Runewarp::Shell.run!("ruby", "./examples/docker/smoke.rb")

    Runewarp::Core.section("Checking Docker image surface")
    Runewarp::Shell.run!("ruby", "./scripts/validate-install-surfaces.rb", "docker-image", "--probe-arg", "--help", "--expected-text", "Usage: runewarp", "--image-tag", "runewarp:ci")

    Runewarp::Core.success("CI contract passed")
    Runewarp::Core.note("Release metadata, install surfaces, Rust checks, docs, and Docker validation all succeeded")
  end
end
