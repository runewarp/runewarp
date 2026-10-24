# frozen_string_literal: true

require "json"

module Runewarp
  module CratesIo
    # The crates.io pause switch. While this is a reason string, CI package readiness and the
    # Release workflow skip `cargo publish`. To resume, switch `h3` / `h3-quinn` to crates.io
    # versions in `Cargo.toml`, then set this to nil.
    PUBLISHING_PAUSE_REASON = "Core depends on a git-pinned h3 until upstream releases its fixes (https://github.com/hyperium/h3/issues/369)"

    # Git dependencies tolerated while publishing is paused, keyed by package name.
    ALLOWED_GIT_DEPENDENCIES = {
      "h3" => "https://github.com/hyperium/h3",
      "h3-quinn" => "https://github.com/hyperium/h3"
    }.freeze

    module_function

    def publishing_paused?
      !PUBLISHING_PAUSE_REASON.nil?
    end

    def pause_message(reason = PUBLISHING_PAUSE_REASON)
      "crates.io publishing is paused: #{reason}"
    end

    def allowed_git_dependencies_description
      ALLOWED_GIT_DEPENDENCIES.group_by { |_name, url| url }.map do |url, entries|
        "#{entries.map(&:first).join(' and ')} from #{url}"
      end.join(", ")
    end

    # Returns "name version (source)" for each git-sourced package in `cargo metadata` JSON that
    # is not allowlisted. Allowlisted names must still come from their allowlisted repository.
    def unexpected_git_dependencies(metadata_json)
      JSON.parse(metadata_json).fetch("packages").filter_map do |package|
        source = package["source"]
        next unless source&.start_with?("git+")

        repository = source.delete_prefix("git+").split(/[?#]/, 2).first
        next if ALLOWED_GIT_DEPENDENCIES[package["name"]] == repository

        "#{package['name']} #{package['version']} (#{source})"
      end
    end
  end
end
