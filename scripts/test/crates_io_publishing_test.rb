# frozen_string_literal: true

require "json"
require_relative "support/test_helper"
require_relative "../lib/runewarp"

class CratesIoPublishingTest < Minitest::Test
  H3_SOURCE = "git+https://github.com/hyperium/h3?rev=43745ad87e95b0c035ac9c547aad467303213425#43745ad87e95b0c035ac9c547aad467303213425"

  def metadata_json(*packages)
    JSON.generate(
      "packages" => packages.map { |name, version, source| { "name" => name, "version" => version, "source" => source } }
    )
  end

  def test_pause_reason_links_the_upstream_h3_release_request
    reason = Runewarp::CratesIo::PUBLISHING_PAUSE_REASON
    skip("crates.io publishing is not paused") if reason.nil?

    assert_includes(reason, "https://github.com/hyperium/h3/issues/369")
  end

  def test_registry_and_path_dependencies_are_not_reported
    metadata = metadata_json(
      ["runewarp", "0.2.0-dev", nil],
      ["tokio", "1.48.0", "registry+https://github.com/rust-lang/crates.io-index"],
      ["quinn", "0.11.9", "sparse+https://index.crates.io/"]
    )

    assert_empty(Runewarp::CratesIo.unexpected_git_dependencies(metadata))
  end

  def test_allowlisted_h3_git_dependencies_are_accepted
    metadata = metadata_json(["h3", "0.0.8", H3_SOURCE], ["h3-quinn", "0.0.10", H3_SOURCE])

    assert_empty(Runewarp::CratesIo.unexpected_git_dependencies(metadata))
  end

  def test_other_git_dependencies_are_reported
    metadata = metadata_json(
      ["h3", "0.0.8", H3_SOURCE],
      ["quinn", "0.11.9", "git+https://github.com/quinn-rs/quinn?branch=main#abc123"],
      ["h3-datagram", "0.0.2", H3_SOURCE],
      ["h3", "0.0.8", "git+https://github.com/someone/h3-fork?rev=abc#abc"]
    )

    assert_equal(
      [
        "quinn 0.11.9 (git+https://github.com/quinn-rs/quinn?branch=main#abc123)",
        "h3-datagram 0.0.2 (#{H3_SOURCE})",
        "h3 0.0.8 (git+https://github.com/someone/h3-fork?rev=abc#abc)"
      ],
      Runewarp::CratesIo.unexpected_git_dependencies(metadata)
    )
  end

  def test_publishing_status_entrypoint_writes_the_paused_output
    Dir.mktmpdir do |dir|
      output_path = File.join(dir, "github-output")
      result = run_command(ruby_script("scripts", "check-crates-io-publishing"), env: { "GITHUB_OUTPUT" => output_path })
      assert(result.success?, result.stderr)

      if Runewarp::CratesIo.publishing_paused?
        assert_file_has_line(output_path, "paused=true")
        assert_equal("skipped: crates.io publishing is paused: #{Runewarp::CratesIo::PUBLISHING_PAUSE_REASON}\n", result.stderr)
      else
        assert_file_has_line(output_path, "paused=false")
        assert_equal("done: crates.io publishing is enabled\n", result.stderr)
      end
    end
  end
end
