# frozen_string_literal: true

require_relative "support/test_helper"

class EntrypointUsageTest < Minitest::Test
  def test_usage_errors_reference_the_kebab_case_entrypoints
    [
      [%w[scripts check-distribution], [], "usage: check-distribution"],
      [%w[scripts validate-release-gates], [], "usage: validate-release-gates"],
      [%w[scripts validate-release-metadata], [], "usage: validate-release-metadata"],
      [%w[scripts lint-workflows], ["--help"], "usage: lint-workflows"],
      [%w[scripts docker-image], [], "docker-image <platform> <output-dir>"],
      [%w[scripts render-release-notes], [], "render-release-notes --version X.Y.Z"]
    ].each do |path_parts, arguments, expected_usage|
      result = run_command(ruby_script(*path_parts), *arguments)

      refute(result.success?)
      assert_includes(result.stderr, expected_usage)
    end
  end
end
