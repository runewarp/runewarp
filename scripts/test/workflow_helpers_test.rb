# frozen_string_literal: true

require_relative "support/test_helper"
require_relative "../lib/runewarp"

class WorkflowHelpersTest < Minitest::Test
  def test_verify_prior_green_ci_uses_the_requested_check_name
    helper_singleton = Runewarp::WorkflowHelpers.singleton_class
    original_fetch_json = helper_singleton.instance_method(:fetch_json)
    captured_uri = nil
    captured_request = nil

    helper_singleton.define_method(:fetch_json) do |uri, request, _label|
      captured_uri = uri
      captured_request = request
      { "check_runs" => [{ "name" => "Images", "conclusion" => "success" }] }
    end

    Runewarp::WorkflowHelpers.verify_prior_green_ci!(
      repository: "runewarp/runewarp",
      commit_sha: "1234567890abcdef1234567890abcdef12345678",
      token: "test-token",
      check_name: "Images"
    )

    assert_includes(captured_uri.to_s, "check_name=Images")
    assert_equal("Bearer test-token", captured_request["Authorization"])
  ensure
    helper_singleton.define_method(:fetch_json, original_fetch_json)
  end

  def test_crates_io_release_exists_sets_the_data_access_user_agent
    helper_singleton = Runewarp::WorkflowHelpers.singleton_class
    original_http_response = helper_singleton.instance_method(:http_response)
    captured_request = nil

    helper_singleton.define_method(:http_response) do |_uri, request, _label|
      captured_request = request
      Struct.new(:code, :message).new("404", "Not Found")
    end

    exists = Runewarp::WorkflowHelpers.crates_io_release_exists?(crate_name: "runewarp", release_version: "0.2.0")

    refute(exists)
    assert_equal("application/json", captured_request["Accept"])
    assert_equal("runewarp-release-check (+https://github.com/runewarp/runewarp)", captured_request["User-Agent"])
  ensure
    helper_singleton.define_method(:http_response, original_http_response)
  end
end
