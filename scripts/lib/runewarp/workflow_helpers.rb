# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "uri"

module Runewarp
  module WorkflowHelpers
    module_function

    def verify_prior_green_ci!(repository:, commit_sha:, token:, check_name: "CI")
      uri = URI("https://api.github.com/repos/#{repository}/commits/#{commit_sha}/check-runs?check_name=#{URI.encode_www_form_component(check_name)}&filter=latest")
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/vnd.github+json"
      request["Authorization"] = "Bearer #{token}"
      request["X-GitHub-Api-Version"] = "2022-11-28"

      payload = fetch_json(uri, request, "GitHub check runs for commit #{commit_sha}")
      matches = Array(payload["check_runs"]).select { |check_run| check_run["name"] == check_name }

      Core.die("commit #{commit_sha} does not have an aggregate #{check_name} check run") if matches.empty?
      return if matches.any? { |check_run| check_run["conclusion"] == "success" }

      Core.die("aggregate #{check_name} check for commit #{commit_sha} is not successful")
    end

    def crates_io_release_exists?(crate_name:, release_version:)
      uri = URI("https://crates.io/api/v1/crates/#{crate_name}/#{release_version}")
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"
      request["User-Agent"] = "runewarp-release-check (+https://github.com/runewarp/runewarp)"

      response = http_response(uri, request, "crates.io for #{crate_name} #{release_version}")
      return true if response.code == "200"
      return false if response.code == "404"

      Core.die("failed to query crates.io for #{crate_name} #{release_version}: HTTP #{response.code} #{response.message}")
    end

    def merge_docker_manifest!(docker_tags:, image_repository:, release_version:, source_image_ref:, github_output:)
      tag_args = docker_tags.lines(chomp: true).reject(&:empty?).flat_map { |tag| ["-t", tag] }

      Shell.run!(
        "docker",
        "buildx",
        "imagetools",
        "create",
        *tag_args,
        source_image_ref
      )

      manifest_json = Shell.capture!("docker", "buildx", "imagetools", "inspect", "#{image_repository}:#{release_version}", "--raw")
      digest = "sha256:#{Digest::SHA256.hexdigest(manifest_json)}"
      Core.write_github_output(github_output, "digest", digest)
    end

    def write_release_summary!(step_summary_path:, workflow_mode:, release_tag:, release_version:, github_ref:, release_source_ref:, release_commit:, image_repository:, docker_tags:, release_notes_path:)
      stripped_tags = docker_tags.lines(chomp: true).reject(&:empty?).map { |tag| tag.delete_prefix("#{image_repository}:") }
      summary = +"## Release workflow\n\n"
      summary << "- Mode: #{workflow_mode}\n"
      summary << "- Release tag: `#{release_tag}`\n"
      summary << "- Release version: `#{release_version}`\n"
      summary << "- Workflow ref: `#{github_ref}`\n"
      summary << "- Release source ref: `#{release_source_ref}`\n"
      summary << "- Release commit: `#{release_commit}`\n"
      summary << "- Docker tags: #{stripped_tags.map { |tag| "`#{tag}`" }.join(', ')}\n"
      summary << "\n## Release notes preview\n\n"
      summary << File.read(release_notes_path, encoding: "utf-8")

      File.open(step_summary_path, "a", encoding: "utf-8") { |handle| handle.write(summary) }
    end

    def github_release_exists?(tag:, repository:)
      Shell.successful?("gh", "release", "view", tag, "--repo", repository)
    end

    def upsert_github_release!(tag:, version:, repository:, notes_path:)
      if github_release_exists?(tag: tag, repository: repository)
        Shell.run!("gh", "release", "edit", tag, "--repo", repository, "--latest", "--title", version, "--notes-file", notes_path)
      else
        Shell.run!("gh", "release", "create", tag, "--repo", repository, "--verify-tag", "--latest", "--title", version, "--notes-file", notes_path)
      end
    end

    def fetch_json(uri, request, label)
      response = http_response(uri, request, label)
      JSON.parse(response.body)
    end

    def http_response(uri, request, label)
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
        http.request(request)
      end

      return response if response.code.start_with?("2") || response.code == "404"

      Core.die("failed to query #{label}: HTTP #{response.code} #{response.message}")
    rescue SocketError, SystemCallError, IOError => error
      Core.die("failed to reach #{label}: #{error.message}")
    end
  end
end
