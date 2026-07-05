# frozen_string_literal: true

module Runewarp
  module ReleaseMetadata
    STABLE_VERSION = /\A\d+\.\d+\.\d+\z/
    STABLE_TAG = /\Av\d+\.\d+\.\d+\z/
    FULL_COMMIT_SHA = /\A[0-9a-f]{40}\z/

    module_function

    def stable_version?(value)
      value.match?(STABLE_VERSION)
    end

    def stable_tag?(value)
      value.match?(STABLE_TAG)
    end

    def tag_from_version(release_version)
      raise Error, "error: stable release tag is required" unless stable_version?(release_version)

      "v#{release_version}"
    end

    def version_from_tag(release_tag)
      raise Error, "error: stable release tag is required" unless stable_tag?(release_tag)

      release_tag.delete_prefix("v")
    end

    def main_commit_tag(commit_sha)
      raise Error, "error: full commit SHA is required" unless commit_sha.match?(FULL_COMMIT_SHA)

      commit_sha[0, 12]
    end

    def resolve(event_name:, push_tag:, workflow_mode_input:, workflow_tag:, image_repository:, release_commit: nil)
      if event_name == "workflow_dispatch"
        release_tag = workflow_tag
        if workflow_mode_input == "publish"
          workflow_mode = "publish"
          release_source_ref = release_tag
        else
          workflow_mode = "rehearsal"
          release_source_ref = "refs/heads/main"
        end
      else
        release_tag = push_tag
        workflow_mode = "publish"
        release_source_ref = release_tag
      end

      raise Error, "error: stable release tag is required" if release_tag.nil? || release_tag.empty?

      release_version = version_from_tag(release_tag)
      {
        "workflow_mode" => workflow_mode,
        "release_tag" => release_tag,
        "release_version" => release_version,
        "release_source_ref" => release_source_ref,
        "image_repository" => image_repository,
        "primary_image_ref" => "#{image_repository}:#{release_version}"
      }.tap do |resolved|
        next if release_commit.nil? || release_commit.empty?

        resolved["source_image_ref"] = "#{image_repository}:#{main_commit_tag(release_commit)}"
      end
    end

    def docker_tags(image_repository, release_version)
      minor_series = release_version.sub(/\.\d+\z/, "")
      major_series = release_version.split(".").first

      [
        "#{image_repository}:#{release_version}",
        "#{image_repository}:#{minor_series}",
        "#{image_repository}:#{major_series}",
        "#{image_repository}:latest"
      ]
    end
  end
end
