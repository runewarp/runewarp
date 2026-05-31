# frozen_string_literal: true

require "shellwords"

module Runewarp
  module DockerBuild
    module_function

    def command(repo_root:, image_tag:)
      cache_flags = ENV.fetch("RUNEWARP_DOCKER_BUILD_FLAGS", "")
      command = ["docker"]

      if cache_flags.empty?
        command << "build"
      else
        command.concat(["buildx", "build", "--load"])
        command.concat(Shellwords.split(cache_flags))
      end

      command.concat(["--file", File.join(repo_root, "Dockerfile"), "--tag", image_tag, repo_root])
    end
  end
end
