#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"
require_relative "lib/runewarp"

image_ref = nil

Runewarp::Core.run_cli do
  OptionParser.new do |parser|
    parser.banner = "usage: check-docker-hub-tag.rb --image-ref docker.io/<namespace>/<repository>:<tag>"
    parser.on("--image-ref IMAGE_REF") { |value| image_ref = value }
  end.parse!

  Runewarp::Core.die("--image-ref is required") if image_ref.nil? || image_ref.empty?

  status = Runewarp::DockerHub.tag_status_from_image_ref(image_ref)
  exists =
    case status
    when "200" then "true"
    when "404" then "false"
    else Runewarp::Core.die("unexpected Docker Hub tag lookup status for #{image_ref}: #{status}")
    end

  puts("exists=#{exists}")
  Runewarp::Core.write_github_output(ENV["GITHUB_OUTPUT"].to_s, "exists", exists)
  end
