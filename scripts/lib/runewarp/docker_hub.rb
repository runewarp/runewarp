# frozen_string_literal: true

require "net/http"
require "uri"

module Runewarp
  module DockerHub
    module_function

    def tag_url_from_image_ref(image_ref)
      match = image_ref.match(%r{\Adocker\.io/(?<namespace>[^/]+)/(?<repository>[^/:]+):(?<tag>[^:]+)\z})
      raise Error, "error: docker-registry-tag-absent mode requires --image-ref in docker.io/<namespace>/<repository>:<tag> form" unless match

      "https://hub.docker.com/v2/namespaces/#{match[:namespace]}/repositories/#{match[:repository]}/tags/#{match[:tag]}"
    end

    def tag_status_from_image_ref(image_ref, http_getter: nil)
      override = ENV["RUNEWARP_DOCKER_HUB_STATUS_OVERRIDE"]
      return override unless override.nil? || override.empty?

      tag_lookup_url = tag_url_from_image_ref(image_ref)
      return http_getter.call(tag_lookup_url) if http_getter

      uri = URI(tag_lookup_url)
      request = Net::HTTP::Get.new(uri)

      response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
        http.request(request)
      end

      response.code
    rescue SocketError, SystemCallError, IOError => error
      raise Error, "error: failed to query Docker Hub tag metadata for #{image_ref}: #{error.message}"
    end
  end
end
