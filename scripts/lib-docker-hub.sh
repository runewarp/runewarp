#!/usr/bin/env bash

runewarp_docker_hub_tag_url_from_image_ref() {
  local image_ref="$1"
  local repository_with_tag repository_path namespace repository tag remainder

  [[ "$image_ref" == *:* ]] || return 1

  tag="${image_ref##*:}"
  repository_with_tag="${image_ref%:*}"
  repository_path="${repository_with_tag#docker.io/}"
  namespace="${repository_path%%/*}"
  remainder="${repository_path#*/}"
  repository="${remainder%%/*}"

  [[ -n "$namespace" && -n "$repository" && "$repository_path" != "$repository_with_tag" && "$remainder" == "$repository" ]] || return 1

  printf 'https://hub.docker.com/v2/namespaces/%s/repositories/%s/tags/%s\n' "$namespace" "$repository" "$tag"
}

runewarp_docker_hub_tag_status_from_image_ref() {
  local image_ref="$1"
  local tag_lookup_url

  require_command curl

  tag_lookup_url="$(runewarp_docker_hub_tag_url_from_image_ref "$image_ref")" || return 1
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$tag_lookup_url"
}
