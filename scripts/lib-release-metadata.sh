#!/usr/bin/env bash

runewarp_release_metadata_is_stable_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

runewarp_release_metadata_is_stable_tag() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

runewarp_release_metadata_tag_from_version() {
  local release_version="$1"

  runewarp_release_metadata_is_stable_version "$release_version" || return 1
  printf 'v%s\n' "$release_version"
}

runewarp_release_metadata_version_from_tag() {
  local release_tag="$1"
  local release_version="${release_tag#v}"

  runewarp_release_metadata_is_stable_tag "$release_tag" || return 1
  printf '%s\n' "$release_version"
}

runewarp_release_metadata_resolve() {
  local event_name="$1"
  local push_tag="$2"
  local workflow_mode_input="$3"
  local workflow_tag="$4"
  local image_repository="$5"
  local workflow_mode release_tag release_source_ref release_version primary_image_ref

  if [[ "$event_name" == "workflow_dispatch" ]]; then
    release_tag="$workflow_tag"
    if [[ "$workflow_mode_input" == "publish" ]]; then
      workflow_mode="publish"
      release_source_ref="$release_tag"
    else
      workflow_mode="rehearsal"
      release_source_ref="refs/heads/main"
    fi
  else
    release_tag="$push_tag"
    workflow_mode="publish"
    release_source_ref="$release_tag"
  fi

  [[ -n "$release_tag" ]] || return 1

  release_version="$(runewarp_release_metadata_version_from_tag "$release_tag")" || return 1
  primary_image_ref="${image_repository}:${release_version}"

  printf 'workflow_mode=%s\n' "$workflow_mode"
  printf 'release_tag=%s\n' "$release_tag"
  printf 'release_version=%s\n' "$release_version"
  printf 'release_source_ref=%s\n' "$release_source_ref"
  printf 'image_repository=%s\n' "$image_repository"
  printf 'primary_image_ref=%s\n' "$primary_image_ref"
}

runewarp_release_metadata_print_docker_tags() {
  local image_repository="$1"
  local release_version="$2"
  local minor_series="${release_version%.*}"
  local major_series="${release_version%%.*}"

  printf '%s:%s\n' "$image_repository" "$release_version"
  printf '%s:%s\n' "$image_repository" "$minor_series"
  printf '%s:%s\n' "$image_repository" "$major_series"
  printf '%s:latest\n' "$image_repository"
}
