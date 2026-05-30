#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

assert_file_has_line() {
  local file_path="$1"
  local expected_line="$2"

  grep -qxF "$expected_line" "$file_path" ||
    die "expected $file_path to contain line: $expected_line"
}

run_release_metadata() {
  local event_name="$1"
  local push_tag="$2"
  local workflow_mode="$3"
  local workflow_tag="$4"
  local temp_dir="$5"

  EVENT_NAME="$event_name" \
  PUSH_TAG="$push_tag" \
  WORKFLOW_MODE="$workflow_mode" \
  WORKFLOW_TAG="$workflow_tag" \
  IMAGE_REPOSITORY=docker.io/runewarp/runewarp \
  GITHUB_ENV="$temp_dir/github-env" \
  GITHUB_OUTPUT="$temp_dir/github-output" \
  "$repo_root/scripts/resolve-release-metadata.sh"
}

test_push_tag_publish_outputs() {
  local temp_dir env_output step_output
  temp_dir="$(mktemp -d)"
  env_output="$temp_dir/github-env"
  step_output="$temp_dir/github-output"

  run_release_metadata push 'v1.2.3' '' '' "$temp_dir"

  assert_file_has_line "$env_output" 'WORKFLOW_MODE=publish'
  assert_file_has_line "$env_output" 'RELEASE_TAG=v1.2.3'
  assert_file_has_line "$env_output" 'RELEASE_VERSION=1.2.3'
  assert_file_has_line "$env_output" 'RELEASE_SOURCE_REF=v1.2.3'
  assert_file_has_line "$env_output" 'IMAGE_REPOSITORY=docker.io/runewarp/runewarp'
  assert_file_has_line "$env_output" 'PRIMARY_IMAGE_REF=docker.io/runewarp/runewarp:1.2.3'

  assert_file_has_line "$step_output" 'workflow_mode=publish'
  assert_file_has_line "$step_output" 'release_tag=v1.2.3'
  assert_file_has_line "$step_output" 'release_version=1.2.3'
  assert_file_has_line "$step_output" 'release_source_ref=v1.2.3'
  assert_file_has_line "$step_output" 'image_repository=docker.io/runewarp/runewarp'
  assert_file_has_line "$step_output" 'primary_image_ref=docker.io/runewarp/runewarp:1.2.3'
  assert_file_has_line "$step_output" 'docker_tags<<EOF'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:1.2.3'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:1.2'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:1'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:latest'
  assert_file_has_line "$step_output" 'EOF'

  rm -rf "$temp_dir"
}

test_rehearsal_dispatch_targets_main() {
  local temp_dir env_output step_output
  temp_dir="$(mktemp -d)"
  env_output="$temp_dir/github-env"
  step_output="$temp_dir/github-output"

  run_release_metadata workflow_dispatch '' 'rehearsal' 'v1.2.3' "$temp_dir"

  assert_file_has_line "$env_output" 'WORKFLOW_MODE=rehearsal'
  assert_file_has_line "$env_output" 'RELEASE_TAG=v1.2.3'
  assert_file_has_line "$env_output" 'RELEASE_VERSION=1.2.3'
  assert_file_has_line "$env_output" 'RELEASE_SOURCE_REF=refs/heads/main'
  assert_file_has_line "$step_output" 'workflow_mode=rehearsal'
  assert_file_has_line "$step_output" 'release_source_ref=refs/heads/main'

  rm -rf "$temp_dir"
}

test_publish_dispatch_uses_release_tag_as_source_ref() {
  local temp_dir env_output step_output
  temp_dir="$(mktemp -d)"
  env_output="$temp_dir/github-env"
  step_output="$temp_dir/github-output"

  run_release_metadata workflow_dispatch '' 'publish' 'v10.20.3' "$temp_dir"

  assert_file_has_line "$env_output" 'WORKFLOW_MODE=publish'
  assert_file_has_line "$env_output" 'RELEASE_TAG=v10.20.3'
  assert_file_has_line "$env_output" 'RELEASE_VERSION=10.20.3'
  assert_file_has_line "$env_output" 'RELEASE_SOURCE_REF=v10.20.3'
  assert_file_has_line "$step_output" 'workflow_mode=publish'
  assert_file_has_line "$step_output" 'release_version=10.20.3'
  assert_file_has_line "$step_output" 'release_source_ref=v10.20.3'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:10.20.3'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:10.20'
  assert_file_has_line "$step_output" 'docker.io/runewarp/runewarp:10'

  rm -rf "$temp_dir"
}

test_non_stable_release_tag_is_rejected() {
  local temp_dir stderr_path
  temp_dir="$(mktemp -d)"
  stderr_path="$temp_dir/stderr"

  if run_release_metadata push 'v1.2.3-rc.1' '' '' "$temp_dir" 2>"$stderr_path"; then
    die "expected non-stable release tag to fail"
  fi

  [[ ! -s "$temp_dir/github-env" ]] || die "expected non-stable release tag to avoid writing GITHUB_ENV"
  [[ ! -s "$temp_dir/github-output" ]] || die "expected non-stable release tag to avoid writing GITHUB_OUTPUT"
  grep -q 'stable release tag is required' "$stderr_path" ||
    die "expected non-stable release tag failure message"

  rm -rf "$temp_dir"
}

main() {
  section "Testing release metadata resolution"
  test_push_tag_publish_outputs
  test_rehearsal_dispatch_targets_main
  test_publish_dispatch_uses_release_tag_as_source_ref
  test_non_stable_release_tag_is_rejected
  success "release metadata tests passed"
}

main "$@"
