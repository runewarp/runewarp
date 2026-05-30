#!/usr/bin/env bash

__runewarp_section_started=0

section() {
  if (( __runewarp_section_started )); then
    printf '\n' >&2
  fi
  __runewarp_section_started=1
  printf '==> %s\n' "$1" >&2
}

note() {
  printf '  - %s\n' "$1" >&2
}

success() {
  printf 'done: %s\n' "$1" >&2
}

warn() {
  printf 'warning: %s\n' "$1" >&2
}

die() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

usage_error() {
  printf 'usage: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

runewarp_version() {
  local repo_root="$1"
  local version

  version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/Cargo.toml" | head -n1)"
  [[ -n "$version" ]] || return 1
  printf '%s\n' "$version"
}

runewarp_git_commit() {
  local repo_root="$1"
  local commit="${RUNEWARP_GIT_COMMIT:-}"

  if [[ -z "$commit" ]]; then
    commit="$(git -C "$repo_root" rev-parse --short=12 HEAD)"
  fi

  [[ -n "$commit" ]] || return 1
  printf '%s\n' "$commit"
}

runewarp_retry_command() {
  local retry_attempts="$1"
  local retry_delay_seconds="$2"
  local retry_label="$3"
  local failure_message="$4"
  shift 4

  [[ "$retry_attempts" =~ ^[0-9]+$ ]] || die "--retry-attempts must be a non-negative integer"
  [[ "$retry_delay_seconds" =~ ^[0-9]+$ ]] || die "--retry-delay-seconds must be a non-negative integer"
  (( retry_attempts >= 1 )) || die "--retry-attempts must be at least 1"

  local attempt=1
  while (( attempt <= retry_attempts )); do
    if "$@"; then
      return 0
    fi

    if (( attempt == retry_attempts )); then
      die "$failure_message"
    fi

    warn "$retry_label attempt $attempt failed; retrying after ${retry_delay_seconds}s"
    sleep "$retry_delay_seconds"
    attempt=$((attempt + 1))
  done
}
