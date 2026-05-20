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
