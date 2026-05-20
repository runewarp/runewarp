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
