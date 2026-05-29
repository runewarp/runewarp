#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_root="$(cd "$script_dir/.." && pwd)"
repo_root="$tool_root"
__runewarp_install_surface_cleanup_dir=""

. "$tool_root/scripts/lib.sh"

usage() {
  usage_error "$(basename "$0") <cargo-install|package-readiness|docker-image> [--repo-root PATH] [--bin-name NAME] [--expected-version X.Y.Z] [--expected-text TEXT] [--probe-arg ARG] [--image-tag NAME]"
}

validate_cargo_install() {
  local repo_root="$1"
  local bin_name="$2"
  local expected_version="$3"
  local expected_text="$4"
  local probe_arg="$5"
  local install_root output

  [[ -n "$bin_name" ]] || die "cargo-install mode requires --bin-name"
  if [[ -z "$expected_version" && -z "$expected_text" ]]; then
    die "cargo-install mode requires --expected-version or --expected-text"
  fi
  if [[ -z "$probe_arg" ]]; then
    if [[ -n "$expected_version" ]]; then
      probe_arg="--version"
    else
      probe_arg="--help"
    fi
  fi

  require_command cargo
  install_root="$(mktemp -d)"
  __runewarp_install_surface_cleanup_dir="$install_root"
  trap 'if [[ -n "$__runewarp_install_surface_cleanup_dir" ]]; then rm -rf "$__runewarp_install_surface_cleanup_dir"; fi' RETURN

  section "Installing crate from source"
  note "Repository root: $repo_root"
  note "Binary: $bin_name"

  cargo install \
    --locked \
    --path "$repo_root" \
    --root "$install_root" \
    >/dev/null

  section "Checking installed binary"
  output="$("$install_root/bin/$bin_name" "$probe_arg")"
  if [[ -n "$expected_version" ]]; then
    validate_version_output "installed binary" "$output" "$expected_version"
  else
    validate_version_output "installed binary" "$output" "$expected_text"
  fi

  success "cargo install surface is valid"
  __runewarp_install_surface_cleanup_dir=""
  rm -rf "$install_root"
}

validate_version_output() {
  local command_label="$1"
  local output="$2"
  local expected_text="$3"

  [[ "$output" == *"$expected_text"* ]] || die "${command_label} output did not include expected text: $expected_text"
}

validate_package_readiness() {
  local repo_root="$1"

  require_command cargo

  section "Checking package readiness"
  note "Repository root: $repo_root"

  cargo publish \
    --dry-run \
    --allow-dirty \
    --locked \
    --manifest-path "$repo_root/Cargo.toml" \
    >/dev/null

  success "package readiness is valid"
}

validate_docker_image() {
  local repo_root="$1"
  local expected_version="$2"
  local expected_text="$3"
  local probe_arg="$4"
  local image_tag="$5"
  local output

  if [[ -z "$expected_version" && -z "$expected_text" ]]; then
    die "docker-image mode requires --expected-version or --expected-text"
  fi
  [[ -n "$image_tag" ]] || die "docker-image mode requires --image-tag"
  if [[ -z "$probe_arg" ]]; then
    if [[ -n "$expected_version" ]]; then
      probe_arg="--version"
    else
      probe_arg="--help"
    fi
  fi

  require_command docker

  section "Building Docker image"
  note "Repository root: $repo_root"
  note "Image tag: $image_tag"

  docker build \
    --file "$repo_root/Dockerfile" \
    --tag "$image_tag" \
    "$repo_root" \
    >/dev/null

  section "Checking Docker image startup"
  output="$(docker run --rm "$image_tag" "$probe_arg")"
  if [[ -n "$expected_version" ]]; then
    validate_version_output "docker image" "$output" "$expected_version"
  else
    validate_version_output "docker image" "$output" "$expected_text"
  fi

  success "docker image surface is valid"
}

main() {
  local mode="${1:-}"
  local bin_name=""
  local expected_version=""
  local expected_text=""
  local probe_arg=""
  local image_tag=""

  [[ -n "$mode" ]] || usage
  shift

  while (($#)); do
    case "$1" in
      --repo-root)
        [[ $# -ge 2 ]] || usage
        repo_root="$2"
        shift 2
        ;;
      --bin-name)
        [[ $# -ge 2 ]] || usage
        bin_name="$2"
        shift 2
        ;;
      --expected-version)
        [[ $# -ge 2 ]] || usage
        expected_version="$2"
        shift 2
        ;;
      --expected-text)
        [[ $# -ge 2 ]] || usage
        expected_text="$2"
        shift 2
        ;;
      --probe-arg)
        [[ $# -ge 2 ]] || usage
        probe_arg="$2"
        shift 2
        ;;
      --image-tag)
        [[ $# -ge 2 ]] || usage
        image_tag="$2"
        shift 2
        ;;
      *)
        usage
        ;;
    esac
  done

  case "$mode" in
    cargo-install)
      validate_cargo_install "$repo_root" "$bin_name" "$expected_version" "$expected_text" "$probe_arg"
      ;;
    package-readiness)
      validate_package_readiness "$repo_root"
      ;;
    docker-image)
      validate_docker_image "$repo_root" "$expected_version" "$expected_text" "$probe_arg" "$image_tag"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
