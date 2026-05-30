#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tool_root="$(cd "$script_dir/.." && pwd)"
repo_root="$tool_root"
__runewarp_install_surface_cleanup_dir=""

. "$tool_root/scripts/lib.sh"
. "$script_dir/lib-docker-hub.sh"

usage() {
  usage_error "$(basename "$0") <cargo-install|package-readiness|registry-install|docker-image|docker-registry-image|docker-registry-tag-absent> [--repo-root PATH] [--bin-name NAME] [--crate-name NAME] [--expected-version X.Y.Z] [--expected-text TEXT] [--probe-arg ARG] [--image-tag NAME] [--image-ref REF] [--retry-attempts COUNT] [--retry-delay-seconds SECONDS]"
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

  CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
  CARGO_HTTP_MULTIPLEXING=false \
  CARGO_NET_RETRY=5 \
  cargo publish \
    --dry-run \
    --allow-dirty \
    --locked \
    --manifest-path "$repo_root/Cargo.toml" \
    >/dev/null

  success "package readiness is valid"
}

validate_registry_install() {
  local crate_name="$1"
  local bin_name="$2"
  local expected_version="$3"
  local expected_text="$4"
  local probe_arg="$5"
  local retry_attempts="$6"
  local retry_delay_seconds="$7"
  local install_root output

  [[ -n "$crate_name" ]] || die "registry-install mode requires --crate-name"
  [[ -n "$bin_name" ]] || die "registry-install mode requires --bin-name"
  [[ -n "$expected_version" ]] || die "registry-install mode requires --expected-version"
  if [[ -z "$expected_version" && -z "$expected_text" ]]; then
    die "registry-install mode requires --expected-version or --expected-text"
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

  section "Installing crate from crates.io"
  note "Crate: $crate_name"
  note "Binary: $bin_name"
  note "Retry attempts: $retry_attempts"

  runewarp_retry_command \
    "$retry_attempts" \
    "$retry_delay_seconds" \
    "crate registry install" \
    "crate registry install did not succeed after $retry_attempts attempts" \
    env \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_HTTP_MULTIPLEXING=false \
    CARGO_NET_RETRY=5 \
    cargo install \
      --locked \
      --version "$expected_version" \
      --root "$install_root" \
      "$crate_name" \
      >/dev/null

  section "Checking installed registry binary"
  output="$("$install_root/bin/$bin_name" "$probe_arg")"
  if [[ -n "$expected_version" ]]; then
    validate_version_output "registry-installed binary" "$output" "$expected_version"
  else
    validate_version_output "registry-installed binary" "$output" "$expected_text"
  fi

  success "crates.io install surface is valid"
  __runewarp_install_surface_cleanup_dir=""
  rm -rf "$install_root"
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

validate_docker_registry_image() {
  local image_ref="$1"
  local expected_version="$2"
  local expected_text="$3"
  local probe_arg="$4"
  local retry_attempts="$5"
  local retry_delay_seconds="$6"
  local output

  [[ -n "$image_ref" ]] || die "docker-registry-image mode requires --image-ref"
  if [[ -z "$expected_version" && -z "$expected_text" ]]; then
    die "docker-registry-image mode requires --expected-version or --expected-text"
  fi
  if [[ -z "$probe_arg" ]]; then
    if [[ -n "$expected_version" ]]; then
      probe_arg="--version"
    else
      probe_arg="--help"
    fi
  fi

  require_command docker

  section "Pulling Docker image"
  note "Image ref: $image_ref"
  note "Retry attempts: $retry_attempts"
  runewarp_retry_command \
    "$retry_attempts" \
    "$retry_delay_seconds" \
    "docker pull" \
    "docker registry image did not become available after $retry_attempts attempts" \
    docker pull "$image_ref" >/dev/null

  section "Checking released Docker image startup"
  output="$(docker run --rm "$image_ref" "$probe_arg")"
  if [[ -n "$expected_version" ]]; then
    validate_version_output "released docker image" "$output" "$expected_version"
  else
    validate_version_output "released docker image" "$output" "$expected_text"
  fi

  success "docker registry image surface is valid"
}

validate_docker_registry_tag_absent() {
  local image_ref="$1"
  local http_status

  [[ -n "$image_ref" ]] || die "docker-registry-tag-absent mode requires --image-ref"

  section "Checking Docker tag immutability"
  note "Image ref: $image_ref"

  runewarp_docker_hub_tag_url_from_image_ref "$image_ref" >/dev/null ||
    die "docker-registry-tag-absent mode requires --image-ref in docker.io/<namespace>/<repository>:<tag> form"

  http_status="$(runewarp_docker_hub_tag_status_from_image_ref "$image_ref")" ||
    die "failed to query Docker Hub tag metadata for $image_ref"

  case "$http_status" in
    404)
      success "docker version tag is available for first publication"
      ;;
    200)
      die "docker registry tag already exists for $image_ref; cut a new patch version instead of republishing"
      ;;
    *)
      die "unexpected Docker Hub tag lookup status for $image_ref: $http_status"
      ;;
  esac
}

main() {
  local mode="${1:-}"
  local bin_name=""
  local crate_name=""
  local expected_version=""
  local expected_text=""
  local probe_arg=""
  local image_tag=""
  local image_ref=""
  local retry_attempts="10"
  local retry_delay_seconds="30"

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
      --crate-name)
        [[ $# -ge 2 ]] || usage
        crate_name="$2"
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
      --image-ref)
        [[ $# -ge 2 ]] || usage
        image_ref="$2"
        shift 2
        ;;
      --retry-attempts)
        [[ $# -ge 2 ]] || usage
        retry_attempts="$2"
        shift 2
        ;;
      --retry-delay-seconds)
        [[ $# -ge 2 ]] || usage
        retry_delay_seconds="$2"
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
    registry-install)
      validate_registry_install "$crate_name" "$bin_name" "$expected_version" "$expected_text" "$probe_arg" "$retry_attempts" "$retry_delay_seconds"
      ;;
    docker-image)
      validate_docker_image "$repo_root" "$expected_version" "$expected_text" "$probe_arg" "$image_tag"
      ;;
    docker-registry-image)
      validate_docker_registry_image "$image_ref" "$expected_version" "$expected_text" "$probe_arg" "$retry_attempts" "$retry_delay_seconds"
      ;;
    docker-registry-tag-absent)
      validate_docker_registry_tag_absent "$image_ref"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
