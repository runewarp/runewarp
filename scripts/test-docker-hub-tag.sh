#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

. "$repo_root/scripts/lib.sh"

assert_file_has_line() {
  local file_path="$1"
  local expected_line="$2"

  grep -qxF -- "$expected_line" "$file_path" ||
    die "expected $file_path to contain line: $expected_line"
}

test_missing_tag_writes_exists_false() {
  local temp_dir fake_bin_dir commands_file github_output
  temp_dir="$(mktemp -d)"
  fake_bin_dir="$temp_dir/fake-bin"
  commands_file="$temp_dir/curl-commands.txt"
  github_output="$temp_dir/github-output"

  mkdir -p "$fake_bin_dir"
  cat > "$fake_bin_dir/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" > "$commands_file"
printf '404'
EOF
  chmod +x "$fake_bin_dir/curl"

  PATH="$fake_bin_dir:$PATH" \
  GITHUB_OUTPUT="$github_output" \
  "$repo_root/scripts/check-docker-hub-tag.sh" \
    --image-ref docker.io/runewarp/runewarp:0.1.0 \
    > "$temp_dir/stdout"

  assert_file_has_line "$github_output" 'exists=false'
  assert_file_has_line "$commands_file" '--silent --show-error --output /dev/null --write-out %{http_code} https://hub.docker.com/v2/namespaces/runewarp/repositories/runewarp/tags/0.1.0'

  rm -rf "$temp_dir"
}

test_existing_tag_writes_exists_true() {
  local temp_dir fake_bin_dir github_output
  temp_dir="$(mktemp -d)"
  fake_bin_dir="$temp_dir/fake-bin"
  github_output="$temp_dir/github-output"

  mkdir -p "$fake_bin_dir"
  cat > "$fake_bin_dir/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '200'
EOF
  chmod +x "$fake_bin_dir/curl"

  PATH="$fake_bin_dir:$PATH" \
  GITHUB_OUTPUT="$github_output" \
  "$repo_root/scripts/check-docker-hub-tag.sh" \
    --image-ref docker.io/runewarp/runewarp:0.1.0 \
    > "$temp_dir/stdout"

  assert_file_has_line "$github_output" 'exists=true'
  assert_file_has_line "$temp_dir/stdout" 'exists=true'

  rm -rf "$temp_dir"
}

main() {
  section "Testing Docker Hub tag lookup"
  test_missing_tag_writes_exists_false
  test_existing_tag_writes_exists_true
  success "Docker Hub tag tests passed"
}

main "$@"
