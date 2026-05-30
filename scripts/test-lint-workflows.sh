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

create_test_repo() {
  local temp_dir="$1"

  mkdir -p "$temp_dir/scripts" "$temp_dir/.github/workflows"
  cp "$repo_root/scripts/lib.sh" "$temp_dir/scripts/lib.sh"
  cp "$repo_root/scripts/lint-workflows.sh" "$temp_dir/scripts/lint-workflows.sh"
  chmod +x "$temp_dir/scripts/lint-workflows.sh"

  git -C "$temp_dir" init --quiet
  git -C "$temp_dir" config user.name "Runewarp Test"
  git -C "$temp_dir" config user.email "runewarp-test@example.invalid"
}

test_no_arg_lints_all_workflows_without_empty_array_crash() {
  local temp_dir fake_bin_dir commands_file stderr_path
  temp_dir="$(mktemp -d)"
  fake_bin_dir="$temp_dir/fake-bin"
  commands_file="$temp_dir/docker-commands.txt"
  stderr_path="$temp_dir/stderr"

  create_test_repo "$temp_dir"
  cat > "$temp_dir/.github/workflows/ci.yml" <<'EOF'
name: CI
on: push
jobs:
  workflow-lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
EOF
  mkdir -p "$fake_bin_dir"
  cat > "$fake_bin_dir/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" > "$commands_file"
EOF
  chmod +x "$fake_bin_dir/docker"

  PATH="$fake_bin_dir:$PATH" \
  "$temp_dir/scripts/lint-workflows.sh" \
    >/dev/null \
    2>"$stderr_path"

  assert_file_has_line "$commands_file" "run --rm -v $temp_dir:/repo -w /repo rhysd/actionlint:1.7.8 -color"
  grep -q 'Workflow files: all' "$stderr_path" ||
    die "expected no-arg lint run to report all workflows"

  rm -rf "$temp_dir"
}

test_staged_mode_uses_index_content_from_repo_visible_temp_root() {
  local temp_dir fake_bin_dir commands_file mount_path_file linted_workflow_file
  temp_dir="$(mktemp -d)"
  fake_bin_dir="$temp_dir/fake-bin"
  commands_file="$temp_dir/docker-commands.txt"
  mount_path_file="$temp_dir/mount-path.txt"
  linted_workflow_file="$temp_dir/linted-workflow.yml"

  create_test_repo "$temp_dir"
  cat > "$temp_dir/.github/workflows/release.yml" <<'EOF'
name: staged
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: echo staged
EOF
  git -C "$temp_dir" add .github/workflows/release.yml
  cat > "$temp_dir/.github/workflows/release.yml" <<'EOF'
name: unstaged
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: echo unstaged
EOF

  mkdir -p "$fake_bin_dir"
  cat > "$fake_bin_dir/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" > "$commands_file"
while ((\$#)); do
  if [[ "\$1" == "-v" ]]; then
    mount_root="\${2%%:*}"
    printf '%s\n' "\$mount_root" > "$mount_path_file"
    cat "\$mount_root/.github/workflows/release.yml" > "$linted_workflow_file"
    exit 0
  fi
  shift
done
exit 1
EOF
  chmod +x "$fake_bin_dir/docker"

  PATH="$fake_bin_dir:$PATH" \
  "$temp_dir/scripts/lint-workflows.sh" --staged \
    >/dev/null \
    2>/dev/null

  assert_file_has_line "$commands_file" "run --rm -v $(cat "$mount_path_file"):/repo -w /repo rhysd/actionlint:1.7.8 -color .github/workflows/release.yml"
  [[ "$(cat "$mount_path_file")" == "$temp_dir"/.workflow-lint.* ]] ||
    die "expected staged lint root under the repository so Docker can mount it"
  assert_file_has_line "$linted_workflow_file" 'name: staged'
  ! grep -q 'name: unstaged' "$linted_workflow_file" ||
    die "expected staged lint to read index content rather than the working tree"

  rm -rf "$temp_dir"
}

main() {
  section "Testing workflow lint script"
  test_no_arg_lints_all_workflows_without_empty_array_crash
  test_staged_mode_uses_index_content_from_repo_visible_temp_root
  success "workflow lint script tests passed"
}

main "$@"
