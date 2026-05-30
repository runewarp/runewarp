#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
actionlint_image="rhysd/actionlint:1.7.8"
__runewarp_workflow_lint_temp_dir=""

. "$repo_root/scripts/lib.sh"

usage() {
  usage_error "$(basename "$0") [--staged] [PATH ...]"
}

is_workflow_path() {
  local candidate="$1"

  [[ "$candidate" == .github/workflows/*.yml || "$candidate" == .github/workflows/*.yaml ]]
}

normalize_workflow_path() {
  local candidate="$1"

  if [[ "$candidate" == "$repo_root/"* ]]; then
    candidate="${candidate#"$repo_root"/}"
  fi

  printf '%s\n' "$candidate"
}

run_actionlint() {
  local lint_root="$1"
  shift
  local -a workflow_paths=("$@")

  section "Linting workflows"
  note "Lint root: $lint_root"
  if ((${#workflow_paths[@]})); then
    note "Workflow files: ${workflow_paths[*]}"
  else
    note "Workflow files: all"
  fi

  if command -v docker >/dev/null 2>&1; then
    note "Runner: docker image $actionlint_image"
    if ((${#workflow_paths[@]})); then
      docker run --rm -v "$lint_root":/repo -w /repo "$actionlint_image" -color "${workflow_paths[@]}"
    else
      docker run --rm -v "$lint_root":/repo -w /repo "$actionlint_image" -color
    fi
    return
  fi

  note "Runner: host actionlint + shellcheck"
  require_command actionlint
  require_command shellcheck
  (
    cd "$lint_root"
    if ((${#workflow_paths[@]})); then
      actionlint -color "${workflow_paths[@]}"
    else
      actionlint -color
    fi
  )
}

main() {
  local staged_only=0
  local lint_root="$repo_root"
  local candidate normalized_path
  local -a requested_paths=()
  local -a workflow_paths=()

  while (($#)); do
    case "$1" in
      --staged)
        (( staged_only == 0 )) || usage
        staged_only=1
        shift
        ;;
      --help|-h)
        usage
        ;;
      --*)
        usage
        ;;
      *)
        requested_paths+=("$1")
        shift
        ;;
    esac
  done

  if (( staged_only )); then
    ((${#requested_paths[@]} == 0)) || usage
    require_command git
    while IFS= read -r candidate; do
      [[ -n "$candidate" ]] || continue
      is_workflow_path "$candidate" || continue
      workflow_paths+=("$candidate")
    done < <(git -C "$repo_root" diff --cached --name-only --diff-filter=ACMR -- .github/workflows)

    if ((${#workflow_paths[@]} == 0)); then
      section "Linting workflows"
      note "No staged workflow changes to lint"
      success "workflow lint skipped"
      return
    fi

    __runewarp_workflow_lint_temp_dir="$(mktemp -d "$repo_root/.workflow-lint.XXXXXX")"
    trap 'if [[ -n "$__runewarp_workflow_lint_temp_dir" ]]; then rm -rf "$__runewarp_workflow_lint_temp_dir"; fi' EXIT
    lint_root="$__runewarp_workflow_lint_temp_dir"

    for candidate in "${workflow_paths[@]}"; do
      mkdir -p "$lint_root/$(dirname "$candidate")"
      git -C "$repo_root" show ":$candidate" > "$lint_root/$candidate"
    done

    run_actionlint "$lint_root" "${workflow_paths[@]}"
    return
  fi

  if ((${#requested_paths[@]})); then
    for candidate in "${requested_paths[@]}"; do
      normalized_path="$(normalize_workflow_path "$candidate")"
      is_workflow_path "$normalized_path" || die "workflow path must be under .github/workflows: $candidate"
      [[ -f "$repo_root/$normalized_path" ]] || die "workflow file not found: $candidate"
      workflow_paths+=("$normalized_path")
    done
  fi

  if ((${#workflow_paths[@]})); then
    run_actionlint "$lint_root" "${workflow_paths[@]}"
  else
    run_actionlint "$lint_root"
  fi
}

main "$@"
