#!/usr/bin/env bash

runewarp_changelog_first_h2_heading() {
  awk '
    /^## / {
      sub(/^## /, "", $0)
      print
      exit
    }
  ' "$1"
}

runewarp_changelog_normalize_heading() {
  case "$1" in
    "Unreleased"|"[Unreleased]")
      printf 'Unreleased\n'
      ;;
    *)
      printf '%s\n' "$1"
      ;;
  esac
}

runewarp_changelog_has_unreleased_heading() {
  grep -Eq '^## (\[Unreleased\]|Unreleased)$' "$1"
}

runewarp_changelog_validate_release_headings() {
  local changelog_path="$1"

  awk '
    /^## / {
      if ($0 == "## Unreleased" || $0 == "## [Unreleased]") {
        next
      }

      if ($0 !~ /^## \[[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$/) {
        printf "error: invalid changelog release heading: %s\n", $0 > "/dev/stderr"
        exit 1
      }
    }
  ' "$changelog_path"
}

runewarp_changelog_validate_subsection_headings() {
  local changelog_path="$1"

  awk '
    BEGIN {
      allowed["Added"] = 1
      allowed["Changed"] = 1
      allowed["Deprecated"] = 1
      allowed["Removed"] = 1
      allowed["Fixed"] = 1
      allowed["Security"] = 1
      in_section = 0
    }

    /^## / {
      in_section = 1
      next
    }

    /^### / {
      heading = $0
      sub(/^### /, "", heading)

      if (!in_section) {
        printf "error: changelog subsection must appear under a changelog section: %s\n", heading > "/dev/stderr"
        exit 1
      }

      if (!(heading in allowed)) {
        printf "error: invalid changelog subsection: %s\n", heading > "/dev/stderr"
        exit 1
      }
    }
  ' "$changelog_path"
}

runewarp_changelog_validate_section_subsection_headings() {
  local changelog_path="$1"
  local section_heading="$2"

  awk -v section_heading="$section_heading" '
    BEGIN {
      allowed["Added"] = 1
      allowed["Changed"] = 1
      allowed["Deprecated"] = 1
      allowed["Removed"] = 1
      allowed["Fixed"] = 1
      allowed["Security"] = 1
    }

    $0 == section_heading {
      in_section = 1
      saw_section = 1
      next
    }

    in_section && /^## / {
      exit 0
    }

    in_section && /^### / {
      heading = $0
      sub(/^### /, "", heading)

      if (!(heading in allowed)) {
        printf "error: invalid changelog subsection: %s\n", heading > "/dev/stderr"
        exit 1
      }
    }

    END {
      if (!saw_section) {
        exit 2
      }
    }
  ' "$changelog_path"
}

runewarp_changelog_find_release_heading() {
  local changelog_path="$1"
  local version="$2"

  awk -v prefix="## [$version] - " '
    index($0, prefix) == 1 {
      date = substr($0, length(prefix) + 1)
      if (date ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/) {
        print
        exit
      }
    }
  ' "$changelog_path"
}

runewarp_changelog_section_has_list_item() {
  local changelog_path="$1"
  local heading="$2"

  awk -v heading="$heading" '
    $0 == heading {
      in_section = 1
      next
    }

    in_section && /^## / {
      exit found ? 0 : 1
    }

    in_section && /^- / {
      found = 1
    }

    END {
      if (in_section) {
        exit found ? 0 : 1
      }

      exit 2
    }
  ' "$changelog_path"
}

runewarp_changelog_print_release_section() {
  local changelog_path="$1"
  local heading="$2"

  awk -v heading="$heading" '
    $0 == heading {
      in_section = 1
      next
    }

    in_section && /^## / {
      exit
    }

    in_section {
      if ($0 ~ /^### /) {
        sub(/^### /, "## ", $0)
      }
      print
    }
  ' "$changelog_path"
}
