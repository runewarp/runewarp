# frozen_string_literal: true

require_relative "support/test_helper"

class ReleaseDocsTest < Minitest::Test
  def write_repo_files(repo_root, version:, changelog:)
    File.write(File.join(repo_root, "Cargo.toml"), <<~TOML, encoding: "utf-8")
      [package]
      name = "runewarp"
      version = "#{version}"
      edition = "2024"
    TOML
    File.write(File.join(repo_root, "CHANGELOG.md"), changelog, encoding: "utf-8")
  end

  def init_git_repo(repo_root, tag)
    system("git", "-C", repo_root, "init", "-q", exception: true)
    system("git", "-C", repo_root, "config", "user.name", "Runewarp Tests", exception: true)
    system("git", "-C", repo_root, "config", "user.email", "tests@example.com", exception: true)
    system("git", "-C", repo_root, "config", "commit.gpgsign", "false", exception: true)
    system("git", "-C", repo_root, "add", "Cargo.toml", "CHANGELOG.md", exception: true)
    system("git", "-C", repo_root, "commit", "-qm", "test release metadata", exception: true)
    system("git", "-C", repo_root, "tag", "-a", tag, "-m", tag, exception: true)
  end

  def test_ci_mode_accepts_a_stable_release_entry_without_unreleased
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      result = run_command(ruby_script("scripts", "validate-release-metadata"), "ci", "--repo-root", repo_root)
      assert(result.success?, result.stderr)
    end
  end

  def test_ci_mode_rejects_unreleased_for_a_stable_version
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_with_unreleased_changelog)
      result = run_command(ruby_script("scripts", "validate-release-metadata"), "ci", "--repo-root", repo_root)
      refute(result.success?)
      assert_includes(result.stderr, "must not keep an Unreleased section")
    end
  end

  def test_ci_mode_accepts_a_dev_version_with_unreleased
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.2.0-dev", changelog: unreleased_changelog)
      result = run_command(ruby_script("scripts", "validate-release-metadata"), "ci", "--repo-root", repo_root)
      assert(result.success?, result.stderr)
    end
  end

  def test_ci_mode_rejects_nonstandard_changelog_subsections
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: invalid_subsection_changelog)
      result = run_command(ruby_script("scripts", "validate-release-metadata"), "ci", "--repo-root", repo_root)
      refute(result.success?)
      assert_includes(result.stderr, "invalid changelog subsection: Features")
    end
  end

  def test_release_mode_requires_a_matching_head_tag
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      init_git_repo(repo_root, "v0.1.0")
      result = run_command(ruby_script("scripts", "validate-release-metadata"), "release", "--repo-root", repo_root, "--tag", "v0.1.0")
      assert(result.success?, result.stderr)
    end
  end

  def test_release_mode_rejects_a_mismatched_tag
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      init_git_repo(repo_root, "v0.1.0")
      result = run_command(ruby_script("scripts", "validate-release-metadata"), "release", "--repo-root", repo_root, "--tag", "v0.1.1")
      refute(result.success?)
      assert_includes(result.stderr, "must match Cargo version 0.1.0")
    end
  end

  def test_render_release_notes_outputs_the_changelog_entry_and_install_appendix
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: release_notes_changelog)
      result = run_command(ruby_script("scripts", "render-release-notes"), "--repo-root", repo_root, "--version", "0.1.0")
      assert(result.success?, result.stderr)
      assert_includes(result.stdout, "\n## Added\n")
      refute_includes(result.stdout, "\n### Added\n")
      assert_includes(result.stdout, "- Public release metadata contract.")
      assert_includes(result.stdout, "\n## Security\n")
      assert_includes(result.stdout, "## Install")
      assert_includes(result.stdout, "cargo install --version 0.1.0 runewarp")
      assert_includes(result.stdout, "docker pull runewarp/runewarp:0.1.0")
    end
  end

  def test_render_release_notes_rejects_a_near_match_heading
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: near_match_changelog)
      result = run_command(ruby_script("scripts", "render-release-notes"), "--repo-root", repo_root, "--version", "0.1.0")
      refute(result.success?)
      assert_includes(result.stderr, "does not contain a release entry for 0.1.0")
    end
  end

  def test_render_release_notes_rejects_invalid_subsections_in_the_requested_release
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: invalid_subsection_changelog)
      result = run_command(ruby_script("scripts", "render-release-notes"), "--repo-root", repo_root, "--version", "0.1.0")
      refute(result.success?)
      assert_includes(result.stderr, "invalid changelog subsection: Features")
    end
  end

  def test_render_release_notes_only_validates_the_requested_release_section
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: future_invalid_subsection_changelog)
      result = run_command(ruby_script("scripts", "render-release-notes"), "--repo-root", repo_root, "--version", "0.1.0")
      assert(result.success?, result.stderr)
      assert_includes(result.stdout, "- Public release metadata contract.")
      refute_includes(result.stdout, "Future invalid subsection.")
    end
  end

  private

  def changelog_prelude
    "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n"
  end

  def stable_changelog
    "#{changelog_prelude}## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n"
  end

  def stable_with_unreleased_changelog
    "#{changelog_prelude}## [Unreleased]\n\n### Added\n\n- Work in progress.\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n"
  end

  def unreleased_changelog
    "#{changelog_prelude}## [Unreleased]\n\n### Added\n\n- Upcoming release notes.\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n"
  end

  def invalid_subsection_changelog
    "#{changelog_prelude}## [0.1.0] - 2026-05-29\n\n### Features\n\n- Public release metadata contract.\n"
  end

  def release_notes_changelog
    "#{changelog_prelude}## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n\n### Security\n\n- Stable trust boundaries.\n"
  end

  def near_match_changelog
    "#{changelog_prelude}## [0x1x0] - 2026-05-29\n\n### Added\n\n- Wrong release heading.\n"
  end

  def future_invalid_subsection_changelog
    "#{changelog_prelude}## [0.2.0] - 2026-05-30\n\n### Features\n\n- Future invalid subsection.\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n"
  end
end
