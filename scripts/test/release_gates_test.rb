# frozen_string_literal: true

require_relative "support/test_helper"

class ReleaseGatesTest < Minitest::Test
  def write_repo_files(repo_root, version:, changelog:)
    File.write(File.join(repo_root, "Cargo.toml"), <<~TOML, encoding: "utf-8")
      [package]
      name = "runewarp"
      version = "#{version}"
      edition = "2024"
    TOML
    File.write(File.join(repo_root, "CHANGELOG.md"), changelog, encoding: "utf-8")
  end

  def run_git(repo_root, *arguments)
    system("git", "-C", repo_root, *arguments, exception: true)
  end

  def init_git_repo_with_origin_main(repo_root)
    remote_root = File.join(repo_root, "remote.git")
    FileUtils.mkdir_p(remote_root)
    run_git(remote_root, "init", "--bare", "-q")
    run_git(repo_root, "init", "-q", "-b", "main")
    run_git(repo_root, "config", "user.name", "Runewarp Tests")
    run_git(repo_root, "config", "user.email", "tests@example.com")
    run_git(repo_root, "config", "commit.gpgsign", "false")
    run_git(repo_root, "remote", "add", "origin", remote_root)
    run_git(repo_root, "add", "Cargo.toml", "CHANGELOG.md")
    run_git(repo_root, "commit", "-qm", "test release gates")
    run_git(repo_root, "push", "-u", "origin", "main")
  end

  def init_git_repo_with_signed_tag(repo_root, tag, signer_principal)
    init_git_repo_with_origin_main(repo_root)

    signing_key = File.join(repo_root, "signing-key")
    allowed_signers = File.join(repo_root, "allowed_signers")
    system("ssh-keygen", "-t", "ed25519", "-N", "", "-C", signer_principal, "-f", signing_key, out: File::NULL, exception: true)
    public_key = File.read("#{signing_key}.pub", encoding: "utf-8")
    File.write(allowed_signers, "#{signer_principal} #{public_key}", encoding: "utf-8")

    run_git(repo_root, "config", "gpg.format", "ssh")
    run_git(repo_root, "config", "gpg.ssh.program", "ssh-keygen")
    run_git(repo_root, "config", "user.signingkey", signing_key)
    run_git(repo_root, "tag", "-s", tag, "-m", tag)
    allowed_signers
  end

  def write_allowed_signers(repo_root, signer_principal)
    signing_key = File.join(repo_root, "alternate-signing-key")
    allowed_signers = File.join(repo_root, "alternate_allowed_signers")
    system("ssh-keygen", "-t", "ed25519", "-N", "", "-C", signer_principal, "-f", signing_key, out: File::NULL, exception: true)
    public_key = File.read("#{signing_key}.pub", encoding: "utf-8")
    File.write(allowed_signers, "#{signer_principal} #{public_key}", encoding: "utf-8")
    allowed_signers
  end

  def test_rehearsal_mode_accepts_a_matching_release_tag_without_a_git_tag_object
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      init_git_repo_with_origin_main(repo_root)
      result = run_command(ruby_script("scripts", "validate_release_gates"), "rehearsal", "--repo-root", repo_root, "--tag", "v0.1.0")
      assert(result.success?, result.stderr)
    end
  end

  def test_rehearsal_mode_rejects_a_candidate_commit_outside_origin_main
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      init_git_repo_with_origin_main(repo_root)
      File.write(File.join(repo_root, "feature.txt"), "feature branch only\n", encoding: "utf-8")
      run_git(repo_root, "checkout", "-qb", "feature/release-candidate")
      run_git(repo_root, "add", "feature.txt")
      run_git(repo_root, "commit", "-qm", "feature-only candidate")

      result = run_command(ruby_script("scripts", "validate_release_gates"), "rehearsal", "--repo-root", repo_root, "--tag", "v0.1.0")
      refute(result.success?)
    end
  end

  def test_tag_mode_accepts_an_ssh_signed_tag_from_the_allowed_signers_file
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      allowed_signers = init_git_repo_with_signed_tag(repo_root, "v0.1.0", "release@test.example")
      result = run_command(ruby_script("scripts", "validate_release_gates"), "tag", "--repo-root", repo_root, "--tag", "v0.1.0", "--allowed-signers-file", allowed_signers)
      assert(result.success?, result.stderr)
    end
  end

  def test_tag_mode_can_validate_tagged_release_metadata_from_a_separate_source_tree
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      allowed_signers = init_git_repo_with_signed_tag(repo_root, "v0.1.0", "release@test.example")
      write_repo_files(repo_root, version: "0.2.0-dev", changelog: unreleased_changelog)
      run_git(repo_root, "add", "Cargo.toml", "CHANGELOG.md")
      run_git(repo_root, "commit", "-qm", "post release main")
      run_git(repo_root, "push")

      release_source = File.join(repo_root, "release-source")
      system("git", "clone", "-q", repo_root, release_source, exception: true)
      run_git(release_source, "checkout", "-q", "v0.1.0")

      result = run_command(ruby_script("scripts", "validate_release_gates"), "tag", "--repo-root", repo_root, "--tag", "v0.1.0", "--allowed-signers-file", allowed_signers, "--metadata-repo-root", release_source)
      assert(result.success?, result.stderr)
    end
  end

  def test_tag_mode_rejects_a_tag_signed_by_an_untrusted_key
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      init_git_repo_with_signed_tag(repo_root, "v0.1.0", "release@test.example")
      allowed_signers = write_allowed_signers(repo_root, "other@test.example")
      result = run_command(ruby_script("scripts", "validate_release_gates"), "tag", "--repo-root", repo_root, "--tag", "v0.1.0", "--allowed-signers-file", allowed_signers)
      refute(result.success?)
    end
  end

  def test_tag_mode_rejects_a_signed_tag_for_a_commit_outside_origin_main
    Dir.mktmpdir do |repo_root|
      write_repo_files(repo_root, version: "0.1.0", changelog: stable_changelog)
      init_git_repo_with_origin_main(repo_root)
      File.write(File.join(repo_root, "feature.txt"), "feature branch only\n", encoding: "utf-8")
      run_git(repo_root, "checkout", "-qb", "feature/release-candidate")
      run_git(repo_root, "add", "feature.txt")
      run_git(repo_root, "commit", "-qm", "feature-only candidate")

      signing_key = File.join(repo_root, "feature-signing-key")
      allowed_signers = File.join(repo_root, "feature_allowed_signers")
      system("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "release@test.example", "-f", signing_key, out: File::NULL, exception: true)
      public_key = File.read("#{signing_key}.pub", encoding: "utf-8")
      File.write(allowed_signers, "release@test.example #{public_key}", encoding: "utf-8")
      run_git(repo_root, "config", "gpg.format", "ssh")
      run_git(repo_root, "config", "gpg.ssh.program", "ssh-keygen")
      run_git(repo_root, "config", "user.signingkey", signing_key)
      run_git(repo_root, "tag", "-s", "v0.1.0", "-m", "v0.1.0")

      result = run_command(ruby_script("scripts", "validate_release_gates"), "tag", "--repo-root", repo_root, "--tag", "v0.1.0", "--allowed-signers-file", allowed_signers)
      refute(result.success?)
    end
  end

  private

  def changelog_prelude
    "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n"
  end

  def stable_changelog
    "#{changelog_prelude}## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n"
  end

  def unreleased_changelog
    "#{changelog_prelude}## [Unreleased]\n\n### Changed\n\n- Start the next development cycle.\n"
  end
end
