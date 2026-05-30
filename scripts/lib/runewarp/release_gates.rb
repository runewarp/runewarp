#!/usr/bin/env ruby
# frozen_string_literal: true

module Runewarp
  module ReleaseGates
    module_function

    def validate!(mode:, repo_root:, metadata_repo_root: nil, release_tag:, allowed_signers_file: nil)
      metadata_repo_root ||= repo_root

      case mode
      when "rehearsal"
        validate_rehearsal_mode!(repo_root, metadata_repo_root, release_tag)
      when "tag"
        validate_tag_mode!(repo_root, metadata_repo_root, release_tag, allowed_signers_file)
      else
        Core.usage_error("validate-release-gates.rb <rehearsal|tag> [--repo-root PATH] [--metadata-repo-root PATH] --tag vX.Y.Z [--allowed-signers-file PATH]")
      end
    end

    def require_commit_reachable_from_main(repo_root, candidate_ref)
      main_ref = "refs/remotes/origin/main"

      Core.require_command("git")
      Core.die("candidate ref #{candidate_ref} does not exist in #{repo_root}") unless Shell.successful?("git", "-C", repo_root, "rev-parse", "--verify", "#{candidate_ref}^{commit}")
      Core.die("main ref #{main_ref} does not exist in #{repo_root}") unless Shell.successful?("git", "-C", repo_root, "rev-parse", "--verify", "#{main_ref}^{commit}")
      Core.die("candidate ref #{candidate_ref} must be reachable from #{main_ref}") unless Shell.successful?("git", "-C", repo_root, "merge-base", "--is-ancestor", candidate_ref, main_ref)
    end

    def validate_rehearsal_mode!(repo_root, metadata_repo_root, release_tag)
      Core.die("rehearsal mode requires --tag vX.Y.Z") if release_tag.nil? || release_tag.empty?

      cargo_version = Core.runewarp_version(metadata_repo_root)
      Core.die("failed to read version from Cargo.toml") if cargo_version.nil? || cargo_version.empty?
      Core.die("rehearsal mode requires a stable Cargo version, found #{cargo_version}") unless ReleaseMetadata.stable_version?(cargo_version)

      expected_tag = ReleaseMetadata.tag_from_version(cargo_version)
      Core.die("rehearsal tag #{release_tag} must match Cargo version #{cargo_version} as #{expected_tag}") unless release_tag == expected_tag

      require_commit_reachable_from_main(repo_root, "HEAD")
      ReleaseDocs.validate_metadata!(mode: "ci", repo_root: metadata_repo_root)
      ReleaseDocs.render_release_notes(repo_root: metadata_repo_root, version: cargo_version)
      Core.success("release rehearsal gate is valid")
    end

    def validate_tag_mode!(repo_root, metadata_repo_root, release_tag, allowed_signers_file)
      Core.die("tag mode requires --tag vX.Y.Z") if release_tag.nil? || release_tag.empty?
      Core.die("tag mode requires --allowed-signers-file") if allowed_signers_file.nil? || allowed_signers_file.empty?
      Core.die("allowed signers file is required at #{allowed_signers_file}") unless File.file?(allowed_signers_file)

      Core.require_command("git")
      ReleaseDocs.validate_metadata!(mode: "release", repo_root: metadata_repo_root, tag_repo_root: repo_root, release_tag: release_tag)
      require_commit_reachable_from_main(repo_root, release_tag)

      Core.section("Verifying signed release tag")
      Core.note("Tag: #{release_tag}")
      Core.note("Allowed signers: #{allowed_signers_file}")

      Shell.run!(
        "git",
        "-C",
        repo_root,
        "-c",
        "gpg.format=ssh",
        "-c",
        "gpg.ssh.program=ssh-keygen",
        "-c",
        "gpg.ssh.allowedSignersFile=#{allowed_signers_file}",
        "verify-tag",
        release_tag,
        out: File::NULL
      )

      Core.success("release tag gate is valid")
    end
  end
end
