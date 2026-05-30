# frozen_string_literal: true

module Runewarp
  module ReleaseDocs
    module_function

    def validate_metadata!(mode:, repo_root:, tag_repo_root: nil, release_tag: nil)
      tag_repo_root ||= repo_root

      changelog_path = File.join(repo_root, "CHANGELOG.md")
      cargo_toml_path = File.join(repo_root, "Cargo.toml")

      Core.die("Cargo.toml is required at #{cargo_toml_path}") unless File.file?(cargo_toml_path)
      Core.die("CHANGELOG.md is required at #{changelog_path}") unless File.file?(changelog_path)

      first_line = File.open(changelog_path, "r", encoding: "utf-8", &:readline).chomp
      Core.die("CHANGELOG.md must start with a '# Changelog' heading") unless first_line == "# Changelog"

      cargo_version = Core.runewarp_version(repo_root)
      Core.die("failed to read version from Cargo.toml") if cargo_version.nil? || cargo_version.empty?

      validate_ci_mode!(cargo_version, changelog_path)
      validate_release_mode!(repo_root, tag_repo_root, cargo_version, release_tag) if mode == "release"

      Core.success("release metadata is valid")
    end

    def validate_ci_mode!(cargo_version, changelog_path)
      first_heading = Changelog.first_h2_heading(changelog_path)
      Core.die("CHANGELOG.md must contain at least one level-2 section heading") if first_heading.nil? || first_heading.empty?

      normalized_first_heading = Changelog.normalize_heading(first_heading)
      Changelog.validate_release_headings!(changelog_path)
      Changelog.validate_subsection_headings!(changelog_path)

      if ReleaseMetadata.stable_version?(cargo_version)
        release_heading = Changelog.find_release_heading(changelog_path, cargo_version)
        Core.die("stable Cargo version #{cargo_version} requires a matching changelog release entry") if release_heading.nil? || release_heading.empty?
        Core.die("stable Cargo version #{cargo_version} must not keep an Unreleased section") if Changelog.unreleased_heading?(changelog_path)
        Core.die("stable Cargo version #{cargo_version} requires the top changelog section to match that release") unless first_heading.start_with?("[#{cargo_version}]")
        Core.die("release entry #{cargo_version} must contain at least one bullet item") unless Changelog.section_has_list_item?(changelog_path, release_heading)
        return
      end

      Core.die("pre-release Cargo version #{cargo_version} requires Unreleased to be the top changelog section") unless normalized_first_heading == "Unreleased"
      Core.die("pre-release Cargo version #{cargo_version} requires an Unreleased section") unless Changelog.unreleased_heading?(changelog_path)
    end

    def validate_release_mode!(repo_root, tag_repo_root, cargo_version, release_tag)
      Core.die("release mode requires --tag vX.Y.Z") if release_tag.nil? || release_tag.empty?
      Core.die("release mode requires a stable Cargo version, found #{cargo_version}") unless ReleaseMetadata.stable_version?(cargo_version)

      expected_tag = ReleaseMetadata.tag_from_version(cargo_version)
      Core.die("release tag #{release_tag} must match Cargo version #{cargo_version} as #{expected_tag}") unless release_tag == expected_tag

      tag_commit = Shell.capture!("git", "-C", tag_repo_root, "rev-list", "-n1", release_tag, allow_failure: true).strip
      Core.die("git tag #{release_tag} does not exist in #{tag_repo_root}") if tag_commit.empty?

      head_commit = Shell.capture!("git", "-C", repo_root, "rev-parse", "HEAD").strip
      Core.die("git tag #{release_tag} must point at HEAD") unless tag_commit == head_commit

      render_release_notes(repo_root: repo_root, version: cargo_version)
    end

    def render_release_notes(repo_root:, version:)
      changelog_path = File.join(repo_root, "CHANGELOG.md")
      Core.die("CHANGELOG.md is required at #{changelog_path}") unless File.file?(changelog_path)

      release_heading = Changelog.find_release_heading(changelog_path, version)
      Core.die("CHANGELOG.md does not contain a release entry for #{version}") if release_heading.nil? || release_heading.empty?

      Changelog.validate_section_subsection_headings!(changelog_path, release_heading)
      release_body = Changelog.print_release_section(changelog_path, release_heading)

      "#{release_body}\n\n## Install\n\n```bash\ncargo install --version #{version} runewarp\ndocker pull runewarp/runewarp:#{version}\n```\n"
    end
  end
end
