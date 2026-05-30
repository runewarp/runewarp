use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn write_repo_files(repo_root: &Path, version: &str, changelog: &str) {
    fs::write(
        repo_root.join("Cargo.toml"),
        format!("[package]\nname = \"runewarp\"\nversion = \"{version}\"\nedition = \"2024\"\n"),
    )
    .unwrap();
    fs::write(repo_root.join("CHANGELOG.md"), changelog).unwrap();
}

fn run_validator(repo_root: &Path, args: &[&str]) -> Output {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("validate-release-metadata.sh");

    Command::new("bash")
        .arg(script_path)
        .args(args)
        .arg("--repo-root")
        .arg(repo_root)
        .output()
        .unwrap()
}

fn run_release_notes(repo_root: &Path, version: &str) -> Output {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("render-release-notes.sh");

    Command::new("bash")
        .arg(script_path)
        .arg("--repo-root")
        .arg(repo_root)
        .arg("--version")
        .arg(version)
        .output()
        .unwrap()
}

fn init_git_repo(repo_root: &Path, tag: &str) {
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(repo_root)
            .status()
            .unwrap();
        assert!(status.success(), "git command failed: {args:?}");
    };

    run(&["init", "-q"]);
    run(&["config", "user.name", "Runewarp Tests"]);
    run(&["config", "user.email", "tests@example.com"]);
    run(&["config", "commit.gpgsign", "false"]);
    run(&["add", "Cargo.toml", "CHANGELOG.md"]);
    run(&["commit", "-qm", "test release metadata"]);
    run(&["tag", "-a", tag, "-m", tag]);
}

#[test]
fn ci_mode_accepts_a_stable_release_entry_without_unreleased() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );

    let output = run_validator(temp_dir.path(), &["ci"]);
    assert!(output.status.success());
}

#[test]
fn ci_mode_rejects_unreleased_for_a_stable_version() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## Unreleased\n\n### Added\n\n- Work in progress.\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );

    let output = run_validator(temp_dir.path(), &["ci"]);
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("must not keep an Unreleased section"));
}

#[test]
fn ci_mode_accepts_a_dev_version_with_unreleased() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.2.0-dev",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## Unreleased\n\n### Added\n\n- Upcoming release notes.\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );

    let output = run_validator(temp_dir.path(), &["ci"]);
    assert!(output.status.success());
}

#[test]
fn ci_mode_rejects_nonstandard_changelog_subsections() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Features\n\n- Public release metadata contract.\n",
    );

    let output = run_validator(temp_dir.path(), &["ci"]);
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid changelog subsection: Features"));
}

#[test]
fn release_mode_requires_a_matching_head_tag() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    init_git_repo(temp_dir.path(), "v0.1.0");

    let output = run_validator(temp_dir.path(), &["release", "--tag", "v0.1.0"]);
    assert!(output.status.success());
}

#[test]
fn release_mode_rejects_a_mismatched_tag() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    init_git_repo(temp_dir.path(), "v0.1.0");

    let output = run_validator(temp_dir.path(), &["release", "--tag", "v0.1.1"]);
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("must match Cargo version 0.1.0"));
}

#[test]
fn render_release_notes_outputs_the_changelog_entry_and_install_appendix() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n\n### Security\n\n- Stable trust boundaries.\n",
    );

    let output = run_release_notes(temp_dir.path(), "0.1.0");
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\n## Added\n"));
    assert!(!stdout.contains("\n### Added\n"));
    assert!(stdout.contains("- Public release metadata contract."));
    assert!(stdout.contains("\n## Security\n"));
    assert!(stdout.contains("## Install"));
    assert!(stdout.contains("cargo install --version 0.1.0 runewarp"));
    assert!(stdout.contains("docker pull runewarp/runewarp:0.1.0"));
}
