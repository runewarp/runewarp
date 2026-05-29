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
        .join("validate-release-gates.sh");

    Command::new("bash")
        .arg(script_path)
        .args(args)
        .arg("--repo-root")
        .arg(repo_root)
        .output()
        .unwrap()
}

fn run_git(repo_root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {args:?}");
}

fn init_git_repo_with_origin_main(repo_root: &Path) {
    let remote_root = repo_root.join("remote.git");
    fs::create_dir_all(&remote_root).unwrap();

    run_git(&remote_root, &["init", "--bare", "-q"]);
    run_git(repo_root, &["init", "-q", "-b", "main"]);
    run_git(repo_root, &["config", "user.name", "Runewarp Tests"]);
    run_git(repo_root, &["config", "user.email", "tests@example.com"]);
    run_git(repo_root, &["config", "commit.gpgsign", "false"]);
    run_git(
        repo_root,
        &["remote", "add", "origin", remote_root.to_str().unwrap()],
    );
    run_git(repo_root, &["add", "Cargo.toml", "CHANGELOG.md"]);
    run_git(repo_root, &["commit", "-qm", "test release gates"]);
    run_git(repo_root, &["push", "-u", "origin", "main"]);
}

fn init_git_repo_with_signed_tag(
    repo_root: &Path,
    tag: &str,
    signer_principal: &str,
) -> std::path::PathBuf {
    init_git_repo_with_origin_main(repo_root);

    let signing_key = repo_root.join("signing-key");
    let allowed_signers = repo_root.join("allowed_signers");
    let keygen_status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            signer_principal,
            "-f",
            signing_key.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(keygen_status.success());

    let public_key = fs::read_to_string(signing_key.with_extension("pub")).unwrap();
    fs::write(allowed_signers, format!("{signer_principal} {public_key}")).unwrap();

    run_git(repo_root, &["config", "gpg.format", "ssh"]);
    run_git(repo_root, &["config", "gpg.ssh.program", "ssh-keygen"]);
    run_git(
        repo_root,
        &["config", "user.signingkey", signing_key.to_str().unwrap()],
    );
    run_git(repo_root, &["tag", "-s", tag, "-m", tag]);

    repo_root.join("allowed_signers")
}

fn write_allowed_signers(repo_root: &Path, signer_principal: &str) -> std::path::PathBuf {
    let signing_key = repo_root.join("alternate-signing-key");
    let allowed_signers = repo_root.join("alternate_allowed_signers");
    let keygen_status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            signer_principal,
            "-f",
            signing_key.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(keygen_status.success());

    let public_key = fs::read_to_string(signing_key.with_extension("pub")).unwrap();
    fs::write(&allowed_signers, format!("{signer_principal} {public_key}")).unwrap();
    allowed_signers
}

#[test]
fn rehearsal_mode_accepts_a_matching_release_tag_without_a_git_tag_object() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    init_git_repo_with_origin_main(temp_dir.path());

    let output = run_validator(temp_dir.path(), &["rehearsal", "--tag", "v0.1.0"]);

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn rehearsal_mode_rejects_a_candidate_commit_outside_origin_main() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    init_git_repo_with_origin_main(temp_dir.path());
    fs::write(temp_dir.path().join("feature.txt"), "feature branch only\n").unwrap();
    run_git(
        temp_dir.path(),
        &["checkout", "-qb", "feature/release-candidate"],
    );
    run_git(temp_dir.path(), &["add", "feature.txt"]);
    run_git(
        temp_dir.path(),
        &["commit", "-qm", "feature-only candidate"],
    );

    let output = run_validator(temp_dir.path(), &["rehearsal", "--tag", "v0.1.0"]);

    assert!(!output.status.success(), "{output:?}");
}

#[test]
fn tag_mode_accepts_an_ssh_signed_tag_from_the_allowed_signers_file() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    let allowed_signers =
        init_git_repo_with_signed_tag(temp_dir.path(), "v0.1.0", "release@test.example");

    let output = run_validator(
        temp_dir.path(),
        &[
            "tag",
            "--tag",
            "v0.1.0",
            "--allowed-signers-file",
            allowed_signers.to_str().unwrap(),
        ],
    );

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn tag_mode_rejects_a_tag_signed_by_an_untrusted_key() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    init_git_repo_with_signed_tag(temp_dir.path(), "v0.1.0", "release@test.example");
    let allowed_signers = write_allowed_signers(temp_dir.path(), "other@test.example");

    let output = run_validator(
        temp_dir.path(),
        &[
            "tag",
            "--tag",
            "v0.1.0",
            "--allowed-signers-file",
            allowed_signers.to_str().unwrap(),
        ],
    );

    assert!(!output.status.success(), "{output:?}");
}

#[test]
fn tag_mode_rejects_a_signed_tag_for_a_commit_outside_origin_main() {
    let temp_dir = TempDir::new().unwrap();
    write_repo_files(
        temp_dir.path(),
        "0.1.0",
        "# Changelog\n\nAll notable changes to Runewarp will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).\n\n## [0.1.0] - 2026-05-29\n\n### Added\n\n- Public release metadata contract.\n",
    );
    init_git_repo_with_origin_main(temp_dir.path());
    fs::write(temp_dir.path().join("feature.txt"), "feature branch only\n").unwrap();
    run_git(
        temp_dir.path(),
        &["checkout", "-qb", "feature/release-candidate"],
    );
    run_git(temp_dir.path(), &["add", "feature.txt"]);
    run_git(
        temp_dir.path(),
        &["commit", "-qm", "feature-only candidate"],
    );

    let signing_key = temp_dir.path().join("feature-signing-key");
    let allowed_signers = temp_dir.path().join("feature_allowed_signers");
    let keygen_status = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "release@test.example",
            "-f",
            signing_key.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(keygen_status.success());
    let public_key = fs::read_to_string(signing_key.with_extension("pub")).unwrap();
    fs::write(
        &allowed_signers,
        format!("release@test.example {public_key}"),
    )
    .unwrap();

    run_git(temp_dir.path(), &["config", "gpg.format", "ssh"]);
    run_git(
        temp_dir.path(),
        &["config", "gpg.ssh.program", "ssh-keygen"],
    );
    run_git(
        temp_dir.path(),
        &["config", "user.signingkey", signing_key.to_str().unwrap()],
    );
    run_git(temp_dir.path(), &["tag", "-s", "v0.1.0", "-m", "v0.1.0"]);

    let output = run_validator(
        temp_dir.path(),
        &[
            "tag",
            "--tag",
            "v0.1.0",
            "--allowed-signers-file",
            allowed_signers.to_str().unwrap(),
        ],
    );

    assert!(!output.status.success(), "{output:?}");
}
