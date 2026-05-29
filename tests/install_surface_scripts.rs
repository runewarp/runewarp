use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn run_validator(repo_root: &Path, args: &[&str]) -> Output {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("validate-install-surfaces.sh");

    Command::new("bash")
        .arg(script_path)
        .args(args)
        .arg("--repo-root")
        .arg(repo_root)
        .output()
        .unwrap()
}

fn write_minimal_binary_crate(repo_root: &Path, version: &str) {
    fs::create_dir_all(repo_root.join("src")).unwrap();
    fs::write(
        repo_root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"install-surface-fixture\"\nversion = \"{version}\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\n"
        ),
    )
    .unwrap();
    fs::write(
        repo_root.join("src").join("main.rs"),
        "fn main() {\n    if std::env::args().nth(1).as_deref() == Some(\"--version\") {\n        println!(\"install-surface-fixture {}\", env!(\"CARGO_PKG_VERSION\"));\n        return;\n    }\n\n    println!(\"fixture\");\n}\n",
    )
    .unwrap();

    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(repo_root)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn cargo_install_mode_installs_the_binary_and_checks_its_version() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let output = run_validator(
        temp_dir.path(),
        &[
            "cargo-install",
            "--bin-name",
            "install-surface-fixture",
            "--expected-version",
            "0.3.1",
        ],
    );

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn package_readiness_mode_accepts_a_publishable_crate() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let output = run_validator(temp_dir.path(), &["package-readiness"]);

    assert!(output.status.success(), "{output:?}");
}
