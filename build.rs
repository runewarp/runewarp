#[path = "src/version_info.rs"]
mod version_info;

fn main() {
    let package_version =
        std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION must be set");
    let build_commit = std::env::var(version_info::BUILD_COMMIT_ENV)
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(git_commit);
    let cli_version = version_info::cli_version(&package_version, build_commit.as_deref())
        .unwrap_or_else(|message| panic!("{message}"));

    println!("cargo:rustc-env=RUNEWARP_CLI_VERSION={cli_version}");
}

fn git_commit() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8(output.stdout).ok()?;
    let trimmed = commit.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.to_owned())
}
