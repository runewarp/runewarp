pub(crate) const BUILD_COMMIT_ENV: &str = "RUNEWARP_BUILD_COMMIT";

const DEV_SUFFIX: &str = "-dev";

pub(crate) fn cli_version(
    package_version: &str,
    build_commit: Option<&str>,
) -> Result<String, String> {
    match short_build_commit(package_version, build_commit)? {
        Some(commit) => Ok(format!("{package_version} ({commit})")),
        None => Ok(package_version.to_owned()),
    }
}

fn short_build_commit(
    package_version: &str,
    build_commit: Option<&str>,
) -> Result<Option<String>, String> {
    if !package_version.ends_with(DEV_SUFFIX) {
        return Ok(None);
    }

    let commit = build_commit.ok_or_else(|| {
        format!(
            "error: {BUILD_COMMIT_ENV} must be set for -dev builds so --version can report the baked-in commit SHA"
        )
    })?;

    if commit.len() < 12
        || !commit
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(format!(
            "error: {BUILD_COMMIT_ENV} must contain at least 12 hexadecimal characters for -dev builds"
        ));
    }

    Ok(Some(commit[..12].to_owned()))
}
