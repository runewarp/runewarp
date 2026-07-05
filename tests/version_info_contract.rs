#[path = "../src/version_info.rs"]
mod version_info;

#[test]
fn stable_versions_print_only_the_package_version() {
    assert_eq!(version_info::cli_version("0.2.0", None).unwrap(), "0.2.0");
    assert_eq!(
        version_info::cli_version("0.2.0", Some("1234567890ab")).unwrap(),
        "0.2.0"
    );
}

#[test]
fn dev_versions_append_the_baked_in_commit_sha() {
    assert_eq!(
        version_info::cli_version(
            "0.3.0-dev",
            Some("1234567890abcdef1234567890abcdef12345678")
        )
        .unwrap(),
        "0.3.0-dev (1234567890ab)"
    );
}

#[test]
fn dev_versions_require_baked_in_commit_metadata() {
    let error = version_info::cli_version("0.3.0-dev", None).unwrap_err();

    assert!(error.contains("RUNEWARP_BUILD_COMMIT must be set"));
}

#[test]
fn dev_versions_reject_non_hex_commit_metadata() {
    let error = version_info::cli_version("0.3.0-dev", Some("not-a-commit")).unwrap_err();

    assert!(error.contains("at least 12 hexadecimal characters"));
}
