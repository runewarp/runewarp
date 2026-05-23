use assert_cmd::Command;

#[test]
fn no_args_prints_the_top_level_help() {
    let assert = Command::cargo_bin("runewarp").unwrap().assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Private tunneling for TLS passthrough"));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("server"));
    assert!(stdout.contains("client"));
}

#[test]
fn unknown_command_is_rejected_with_cli_usage() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .arg("warp")
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("unrecognized subcommand 'warp'"));
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("For more information, try '--help'."));
}

#[test]
fn keygen_is_rejected_as_an_unrecognized_command() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .arg("keygen")
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    assert!(stderr.contains("unrecognized subcommand 'keygen'"));
    assert!(stderr.contains("Usage: runewarp [COMMAND]"));
}
