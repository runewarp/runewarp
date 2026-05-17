use assert_cmd::Command;

#[test]
fn no_args_prints_the_available_commands() {
    let assert = Command::cargo_bin("runewarp").unwrap().assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Available commands"));
    assert!(stdout.contains("server"));
    assert!(stdout.contains("client"));
    assert!(!stdout.contains("keygen"));
}

#[test]
fn unknown_command_prints_the_available_commands() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .arg("warp")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("unrecognized command: warp"));
    assert!(stdout.contains("Available commands"));
    assert!(stdout.contains("server"));
    assert!(stdout.contains("client"));
    assert!(!stdout.contains("keygen"));
}

#[test]
fn keygen_is_rejected_as_an_unrecognized_command() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .arg("keygen")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("unrecognized command: keygen"));
    assert!(
        stdout
            .lines()
            .any(|line| line == "Available commands: server, client")
    );
}

#[test]
fn server_help_prints_the_server_surface() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["server", "--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Available server commands"));
    assert!(stdout.contains("cert"));
    assert!(stdout.contains("--config"));
}

#[test]
fn client_help_prints_the_client_surface() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "--help"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Available client commands"));
    assert!(stdout.contains("identity"));
    assert!(stdout.contains("--config"));
}
