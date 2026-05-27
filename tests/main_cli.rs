use assert_cmd::Command;

#[test]
fn no_args_prints_the_top_level_help() {
    let assert = Command::cargo_bin("runewarp").unwrap().assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Public ingress. Private by design."));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("server"));
    assert!(stdout.contains("client"));
}

#[test]
fn top_level_help_identifies_runewarp_in_the_product_line() -> Result<(), Box<dyn std::error::Error>>
{
    let assert = Command::cargo_bin("runewarp")?
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.starts_with("Runewarp: Public ingress. Private by design."));
    Ok(())
}

#[test]
fn top_level_help_drops_the_config_defaults_footer() -> Result<(), Box<dyn std::error::Error>> {
    let assert = Command::cargo_bin("runewarp")?
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(!stdout.contains("Config defaults:"));
    Ok(())
}

#[test]
fn help_subcommand_prints_the_top_level_help() -> Result<(), Box<dyn std::error::Error>> {
    let assert = Command::cargo_bin("runewarp")?
        .arg("help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.starts_with("Runewarp: Public ingress. Private by design."));
    assert!(stdout.contains("Usage: runewarp [COMMAND]"));
    Ok(())
}

#[test]
fn top_level_help_describes_the_main_entry_points() -> Result<(), Box<dyn std::error::Error>> {
    let assert = Command::cargo_bin("runewarp")?
        .arg("--help")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone())?;

    assert!(stdout.contains("server  Operate the Server runtime and setup commands"));
    assert!(stdout.contains("client  Operate the Client runtime and setup commands"));
    Ok(())
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
