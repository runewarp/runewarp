use std::fs;
use std::net::TcpListener;
use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Writes a Client config that logs startup lines, then fails on the invalid CA file.
fn write_failing_client_config(dir: &Path, log_format: Option<&str>) {
    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(dir)
        .args([
            "client",
            "identity",
            "init",
            "--key",
            "client-identity/client.key",
        ])
        .assert()
        .success();
    fs::write(dir.join("server-ca.pem"), "not a certificate").unwrap();
    let log_format = log_format
        .map(|format| format!("log-format = \"{format}\"\n"))
        .unwrap_or_default();
    fs::write(
        dir.join("client.toml"),
        format!(
            r#"{log_format}
[client]
server-address = "localhost"
server-trust = "ca-file"
server-ca-file = "server-ca.pem"
identity-key = "client-identity/client.key"

[[client.services]]
public-hostnames = ["app.example.test"]
backend-address = "127.0.0.1:443"
"#
        ),
    )
    .unwrap();
}

fn run_failing_client(dir: &Path, extra_args: &[&str]) -> String {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("xdg-state"))
        .args(["client", "--config", "client.toml"])
        .args(extra_args)
        .assert()
        .failure();
    String::from_utf8(assert.get_output().stderr.clone()).unwrap()
}

/// Asserts every line is a JSON envelope and each `(level, message prefix)` appears.
fn assert_json_lines(stderr: &str, expected_messages: &[(&str, &str)]) {
    let lines = stderr
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("line is not JSON ({error}): {line}"))
        })
        .collect::<Vec<_>>();
    assert!(!lines.is_empty(), "expected JSON log lines");
    for line in &lines {
        let object = line.as_object().expect("each line must be a JSON object");
        let timestamp = object["timestamp"].as_str().expect("timestamp string");
        assert!(OffsetDateTime::parse(timestamp, &Rfc3339).is_ok());
        assert!(timestamp.ends_with('Z'));
        assert!(object["level"].is_string());
        assert!(object["message"].is_string());
        assert!(!object.contains_key("target"));
        assert!(!object.contains_key("fields"));
    }
    for (level, message) in expected_messages {
        assert!(
            lines.iter().any(|line| line["level"] == *level
                && line["message"]
                    .as_str()
                    .is_some_and(|text| text.starts_with(message))),
            "missing {level} {message:?} in {stderr}"
        );
    }
}

#[test]
fn client_text_log_format_is_the_default() {
    let tempdir = tempdir().unwrap();
    write_failing_client_config(tempdir.path(), None);

    let stderr = run_failing_client(tempdir.path(), &[]);

    let lines = stderr.lines().collect::<Vec<_>>();
    assert!(!lines.is_empty());
    for line in &lines {
        let (timestamp, rest) = line.split_once(' ').expect("timestamp separator");
        assert!(OffsetDateTime::parse(timestamp, &Rfc3339).is_ok());
        assert!(!line.starts_with('{'));
        assert!(
            ["  INFO ", "  WARN ", " ERROR ", " DEBUG ", " TRACE "]
                .iter()
                .any(|level| format!(" {rest}").starts_with(level)),
            "unexpected text envelope: {line}"
        );
    }
    assert!(
        stderr.contains("  INFO client tunnel connection connecting: server-address=localhost:443")
    );
    assert!(stderr.contains(" ERROR no certificates found in server-ca.pem\n"));
}

#[test]
fn client_json_log_format_from_config_emits_one_object_per_line() {
    let tempdir = tempdir().unwrap();
    write_failing_client_config(tempdir.path(), Some("json"));

    let stderr = run_failing_client(tempdir.path(), &[]);

    assert_json_lines(
        &stderr,
        &[
            (
                "INFO",
                "client tunnel connection connecting: server-address=localhost:443",
            ),
            ("ERROR", "no certificates found in server-ca.pem"),
        ],
    );
}

#[test]
fn client_log_format_flag_overrides_config() {
    let tempdir = tempdir().unwrap();
    write_failing_client_config(tempdir.path(), Some("text"));

    let stderr = run_failing_client(tempdir.path(), &["--log-format", "json"]);

    assert_json_lines(
        &stderr,
        &[("ERROR", "no certificates found in server-ca.pem")],
    );
}

#[test]
fn invalid_log_format_in_config_is_rejected() {
    let tempdir = tempdir().unwrap();
    write_failing_client_config(tempdir.path(), Some("yaml"));

    let stderr = run_failing_client(tempdir.path(), &[]);

    assert!(stderr.contains("failed to parse [config]"), "{stderr}");
    assert!(!stderr.contains("no certificates found"));
}

#[test]
fn invalid_log_format_flag_is_rejected() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "--log-format", "yaml"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("invalid value 'yaml' for '--log-format"));
}

#[test]
fn server_json_log_format_from_flag_logs_bind_failure_as_json() {
    let tempdir = tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_address = occupied.local_addr().unwrap();
    Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .args([
            "server",
            "cert",
            "init",
            "--hostname",
            "tunnel.example.test",
            "--dir",
            "server-cert",
        ])
        .assert()
        .success();
    fs::write(
        tempdir.path().join("server.toml"),
        format!(
            r#"
[server]
hostname = "tunnel.example.test"
cert-dir = "server-cert"
public-bind-address = "{occupied_address}"
tunnel-bind-address = "127.0.0.1:0"

[[server.tunnels]]
public-hostnames = ["app.example.test"]
client-identity = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
"#
        ),
    )
    .unwrap();

    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .current_dir(tempdir.path())
        .env_remove("RUNEWARP_SERVER_HOSTNAME")
        .args(["server", "--config", "server.toml", "--log-format", "json"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert_json_lines(&stderr, &[]);
    assert!(
        stderr.contains(&occupied_address.to_string()),
        "bind failure should name the address: {stderr}"
    );
    drop(occupied);
}

#[test]
fn log_format_flag_is_rejected_for_server_cert_subcommands() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["server", "--log-format", "json", "cert", "renew"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("--log-format is only supported for `runewarp server`"));
}

#[test]
fn log_format_flag_is_rejected_for_client_identity_subcommands() {
    let assert = Command::cargo_bin("runewarp")
        .unwrap()
        .args(["client", "--log-format", "json", "identity", "show"])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("--log-format may be used only with `runewarp client`"));
}
