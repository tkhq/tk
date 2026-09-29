//! Tests for top-level CLI parsing.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};

#[test]
fn cli_help_lists_registry_ssh_commands() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    command.arg("--help");
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh"))
        .stdout(predicate::str::contains("gpg"))
        .stdout(predicate::str::contains("TK_CONFIG").not())
        .stdout(predicate::str::contains("TURNKEY_ORGANIZATION_ID"))
        .stdout(predicate::str::contains("TURNKEY_PRIVATE_KEY_ID").not())
        .stdout(predicate::str::contains("TURNKEY_TK_CONFIG_PATH").not())
        .stdout(predicate::str::contains(
            "export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock",
        ));

    let mut ssh = Command::new(env!("CARGO_BIN_EXE_tk"));
    ssh.args(["ssh", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keys"))
        .stdout(predicate::str::contains("public-key"))
        .stdout(predicate::str::contains("git-sign"))
        .stdout(predicate::str::contains("agent"));

    let mut start = Command::new(env!("CARGO_BIN_EXE_tk"));
    start
        .args(["ssh", "agent", "start", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--key"))
        .stdout(predicate::str::contains("--socket"))
        .stdout(predicate::str::contains("--pid-file"))
        .stdout(predicate::str::contains("--socket-mode <SOCKET_MODE>"));

    let mut gpg = Command::new(env!("CARGO_BIN_EXE_tk"));
    gpg.args(["gpg", "agent", "serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--key <KEY>"))
        .stdout(predicate::str::contains("--socket <PATH>"))
        .stdout(predicate::str::contains("--socket-mode <SOCKET_MODE>"))
        .stdout(predicate::str::contains("foreground"));
}

#[test]
fn version_reports_the_manifest_version() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    command.arg("-V");
    command
        .assert()
        .success()
        .stdout(format!("tk {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn config_command_is_unknown() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = command
        .args(["--message-format=json", "config", "list"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let record: Value = serde_json::from_slice(&output).expect("usage error is JSON");
    assert_eq!(record["code"], "usage_error");
}

#[test]
fn config_path_flag_is_unknown_and_environment_is_ignored() {
    let home = tempfile::tempdir().expect("temporary home");
    let alternate = home.path().join("alternate.toml");
    std::fs::write(&alternate, "malformed alternate registry").expect("write alternate registry");

    let mut flag = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = flag
        .args([
            "--message-format=json",
            "--config",
            "registry.toml",
            "auth",
            "status",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let record: Value = serde_json::from_slice(&output).expect("usage error is JSON");
    assert_eq!(record["code"], "usage_error");
    assert!(
        record["message"]
            .as_str()
            .is_some_and(|message| message.contains("unexpected argument '--config'"))
    );

    let mut environment = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = environment
        .args(["--message-format=json", "profile", "list"])
        .env("HOME", home.path())
        .env("TK_CONFIG", alternate)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).expect("profile list is JSON"),
        json!({
            "schemaVersion": 1,
            "reason": "command_result",
            "command": "profile.list",
            "status": "completed",
            "data": {
                "activeProfile": null,
                "profiles": {},
            },
        })
    );
}

#[test]
fn empty_ssh_registry_is_an_invalid_input() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = command
        .args(["--message-format=json", "ssh", "public-key"])
        .env("HOME", directory.path())
        .env_remove("TK_PROFILE")
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let record: Value = serde_json::from_slice(&output).expect("runtime error is JSON");
    assert_eq!(record["code"], "invalid_input");
    assert_eq!(
        record["message"],
        "the registry holds no SSH keys; register one with tk ssh keys add --private-key-id ID"
    );
}

#[test]
fn usage_errors_follow_the_json_protocol() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    let result = command
        .args(["--message-format=json", "unknown-command"])
        .assert()
        .code(2);
    let record: Value =
        serde_json::from_slice(&result.get_output().stdout).expect("usage error is JSON");
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "usage_error");
    assert!(result.get_output().stderr.is_empty());
}

#[test]
fn profile_set_requires_a_change_and_agent_keys_repeat() {
    let mut profile = Command::new(env!("CARGO_BIN_EXE_tk"));
    profile
        .args(["profile", "set", "work"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "profile set requires --organization-id, --api-base-url, or --api-key-file",
        ));

    let mut remove = Command::new(env!("CARGO_BIN_EXE_tk"));
    remove
        .args(["ssh", "keys", "remove"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("<KEY>"));

    let directory = tempfile::tempdir().expect("temporary directory");
    let mut agent = Command::new(env!("CARGO_BIN_EXE_tk"));
    agent
        .args(["ssh", "agent", "start", "--key", "first", "--key", "second"])
        .env("HOME", directory.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("registry holds no SSH keys"));
}
