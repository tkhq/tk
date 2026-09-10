use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

#[test]
fn config_command_help_lists_subcommands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.args(["config", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("list"));
}

#[test]
fn config_round_trip() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut set_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    set_cmd
        .args(["config", "set", "turnkey.organizationId", "persisted-org"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    set_cmd.assert().success();

    let stored = fs::read_to_string(&config_path).expect("config file should exist");
    assert!(stored.contains("organizationId = \"persisted-org\""));

    let mut get_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    get_cmd
        .args(["config", "get", "turnkey.organizationId"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    get_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("persisted-org"));

    let mut list_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    list_cmd
        .args(["config", "list"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env("TURNKEY_ORGANIZATION_ID", "env-org")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    let output = list_cmd.assert().success().get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&output).expect("config list should output json");
    assert_eq!(value["turnkey"]["organizationId"], "env-org");
}

#[test]
fn config_list_and_get_redact_private_key() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut set_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    set_cmd
        .args([
            "config",
            "set",
            "turnkey.apiPrivateKey",
            "persisted-private-key",
        ])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    set_cmd.assert().success();

    let mut list_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    list_cmd
        .args(["config", "list"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    let output = list_cmd.assert().success().get_output().stdout.clone();
    let value: Value = serde_json::from_slice(&output).expect("config list should output json");
    assert_eq!(value["turnkey"]["apiPrivateKey"], "<redacted>");
    assert!(!String::from_utf8_lossy(&output).contains("persisted-private-key"));

    let mut get_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    get_cmd
        .args(["config", "get", "turnkey.apiPrivateKey"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    get_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("<redacted>"))
        .stdout(predicate::str::contains("persisted-private-key").not());
}

#[test]
fn config_set_writes_owner_only_file() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mode = |path: &std::path::Path| {
        fs::metadata(path)
            .expect("config file should exist")
            .permissions()
            .mode()
            & 0o777
    };

    let mut set_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    set_cmd
        .args(["config", "set", "turnkey.apiPrivateKey", "persisted-key"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);
    set_cmd.assert().success();
    assert_eq!(mode(&config_path), 0o600);

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))
        .expect("permissions should update");

    let mut set_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    set_cmd
        .args(["config", "set", "turnkey.organizationId", "persisted-org"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);
    set_cmd.assert().success();
    assert_eq!(mode(&config_path), 0o600);
}

// Exact Clap golden shared by the get/set usage-error tests.
const UNSUPPORTED_KEY_MESSAGE: &str = r#"error: invalid value 'not.a.key' for '<KEY>': unsupported config key: not.a.key; supported keys: turnkey.organizationId, turnkey.apiPublicKey, turnkey.apiPrivateKey, turnkey.privateKeyId, turnkey.apiBaseUrl

For more information, try '--help'."#;

#[test]
fn config_get_rejects_unsupported_key_in_human_mode() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let assert = cmd
        .args(["config", "get", "not.a.key"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let stderr = String::from_utf8(assert.get_output().stderr.clone())
        .expect("stderr should be valid utf-8");
    assert_eq!(stderr.trim_end(), UNSUPPORTED_KEY_MESSAGE);
    assert!(!config_path.exists(), "a usage error must not touch config");
}

#[test]
fn config_set_rejects_unsupported_key_in_human_mode() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let assert = cmd
        .args(["config", "set", "not.a.key", "some-value"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let stderr = String::from_utf8(assert.get_output().stderr.clone())
        .expect("stderr should be valid utf-8");
    assert_eq!(stderr.trim_end(), UNSUPPORTED_KEY_MESSAGE);
    assert!(!config_path.exists(), "a usage error must not touch config");
}

#[test]
fn config_get_unsupported_key_json_emits_usage_error_envelope() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = cmd
        .args(["config", "get", "not.a.key", "--message-format=json"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).expect("stdout should be one JSON object");
    assert_eq!(
        record,
        serde_json::json!({
            "reason": "command_error",
            "code": "usage_error",
            "message": UNSUPPORTED_KEY_MESSAGE,
        })
    );
    assert!(!config_path.exists(), "a usage error must not touch config");
}

#[test]
fn config_set_unsupported_key_json_emits_usage_error_envelope() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = cmd
        .args([
            "config",
            "set",
            "not.a.key",
            "some-value",
            "--message-format=json",
        ])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).expect("stdout should be one JSON object");
    assert_eq!(
        record,
        serde_json::json!({
            "reason": "command_error",
            "code": "usage_error",
            "message": UNSUPPORTED_KEY_MESSAGE,
        })
    );
    assert!(!config_path.exists(), "a usage error must not touch config");
}
