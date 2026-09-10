use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn cli_help_lists_commands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("activity"))
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("ssh"))
        .stdout(predicate::str::contains("TURNKEY_ORGANIZATION_ID"))
        .stdout(predicate::str::contains("TURNKEY_API_PUBLIC_KEY"))
        .stdout(predicate::str::contains("TURNKEY_API_PRIVATE_KEY"))
        .stdout(predicate::str::contains("TURNKEY_PRIVATE_KEY_ID"))
        .stdout(predicate::str::contains("TURNKEY_API_BASE_URL"))
        .stdout(predicate::str::contains("TURNKEY_TK_CONFIG_PATH"))
        .stdout(predicate::str::contains("~/.config/turnkey/tk/tk.toml"))
        .stdout(predicate::str::contains("ssh       SSH related commands"))
        .stdout(predicate::str::contains("tk ssh agent start"))
        .stdout(predicate::str::contains(
            "export SSH_AUTH_SOCK=~/.config/turnkey/tk/ssh-agent.sock",
        ));

    let mut agent_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    agent_cmd.arg("ssh").arg("--help");

    agent_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("agent"))
        .stdout(predicate::str::contains("public-key"))
        .stdout(predicate::str::contains("git-sign"))
        .stdout(predicate::str::contains(
            "Manage a background SSH agent over a Unix socket",
        ))
        .stdout(predicate::str::contains(
            "Print the configured SSH public key",
        ))
        .stdout(predicate::str::contains(
            "Sign a payload using the Git SSH signer interface",
        ))
        .stdout(predicate::str::contains("tk ssh [OPTIONS] <COMMAND>"));

    let mut nested_agent_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    nested_agent_cmd.arg("ssh").arg("agent").arg("--help");

    nested_agent_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("start"))
        .stdout(predicate::str::contains("stop"))
        .stdout(predicate::str::contains("status"));

    let mut start_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    start_cmd.arg("ssh").arg("agent").arg("start").arg("--help");

    start_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("--socket"))
        .stdout(predicate::str::contains("--pid-file"));
}

#[test]
fn public_key_requires_turnkey_org_id() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("ssh")
        .arg("public-key")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("turnkey.organizationId"));
}

#[test]
fn json_mode_emits_ndjson_outcomes() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let mut set_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let set_output = set_cmd
        .args([
            "config",
            "set",
            "turnkey.organizationId",
            "json-org",
            "--message-format=json",
        ])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let record: serde_json::Value = serde_json::from_slice(&set_output).unwrap();
    assert_eq!(record["reason"], "config_value_set");
    assert_eq!(record["key"], "turnkey.organizationId");

    let mut get_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let get_output = get_cmd
        .args([
            "config",
            "get",
            "turnkey.organizationId",
            "--message-format=json",
        ])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let record: serde_json::Value = serde_json::from_slice(&get_output).unwrap();
    assert_eq!(record["reason"], "config_value");
    assert_eq!(record["value"], "json-org");
}

#[test]
fn json_mode_emits_command_error_envelope_on_stdout() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.args(["ssh", "public-key", "--message-format=json"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");

    let result = cmd.assert().code(1);
    let stdout = result.get_output().stdout.clone();
    assert!(result.get_output().stderr.is_empty());
    let record: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "command_error");
    assert!(
        record["message"]
            .as_str()
            .unwrap()
            .contains("turnkey.organizationId")
    );
}

#[test]
fn usage_errors_follow_the_json_protocol_when_requested() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let result = cmd
        .args(["--message-format=json", "unknown-command"])
        .assert()
        .code(2);
    let record: serde_json::Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "usage_error");
    assert!(record["message"].as_str().unwrap().contains("Usage:"));
    assert!(result.get_output().stderr.is_empty());

    let mut human = Command::new(env!("CARGO_BIN_EXE_tk"));
    human
        .arg("unknown-command")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn missing_nested_subcommand_is_a_json_usage_error_when_requested() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let result = cmd
        .args(["--message-format=json", "ssh", "agent"])
        .assert()
        .code(2);
    let record: serde_json::Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "usage_error");
    assert!(record["message"].as_str().unwrap().contains("Usage:"));
    assert!(result.get_output().stderr.is_empty());
}

#[test]
fn non_interactive_env_accepts_boolean_spellings() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    for value in ["", "false", "0", "no", "true", "1", "yes"] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
        cmd.args(["config", "list"])
            .env("TURNKEY_TK_CONFIG_PATH", &config_path)
            .env("TK_NON_INTERACTIVE", value)
            .assert()
            .success();
    }
}

#[test]
fn config_list_json_reports_the_redacted_config() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = cmd
        .args(["config", "list", "--message-format=json"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env("TURNKEY_ORGANIZATION_ID", "org-id")
        .env("TURNKEY_API_PUBLIC_KEY", "02ab")
        .env("TURNKEY_API_PRIVATE_KEY", "secret-private-key")
        .env("TURNKEY_PRIVATE_KEY_ID", "pk-id")
        .env("TURNKEY_API_BASE_URL", "https://api.example.test")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let record: serde_json::Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(
        record,
        serde_json::json!({
            "reason": "config_listed",
            "config": {
                "turnkey": {
                    "organizationId": "org-id",
                    "apiPublicKey": "02ab",
                    "apiPrivateKey": "<redacted>",
                    "privateKeyId": "pk-id",
                    "apiBaseUrl": "https://api.example.test"
                }
            }
        })
    );
}

#[test]
fn human_errors_render_the_full_chain_on_stderr() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.args(["ssh", "public-key"])
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");

    cmd.assert()
        .code(1)
        .stderr(predicate::str::contains("error: "))
        .stderr(predicate::str::contains("turnkey.organizationId"));
}
