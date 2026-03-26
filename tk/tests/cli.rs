use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn cli_help_lists_commands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("whoami"))
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("git-sign"))
        .stdout(predicate::str::contains("ssh-agent"))
        .stdout(predicate::str::contains("public-key"))
        .stdout(predicate::str::contains("TURNKEY_ORGANIZATION_ID"))
        .stdout(predicate::str::contains("TURNKEY_API_PUBLIC_KEY"))
        .stdout(predicate::str::contains("TURNKEY_API_PRIVATE_KEY"))
        .stdout(predicate::str::contains("TURNKEY_API_BASE_URL"))
        .stdout(predicate::str::contains("TURNKEY_TK_CONFIG_PATH"))
        .stdout(predicate::str::contains("~/.config/turnkey/tk.toml"))
        .stdout(predicate::str::contains(
            "ssh-agent   Manage the Turnkey SSH agent",
        ))
        .stdout(predicate::str::contains("tk ssh-agent start"));

    let mut agent_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    agent_cmd.arg("ssh-agent").arg("--help");

    agent_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("--socket"))
        .stdout(predicate::str::contains("start"))
        .stdout(predicate::str::contains("stop"))
        .stdout(predicate::str::contains("status"));
}

#[test]
fn public_key_requires_turnkey_org_id() {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("public-key")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_API_BASE_URL");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("turnkey.organizationId"));
}
