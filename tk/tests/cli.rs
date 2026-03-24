use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cli_help_lists_commands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("TURNKEY_ORGANIZATION_ID"))
        .stdout(predicate::str::contains("TURNKEY_API_PUBLIC_KEY"))
        .stdout(predicate::str::contains("TURNKEY_API_PRIVATE_KEY"))
        .stdout(predicate::str::contains("TURNKEY_PRIVATE_KEY_ID"))
        .stdout(predicate::str::contains("TURNKEY_API_BASE_URL"))
        .stdout(predicate::str::contains("TURNKEY_AUTH_CONFIG_PATH"))
        .stdout(predicate::str::contains("~/.config/turnkey/auth.toml"));

    let mut config_cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    config_cmd.arg("config").arg("--help");
    config_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("list"));
}
