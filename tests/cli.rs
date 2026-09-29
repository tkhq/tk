//! Tests for top-level CLI parsing.

use std::error::Error;
use std::fs;
use std::iter::successors;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use ssh_key::public::{KeyData, RsaPublicKey};
use ssh_key::{Mpint, PublicKey};

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
    fs::write(&alternate, "malformed alternate registry").expect("write alternate registry");

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
        .args(["profile", "set", "--profile-name", "work"])
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
        .stderr(predicate::str::contains("--key <KEY>"));

    let directory = tempfile::tempdir().expect("temporary directory");
    let mut agent = Command::new(env!("CARGO_BIN_EXE_tk"));
    agent
        .args(["ssh", "agent", "start", "--key", "first", "--key", "second"])
        .env("HOME", directory.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("registry holds no SSH keys"));
}

#[test]
fn agent_start_rejects_bad_destination_constraint_inputs() {
    let home = tempfile::tempdir().expect("temporary home");
    let start = |arguments: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
        command
            .env("HOME", home.path())
            .args(["--message-format=json", "ssh", "agent", "start"])
            .args(arguments);
        command
    };

    let record = |command: &mut Command, code: i32| -> Value {
        serde_json::from_slice(&command.assert().code(code).get_output().stdout)
            .expect("the failure is JSON")
    };

    assert_eq!(
        record(&mut start(&["--allow-namespace", "git"]), 2),
        json!({
            "reason": "command_error",
            "code": "usage_error",
            "message": r#"error: the following required arguments were not provided:
  --allowed-hosts-file <PATH>

Usage: tk ssh agent start --allowed-hosts-file <PATH> --allow-namespace <NAMESPACE>

For more information, try '--help'."#,
        })
    );

    let hosts = home.path().join("allowed-hosts");
    let hosts_flag = hosts.display().to_string();
    assert_eq!(
        record(&mut start(&["--allowed-hosts-file", &hosts_flag]), 1),
        json!({
            "reason": "command_error",
            "code": "command_error",
            "message": format!(
                "failed to read {hosts_flag}: No such file or directory (os error 2)"
            ),
        })
    );

    let reject = |contents: &str| -> Value {
        fs::write(&hosts, contents).expect("write allowed hosts");
        record(&mut start(&["--allowed-hosts-file", &hosts_flag]), 1)
    };
    let exact = |contents: &str, message: String| {
        assert_eq!(
            reject(contents),
            json!({
                "reason": "command_error",
                "code": "invalid_input",
                "message": format!(
                    "the allowed-hosts file must hold ssh-keyscan HOST output: {message}"
                ),
            })
        );
    };

    exact(
        "|1|salt|hash ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPZL8okQwaCTLTWjnEyGGCF3HFTXJa2KRQPGoWvDKdF7\n",
        format!("{hosts_flag}:1: hashed hostnames are not supported"),
    );
    exact(
        "@revoked github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPZL8okQwaCTLTWjnEyGGCF3HFTXJa2KRQPGoWvDKdF7\n",
        format!(
            "{hosts_flag}:1: marker entries such as @revoked and @cert-authority are not supported; list plain host keys"
        ),
    );
    exact(
        "github.com ssh-ed25519\n",
        format!("{hosts_flag}:1: expected known_hosts fields: hostnames, key type, base64 key"),
    );
    exact(
        "# comments only\n\n",
        format!("{hosts_flag} names no host keys"),
    );

    let rsa_host = |n: Mpint| {
        let key = RsaPublicKey {
            e: Mpint::from_positive_bytes(&[1, 0, 1]).expect("RSA exponent"),
            n,
        };
        let line = PublicKey::new(KeyData::Rsa(key), "")
            .to_openssh()
            .expect("encode RSA host key");
        format!("github.com {line}\n")
    };
    let positive = |modulus: &[u8]| Mpint::from_positive_bytes(modulus).expect("RSA modulus");
    exact(
        &rsa_host(Mpint::from_bytes(&[0xff; 256]).expect("negative RSA modulus")),
        format!("{hosts_flag}:1: RSA host key modulus is not positive"),
    );
    exact(
        &rsa_host(positive(&[[1].as_slice(), &[0; 512]].concat())),
        format!("{hosts_flag}:1: RSA host keys over 4096 bits are not supported"),
    );
    exact(
        &rsa_host(positive(&[0xff; 255])),
        format!("{hosts_flag}:1: RSA host keys under 2048 bits are not supported"),
    );

    let invalid_key = PublicKey::from_openssh("ssh-ed25519 not-base64!")
        .expect_err("not-base64! is not a valid key body");
    let invalid_chain = successors(Some(&invalid_key as &dyn Error), |error| (*error).source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    exact(
        "github.com ssh-ed25519 not-base64!\n",
        format!("{hosts_flag}:1: invalid host key: {invalid_chain}"),
    );
}
