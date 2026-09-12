//! The git shim's local paths: the passthrough that becomes the real gpg,
//! and the environment failure a signing call reports before it reaches the
//! network. No server and no credential are involved in either.

use std::fs;
use std::io::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use tempfile::{TempDir, tempdir};

/// Belt and braces. The passthrough path reads none of these, and the
/// signing path here fails before it reads any of them, so this list does
/// not have to track the e2e runner's longer one.
const SCRUBBED: [&str; 10] = [
    "TK_CONFIG",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TK_GPG_WALLET_ID",
    "TK_GPG_KEY_INDEX",
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
    "TURNKEY_API_BASE_URL",
    "RUST_LOG",
];

/// A gpg stand in that reports its own arguments and a distinctive status.
const STAND_IN: &str = r#"#!/bin/sh
printf '%s\n' "$@"
exit 3
"#;

const VERIFY_ARGS: [&str; 5] = [
    "--keyid-format=long",
    "--status-fd=1",
    "--verify",
    "sig",
    "-",
];

/// The argv git sends to sign, with no key named.
const SIGN_ARGS: [&str; 2] = ["--status-fd=2", "-bsa"];

/// One line, no usage footer, and the environment the user can act on.
const BAD_WALLET: &str = r"error: invalid value 'not-a-uuid' for '--wallet-id <WALLET_ID>': invalid character: found `n` at 0 (set by TK_GPG_WALLET_ID or TK_GPG_KEY_INDEX)";

/// The errno `exec` reports for a program that is not there.
const NOT_FOUND: i32 = 2;

/// The exit code the stand in reports, which no tk command path returns.
const STAND_IN_CODE: i32 = 3;

fn stand_in(home: &TempDir) -> PathBuf {
    let path = home.path().join("fake-gpg");
    fs::write(&path, STAND_IN).expect("the stand in should be writable");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("the stand in should be executable");
    path
}

fn tk(home: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in SCRUBBED {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home.path());
    cmd
}

#[test]
fn a_verify_call_becomes_the_configured_program() {
    let home = tempdir().expect("temp home should be creatable");
    let output = tk(&home)
        .env("TK_GPG_PROGRAM", stand_in(&home))
        .args(VERIFY_ARGS)
        .output()
        .expect("tk should run");

    assert_eq!(output.status.code(), Some(STAND_IN_CODE), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).expect("the stand in prints its arguments"),
        VERIFY_ARGS
            .iter()
            .map(|arg| format!("{arg}\n"))
            .collect::<String>()
    );
}

#[test]
fn a_missing_program_names_the_environment_variable() {
    let home = tempdir().expect("temp home should be creatable");
    let program = home.path().join("no-such-gpg");
    let output = tk(&home)
        .env("TK_GPG_PROGRAM", &program)
        .args(VERIFY_ARGS)
        .output()
        .expect("tk should run");

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stderr).expect("the shim reports the failure"),
        format!(
            "error: cannot run {}: {}; install GnuPG or set TK_GPG_PROGRAM\n",
            program.display(),
            Error::from_raw_os_error(NOT_FOUND)
        )
    );
}

/// Git reads the status descriptor, so a bad environment value must arrive
/// as one line that names the variable, not as clap's usage block.
#[test]
fn a_malformed_wallet_environment_value_is_one_line() {
    let home = tempdir().expect("temp home should be creatable");
    let output = tk(&home)
        .env("TK_GPG_WALLET_ID", "not-a-uuid")
        .args(SIGN_ARGS)
        .output()
        .expect("tk should run");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stderr).expect("the shim reports the failure"),
        format!("{BAD_WALLET}\n")
    );
    assert_eq!(output.stdout, b"", "the signature stream must stay clean");
}

/// A gpg marker that arrives as a tk option value must not reach the shim.
/// The command line below is a tk command line, so tk must parse it itself
/// rather than hand it to the program named by `TK_GPG_PROGRAM`.
#[test]
fn a_tk_command_line_carrying_a_gpg_marker_never_runs_the_configured_program() {
    let home = tempdir().expect("temp home should be creatable");
    let output = tk(&home)
        .env("TK_GPG_PROGRAM", stand_in(&home))
        .args(["wallet", "list", "--organization-id", "--verify"])
        .output()
        .expect("tk should run");

    assert_ne!(
        output.status.code(),
        Some(STAND_IN_CODE),
        "the configured program ran: {output:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("tk writes UTF-8");
    assert!(
        !stdout.contains("--verify"),
        "the configured program echoed the argv: {stdout}"
    );
}
