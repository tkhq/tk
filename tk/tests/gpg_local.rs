//! `tk gpg` paths that need no live API: the git shim's passthrough and the
//! failures the registered key table produces before any request, plus one
//! malformed account listing the live API cannot produce on demand.

use std::fs;
use std::io::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// The test supplies every value it needs, so no host variable may reach
/// the binary.
const SCRUBBED: [&str; 10] = [
    "TK_CONFIG",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TK_GPG_PROGRAM",
    "TURNKEY_TK_CONFIG_PATH",
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
    "TURNKEY_API_BASE_URL",
    "RUST_LOG",
];

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

const SIGN_ARGS: [&str; 2] = ["--status-fd=2", "-bsa"];

/// The errno `exec` reports for a program that is not there.
const NOT_FOUND: i32 = 2;

/// The exit code the stand in reports, which no tk command path returns.
const STAND_IN_CODE: i32 = 3;

const KEY_ORG: &str = "3c0f1d5a-2222-4000-8000-0123456789ab";
const OTHER_ORG: &str = "3c0f1d5a-3333-4000-8000-0123456789ab";
const WALLET: &str = "9a1e2c4b-1111-4000-8000-0123456789ab";

/// The P-256 generator at 1_700_000_000, whose fingerprint the auth crate
/// verifies against an independent computation.
const POINT: &str = concat!(
    "04",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
);
const FINGERPRINT: &str = "13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6";

/// The page size `tk gpg` asks the account listing for. A page this long is
/// what makes the client ask for another one.
const PAGE_SIZE: usize = 100;

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

fn tk_with_bundle(home: &TempDir, org: &str) -> Command {
    let key = TurnkeyP256ApiKey::generate();
    let mut cmd = tk(home);
    cmd.env("TURNKEY_ORGANIZATION_ID", org)
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(key.compressed_public_key()),
        )
        .env("TURNKEY_API_PRIVATE_KEY", hex::encode(key.private_key()));
    cmd
}

/// Writes a registry holding one key under `fingerprint`, owned by
/// [`KEY_ORG`], with no profiles.
fn registry_with_key(home: &TempDir, fingerprint: &str) -> PathBuf {
    let dir = home.path().join(".config/turnkey");
    fs::create_dir_all(&dir).expect("the config dir should be creatable");
    let path = dir.join("tk.config.toml");
    fs::write(
        &path,
        format!(
            r#"version = 1

[gpg_keys."{fingerprint}"]
organization_id = "{KEY_ORG}"
wallet_id = "{WALLET}"
wallet_account_id = "account-1"
user_id = "Ada <ada@example.com>"
public_key = "{POINT}"
created = 1700000000
"#
        ),
    )
    .expect("the registry should be writable");
    path
}

fn stderr_of(output: Output) -> String {
    assert_eq!(output.stdout, b"", "the signature stream must stay clean");
    String::from_utf8(output.stderr).expect("the shim reports the failure")
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

#[test]
fn an_empty_key_table_is_one_line_naming_the_registering_commands() {
    let home = tempdir().expect("temp home should be creatable");
    let output = tk(&home).args(SIGN_ARGS).output().expect("tk should run");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        stderr_of(output),
        "error: no OpenPGP keys are registered; create one with tk gpg keys create or register one with tk gpg keys add\n"
    );
}

#[test]
fn a_key_entry_whose_fingerprint_does_not_match_its_fields_is_rejected() {
    let home = tempdir().expect("temp home should be creatable");
    let wrong = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
    let path = registry_with_key(&home, wrong);
    let output = tk(&home).args(SIGN_ARGS).output().expect("tk should run");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        stderr_of(output),
        format!(
            "error: invalid gpg_keys entry {wrong} in {}: public_key and created do not produce this fingerprint\n",
            path.display()
        )
    );
}

/// The environment bundle is an explicit identity, so it must belong to the
/// key's organization. This fails before any request.
#[test]
fn a_bundle_for_another_organization_is_rejected_before_any_request() {
    let home = tempdir().expect("temp home should be creatable");
    registry_with_key(&home, FINGERPRINT);
    let output = tk_with_bundle(&home, OTHER_ORG)
        .args(["--status-fd=2", "-bsau", FINGERPRINT])
        .output()
        .expect("tk should run");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        stderr_of(output),
        format!(
            "error: select a credential for OpenPGP key {FINGERPRINT}: the selected identity (environment) belongs to organization {OTHER_ORG}, not {KEY_ORG}\n"
        )
    );
}

/// With no explicit identity, the key's organization selects the profile.
/// No profile holds one here, so the shim says which login is missing.
#[test]
fn a_key_whose_organization_has_no_profile_names_the_missing_login() {
    let home = tempdir().expect("temp home should be creatable");
    registry_with_key(&home, FINGERPRINT);
    let output = tk(&home)
        .args(["--status-fd=2", "-bsau", FINGERPRINT])
        .output()
        .expect("tk should run");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        stderr_of(output),
        format!(
            "error: select a credential for OpenPGP key {FINGERPRINT}: no profile holds a credential for organization {KEY_ORG}; run tk login <name> --organization-id {KEY_ORG} --api-key-file <path>\n"
        )
    );
}

/// A server that returns a full page and repeats the cursor would page for
/// ever. The live API cannot be made to do it, so this is a mock.
#[tokio::test]
async fn a_repeated_account_cursor_is_reported_as_an_api_error() {
    let server = MockServer::start().await;
    let accounts: Vec<Value> = (0..PAGE_SIZE)
        .map(|_| {
            json!({
                "walletAccountId": "00000000-0000-4000-8000-0000000000ff",
                "organizationId": KEY_ORG,
                "walletId": WALLET,
                "curve": "CURVE_P256",
                "pathFormat": "PATH_FORMAT_BIP32",
                "path": "m/44'/60'/0'/0/0",
                "addressFormat": "ADDRESS_FORMAT_UNCOMPRESSED",
                "address": "04",
                "createdAt": {"seconds": "1700000000", "nanos": "0"},
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallet_accounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accounts": accounts})))
        .mount(&server)
        .await;

    let home = tempdir().expect("temp home should be creatable");
    let output = tk_with_bundle(&home, KEY_ORG)
        .args(["--message-format=json", "--api-base-url"])
        .arg(server.uri())
        .args(["gpg", "keys", "list", "--wallet-id", WALLET])
        .output()
        .expect("tk should run");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let record: Value = serde_json::from_slice(&output.stdout).expect("one JSON record on stdout");
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "api_error");
    assert_eq!(
        record["message"],
        format!(
            "get_wallet_accounts returned a full page of wallet {WALLET} without advancing its cursor"
        )
    );
}
