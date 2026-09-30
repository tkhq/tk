//! `tk gpg` paths that need no live API: the git shim's passthrough and the
//! failures the registered key table produces before any request, plus one
//! malformed account listing the live API cannot produce on demand.
// Test helpers may panic.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    io::{Error, Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    process::Output,
    thread,
};

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const SCRUBBED: [&str; 10] = [
    "HOME",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TK_GPG_PROGRAM",
    "TK_GPG_AGENT_SOCK",
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

/// The P-256 generator at `1_700_000_000`, whose fingerprint the auth crate
/// verifies against an independent computation.
const POINT: &str = concat!(
    "04",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
);
const FINGERPRINT: &str = "13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6";
const OTHER_FINGERPRINT: &str = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
const BROKER_SIGNATURE: &str = r#"-----BEGIN PGP SIGNATURE-----

wjcEABMIAB0FgmVT8QEWIQQT/8ffIM1qv8rtWJktAHrNzTDMpgAKCRAtAHrNzTDMphISAAEBAAIC
=0Ren
-----END PGP SIGNATURE-----
"#;

const REQUEST_HEADER_LEN: usize = 12;

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

fn tk_with_agent(home: &TempDir, socket: &Path) -> Command {
    let mut cmd = tk(home);
    cmd.env("TK_GPG_AGENT_SOCK", socket);
    cmd
}

fn registry_with_keys(home: &TempDir, fingerprints: &[&str]) -> PathBuf {
    let dir = home.path().join(".config/turnkey");
    fs::create_dir_all(&dir).expect("the config dir should be creatable");
    let path = dir.join("tk.config.toml");
    let entries = fingerprints
        .iter()
        .enumerate()
        .map(|(index, fingerprint)| {
            let account = index + 1;
            format!(
                r#"
[gpg_keys."{fingerprint}"]
organization_id = "{KEY_ORG}"
wallet_id = "{WALLET}"
wallet_account_id = "account-{account}"
user_id = "Ada <ada@example.com>"
public_key = "{POINT}"
created = 1700000000
"#
            )
        })
        .collect::<String>();
    fs::write(&path, format!("version = 1\n{entries}")).expect("the registry should be writable");
    path
}

fn assert_shim_failure(build: impl FnOnce(&TempDir) -> (Command, String)) {
    let home = tempdir().expect("temp home should be creatable");
    let (mut cmd, expected) = build(&home);
    let output = cmd.output().expect("tk should run");
    assert_shim_failed(output, &expected);
}

fn assert_shim_failed(output: Output, expected: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(output.stdout, b"", "the signature stream must stay clean");
    assert_eq!(
        String::from_utf8(output.stderr).expect("the shim reports the failure"),
        expected
    );
}

fn sign_request(key: &str, payload: &[u8]) -> Vec<u8> {
    let mut request = b"TKGP\x01\x01".to_vec();
    request.extend_from_slice(&(key.len() as u16).to_be_bytes());
    request.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    request.extend_from_slice(key.as_bytes());
    request.extend_from_slice(payload);
    request
}

fn broker_response(fingerprint: &str, created: u32, signature: &str) -> Vec<u8> {
    let mut response = b"TKGP\x01\x00".to_vec();
    response.extend_from_slice(&created.to_be_bytes());
    response.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    response.extend_from_slice(fingerprint.as_bytes());
    response.extend_from_slice(signature.as_bytes());
    response
}

fn fake_agent() -> (TempDir, PathBuf, UnixListener) {
    let home = tempdir().expect("temp home should be creatable");
    let socket = home.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).expect("the fake agent should bind");
    (home, socket, listener)
}

fn fake_agent_server(listener: UnixListener, response: Vec<u8>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the shim should connect");
        let mut request = vec![0; REQUEST_HEADER_LEN];
        stream
            .read_exact(&mut request)
            .expect("the request header should be readable");
        let key_len = u16::from_be_bytes([request[6], request[7]]);
        let payload_len = u32::from_be_bytes([request[8], request[9], request[10], request[11]]);
        let mut body = vec![0; usize::from(key_len) + payload_len as usize];
        stream
            .read_exact(&mut body)
            .expect("the request body should be readable");
        request.extend(body);
        stream
            .write_all(&response)
            .expect("the response should be writable");
        request
    })
}

#[test]
fn the_git_shim_signs_through_the_agent_without_local_credentials() {
    let (home, socket, listener) = fake_agent();
    let payload = br#"tree 0123456789abcdef
"#;
    let response = broker_response(FINGERPRINT, 1_700_000_001, BROKER_SIGNATURE);
    let server = fake_agent_server(listener, response);

    let output = tk_with_agent(&home, &socket)
        .args(["--status-fd=2", "-bsau", FINGERPRINT])
        .write_stdin(payload)
        .output()
        .expect("tk should run");

    let request = server.join().expect("the fake agent should finish");
    assert_eq!(request, sign_request(FINGERPRINT, payload));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, BROKER_SIGNATURE.as_bytes());
    assert_eq!(
        String::from_utf8(output.stderr).expect("status output should be UTF-8"),
        format!(
            r#"[GNUPG:] BEGIN_SIGNING
[GNUPG:] SIG_CREATED D 19 8 00 1700000001 {FINGERPRINT}
"#
        )
    );
    assert!(!home.path().join(".config/turnkey/tk.config.toml").exists());
}

#[test]
fn an_agent_signature_for_a_different_key_never_reaches_git_output() {
    let (home, socket, listener) = fake_agent();
    let response = broker_response(OTHER_FINGERPRINT, 1_700_000_001, BROKER_SIGNATURE);
    let server = fake_agent_server(listener, response);

    let output = tk_with_agent(&home, &socket)
        .args(["--status-fd=2", "-bsau", FINGERPRINT])
        .output()
        .expect("tk should run");

    let request = server.join().expect("the fake agent should finish");
    assert_eq!(request, sign_request(FINGERPRINT, b""));
    assert_shim_failed(
        output,
        r#"error: read the OpenPGP agent response: OpenPGP agent signature metadata does not match its response frame
"#,
    );
}

#[test]
fn an_unavailable_agent_never_falls_back_to_local_credentials() {
    let home = tempdir().expect("temp home should be creatable");
    let socket = home.path().join("missing-agent.sock");
    let output = tk_with_agent(&home, &socket)
        .args(SIGN_ARGS)
        .write_stdin("payload")
        .output()
        .expect("tk should run");

    assert_shim_failed(
        output,
        &format!(
            r#"error: connect to OpenPGP agent socket {}: No such file or directory (os error 2)
"#,
            socket.display()
        ),
    );
}

#[test]
fn oversized_agent_input_is_rejected_without_signature_output() {
    let (home, socket, _listener) = fake_agent();
    let output = tk_with_agent(&home, &socket)
        .args(SIGN_ARGS)
        .write_stdin(vec![b'x'; 1024 * 1024 + 1])
        .output()
        .expect("tk should run");

    assert_shim_failed(
        output,
        r#"error: write the OpenPGP agent request: payload is too large
"#,
    );
}

#[test]
fn a_truncated_agent_response_never_reaches_git_output() {
    let (home, socket, listener) = fake_agent();
    let truncated_response = b"TKGP\x01\x00".to_vec();
    let server = fake_agent_server(listener, truncated_response);

    let output = tk_with_agent(&home, &socket)
        .args(SIGN_ARGS)
        .write_stdin("payload")
        .output()
        .expect("tk should run");

    let request = server.join().expect("the fake agent should finish");
    assert_eq!(request, sign_request("", b"payload"));
    assert_shim_failed(
        output,
        r#"error: read the OpenPGP agent response: early eof
"#,
    );
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
            r#"error: cannot run {}: {}; install GnuPG or set TK_GPG_PROGRAM
"#,
            program.display(),
            Error::from_raw_os_error(NOT_FOUND)
        )
    );
}

#[test]
fn an_empty_key_table_is_one_line_naming_the_registering_commands() {
    assert_shim_failure(|home| {
        let mut cmd = tk(home);
        cmd.args(SIGN_ARGS);
        (
            cmd,
            r#"error: the registry holds no OpenPGP keys; create one with tk gpg keys create or register one with tk gpg keys add
"#
            .to_string(),
        )
    });
}

#[test]
fn a_key_entry_whose_fingerprint_does_not_match_its_fields_is_rejected() {
    assert_shim_failure(|home| {
        let wrong = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
        let path = registry_with_keys(home, &[wrong]);
        let mut cmd = tk(home);
        cmd.args(SIGN_ARGS);
        (
            cmd,
            format!(
                r#"error: invalid gpg_keys entry {wrong} in {}: public_key and created do not produce this fingerprint
"#,
                path.display()
            ),
        )
    });
}

#[test]
fn two_entries_spelling_one_fingerprint_are_rejected() {
    assert_shim_failure(|home| {
        let lowercase = FINGERPRINT.to_ascii_lowercase();
        let path = registry_with_keys(home, &[FINGERPRINT, &lowercase]);
        let mut cmd = tk(home);
        cmd.args(SIGN_ARGS);
        (
            cmd,
            format!(
                r#"error: invalid gpg_keys entry {lowercase} in {}: duplicates the fingerprint of another entry
"#,
                path.display()
            ),
        )
    });
}

#[test]
fn a_bundle_for_another_organization_is_rejected_before_any_request() {
    assert_shim_failure(|home| {
        registry_with_keys(home, &[FINGERPRINT]);
        let mut cmd = tk_with_bundle(home, OTHER_ORG);
        cmd.args(["--status-fd=2", "-bsau", FINGERPRINT]);
        (
            cmd,
            format!(
                r#"error: select a credential for OpenPGP key {FINGERPRINT}: the selected identity (environment) belongs to organization {OTHER_ORG}, not {KEY_ORG}
"#
            ),
        )
    });
}

#[test]
fn a_key_whose_organization_has_no_profile_names_the_missing_login() {
    assert_shim_failure(|home| {
        registry_with_keys(home, &[FINGERPRINT]);
        let mut cmd = tk(home);
        cmd.args(["--status-fd=2", "-bsau", FINGERPRINT]);
        (
            cmd,
            format!(
                r#"error: select a credential for OpenPGP key {FINGERPRINT}: no profile holds a credential for organization {KEY_ORG}; run tk profile create --profile-name <name> --organization-id {KEY_ORG}
"#
            ),
        )
    });
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
