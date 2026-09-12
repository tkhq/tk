//! `tk gpg` behavior the e2e suite cannot reach: the profile write, which
//! needs a registry of its own, and one malformed account listing, which a
//! live API does not produce.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const WALLET: &str = "9a1e2c4b-1111-4000-8000-0123456789ab";
const ORGANIZATION: &str = "3c0f1d5a-2222-4000-8000-0123456789ab";

/// The page size `tk gpg` asks the account listing for. A page this long is
/// what makes the client ask for another one.
const PAGE_SIZE: usize = 100;

/// Belt and braces. These tests supply every value they need, so no host
/// variable may reach the binary.
const SCRUBBED: [&str; 12] = [
    "HOME",
    "TK_CONFIG",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TK_GPG_WALLET_ID",
    "TK_GPG_KEY_INDEX",
    "TURNKEY_TK_CONFIG_PATH",
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
    "TURNKEY_API_BASE_URL",
    "RUST_LOG",
];

/// The whole registry, mirrored so the test can compare one complete value.
/// `deny_unknown_fields` everywhere makes a field the writer added, renamed,
/// or dropped fail the test rather than pass unseen.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    active_profile: String,
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Profile {
    organization_id: String,
    api_base_url: String,
    api_key_file: PathBuf,
    ssh_signing_key_id: Option<String>,
    gpg: Option<Gpg>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Gpg {
    wallet_id: String,
    key_index: u32,
}

fn tk(home: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in SCRUBBED {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home.path()).arg("--message-format=json");
    cmd
}

/// The credential file path the test registry points at.
fn key_file_of(home: &TempDir) -> PathBuf {
    home.path().join("dev-key.json")
}

/// A home directory holding one active profile named `dev`.
fn home_with_profile() -> TempDir {
    let home = tempdir().expect("temp home should be creatable");
    let config = home.path().join(".config/turnkey");
    fs::create_dir_all(&config).expect("config directory should be creatable");
    let key_file = key_file_of(&home);
    fs::write(
        &key_file,
        r#"{"public_key":"02","private_key":"00","curve":"p256"}"#,
    )
    .expect("credential file should be writable");
    fs::write(
        config.join("tk.config.toml"),
        format!(
            r#"version = 1
active_profile = "dev"

[profiles.dev]
organization_id = "{ORGANIZATION}"
api_base_url = "https://api.turnkey.com"
api_key_file = "{}"
"#,
            key_file.display()
        ),
    )
    .expect("registry should be writable");
    home
}

fn registry_of(home: &TempDir) -> Registry {
    let text = fs::read_to_string(home.path().join(".config/turnkey/tk.config.toml"))
        .expect("registry should be readable");
    toml::from_str(&text).expect("registry should parse as TOML")
}

#[test]
fn gpg_use_writes_the_target_into_the_active_profile() {
    let home = home_with_profile();
    let output = tk(&home)
        .args(["gpg", "use", "--wallet-id", WALLET, "--key-index", "3"])
        .output()
        .expect("tk should run");
    assert!(output.status.success(), "{output:?}");

    let record: Value = serde_json::from_slice(&output.stdout).expect("one JSON record on stdout");
    assert_eq!(
        record,
        json!({
            "reason": "gpg_profile_updated",
            "profile": "dev",
            "walletId": WALLET,
            "keyIndex": 3,
        })
    );

    // The write loads, mutates, and rewrites the whole registry, so the
    // fields it did not touch matter as much as the one it did.
    assert_eq!(
        registry_of(&home),
        Registry {
            version: 1,
            active_profile: "dev".to_string(),
            profiles: BTreeMap::from([(
                "dev".to_string(),
                Profile {
                    organization_id: ORGANIZATION.to_string(),
                    api_base_url: "https://api.turnkey.com".to_string(),
                    api_key_file: key_file_of(&home),
                    ssh_signing_key_id: None,
                    gpg: Some(Gpg {
                        wallet_id: WALLET.to_string(),
                        key_index: 3,
                    }),
                },
            )]),
        }
    );
}

#[test]
fn gpg_use_rejects_a_non_numeric_key_index_during_parsing() {
    let home = home_with_profile();
    let output = tk(&home)
        .args(["gpg", "use", "--wallet-id", WALLET, "--key-index", "x"])
        .output()
        .expect("tk should run");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn gpg_use_without_a_profile_is_invalid_input() {
    let home = tempdir().expect("temp home should be creatable");
    let output = tk(&home)
        .args(["gpg", "use", "--wallet-id", WALLET])
        .output()
        .expect("tk should run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");

    let record: Value = serde_json::from_slice(&output.stdout).expect("one JSON record on stdout");
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "invalid_input");
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
                "organizationId": ORGANIZATION,
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
    let key = TurnkeyP256ApiKey::generate();
    let output = tk(&home)
        .env("TURNKEY_ORGANIZATION_ID", ORGANIZATION)
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(key.compressed_public_key()),
        )
        .env("TURNKEY_API_PRIVATE_KEY", hex::encode(key.private_key()))
        .arg("--api-base-url")
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
