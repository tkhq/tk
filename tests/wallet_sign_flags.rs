//! Flag-based input for `wallet` and `sign` builds the same intents as raw JSON.
// Test helpers may panic.
#![allow(clippy::unwrap_used)]

use std::fs;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
const WALLET: &str = "00000000-0000-4000-8000-0000000000aa";

fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in [
        "HOME",
        "TK_PROFILE",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_API_BASE_URL",
    ] {
        cmd.env_remove(name);
    }
    cmd.arg("--message-format=json");
    cmd
}

fn authed(base: &str) -> Command {
    let mut cmd = cli();
    let key = TurnkeyP256ApiKey::generate();
    cmd.env("TURNKEY_ORGANIZATION_ID", ORG)
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(key.compressed_public_key()),
        )
        .env("TURNKEY_API_PRIVATE_KEY", hex::encode(key.private_key()))
        .arg("--api-base-url")
        .arg(base);
    cmd
}

fn record(cmd: &mut Command, code: i32) -> Value {
    let result = cmd.assert().code(code);
    assert!(result.get_output().stderr.is_empty());
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}

async fn mount_activity(server: &MockServer, endpoint: &str, status: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/public/v1/submit/{endpoint}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"activity":{"id":"activity-id","status":status}})),
        )
        .mount(server)
        .await;
}

async fn mount_accounts(server: &MockServer, pages: Vec<Value>) {
    for (index, accounts) in pages.into_iter().enumerate() {
        let mock = Mock::given(method("POST"))
            .and(path("/public/v1/query/get_wallet_accounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accounts": accounts})));
        if index == 0 {
            mock.up_to_n_times(1).mount(server).await;
        } else {
            mock.mount(server).await;
        }
    }
}

fn account(id: usize, format: &str, account_path: &str) -> Value {
    json!({
        "walletAccountId": format!("account-{id}"),
        "organizationId": ORG,
        "walletId": WALLET,
        "curve": "CURVE_SECP256K1",
        "pathFormat": "PATH_FORMAT_BIP32",
        "path": account_path,
        "addressFormat": format,
        "address": format!("0x{id}"),
    })
}

async fn submitted(server: &MockServer, endpoint: &str) -> Value {
    let requests = server.received_requests().await.unwrap();
    let submit_path = format!("/public/v1/submit/{endpoint}");
    let mut bodies = requests
        .iter()
        .filter(|request| request.url.path() == submit_path)
        .map(|request| request.body_json::<Value>().unwrap());
    let body = bodies.next().unwrap();
    assert!(bodies.next().is_none(), "submitted more than once");
    assert_eq!(body["organizationId"], ORG);
    body
}

async fn run_flags(endpoint: &str, kind: &str, args: &[&str]) -> Value {
    let server = MockServer::start().await;
    mount_activity(&server, endpoint, "ACTIVITY_STATUS_COMPLETED").await;
    record(authed(&server.uri()).args(args), 0);
    let body = submitted(&server, endpoint).await;
    assert_eq!(body["type"], kind);
    body["parameters"].clone()
}

fn eth_account(account_path: &str) -> Value {
    json!({
        "curve": "CURVE_SECP256K1",
        "pathFormat": "PATH_FORMAT_BIP32",
        "path": account_path,
        "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
        "name": null,
    })
}

#[tokio::test]
async fn wallet_create_name_only_creates_no_accounts() {
    let parameters = run_flags(
        "create_wallet",
        "ACTIVITY_TYPE_CREATE_WALLET",
        &["wallet", "create", "--name", "main"],
    )
    .await;
    assert_eq!(
        parameters,
        json!({"walletName": "main", "accounts": [], "mnemonicLength": null})
    );
}

#[tokio::test]
async fn wallet_create_accounts_infer_curve_and_number_repeated_formats() {
    let parameters = run_flags(
        "create_wallet",
        "ACTIVITY_TYPE_CREATE_WALLET",
        &[
            "wallet",
            "create",
            "--name",
            "main",
            "--account",
            "ethereum",
            "--account",
            "ADDRESS_FORMAT_ETHEREUM",
            "--account",
            "solana",
            "--account",
            "cosmos:m/44'/118'/7'/0/0",
            "--mnemonic-length",
            "24",
        ],
    )
    .await;
    assert_eq!(
        parameters,
        json!({
            "walletName": "main",
            "accounts": [
                eth_account("m/44'/60'/0'/0/0"),
                eth_account("m/44'/60'/1'/0/0"),
                {
                    "curve": "CURVE_ED25519",
                    "pathFormat": "PATH_FORMAT_BIP32",
                    "path": "m/44'/501'/0'/0'",
                    "addressFormat": "ADDRESS_FORMAT_SOLANA",
                    "name": null,
                },
                {
                    "curve": "CURVE_SECP256K1",
                    "pathFormat": "PATH_FORMAT_BIP32",
                    "path": "m/44'/118'/7'/0/0",
                    "addressFormat": "ADDRESS_FORMAT_COSMOS",
                    "name": null,
                },
            ],
            "mnemonicLength": 24,
        })
    );
}

#[tokio::test]
async fn raw_json_and_flags_build_the_same_wallet_intent() {
    let from_flags = run_flags(
        "create_wallet",
        "ACTIVITY_TYPE_CREATE_WALLET",
        &[
            "wallet",
            "create",
            "--name",
            "main",
            "--account",
            "ethereum",
        ],
    )
    .await;
    let from_json = run_flags(
        "create_wallet",
        "ACTIVITY_TYPE_CREATE_WALLET",
        &[
            "wallet",
            "create",
            "--input-json",
            &json!({"walletName": "main", "accounts": [eth_account("m/44'/60'/0'/0/0")]})
                .to_string(),
        ],
    )
    .await;
    assert_eq!(from_flags, from_json);
}

#[tokio::test]
async fn account_create_predicts_the_lowest_unused_path_of_the_same_format() {
    let server = MockServer::start().await;
    mount_accounts(
        &server,
        vec![json!([
            account(1, "ADDRESS_FORMAT_ETHEREUM", "m/44'/60'/0'/0/0"),
            account(2, "ADDRESS_FORMAT_ETHEREUM", "m/44'/60'/2'/0/0"),
            account(3, "ADDRESS_FORMAT_SOLANA", "m/44'/501'/1'/0'"),
        ])],
    )
    .await;
    mount_activity(
        &server,
        "create_wallet_accounts",
        "ACTIVITY_STATUS_COMPLETED",
    )
    .await;
    let result = record(
        authed(&server.uri()).args([
            "wallet",
            "account",
            "create",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ethereum",
        ]),
        0,
    );
    assert_eq!(result["command"], "wallet.account.create");
    let body = submitted(&server, "create_wallet_accounts").await;
    assert_eq!(body["type"], "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS");
    assert_eq!(
        body["parameters"],
        json!({
            "walletId": WALLET,
            "accounts": [eth_account("m/44'/60'/1'/0/0")],
            "persist": null,
        })
    );
}

#[tokio::test]
async fn account_create_prediction_reads_every_page() {
    let server = MockServer::start().await;
    let first_page: Vec<Value> = (0..100)
        .map(|index| {
            account(
                index,
                "ADDRESS_FORMAT_ETHEREUM",
                &format!("m/44'/60'/{index}'/0/0"),
            )
        })
        .collect();
    mount_accounts(
        &server,
        vec![
            Value::Array(first_page),
            json!([account(
                100,
                "ADDRESS_FORMAT_ETHEREUM",
                "m/44'/60'/100'/0/0"
            )]),
        ],
    )
    .await;
    mount_activity(
        &server,
        "create_wallet_accounts",
        "ACTIVITY_STATUS_COMPLETED",
    )
    .await;
    record(
        authed(&server.uri()).args([
            "wallet",
            "account",
            "create",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ethereum",
        ]),
        0,
    );
    let body = submitted(&server, "create_wallet_accounts").await;
    assert_eq!(
        body["parameters"]["accounts"],
        json!([eth_account("m/44'/60'/101'/0/0")])
    );
    let queries = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path().ends_with("get_wallet_accounts"))
        .map(|request| request.body_json::<Value>().unwrap()["paginationOptions"]["after"].clone())
        .collect::<Vec<_>>();
    assert_eq!(queries, [json!(""), json!("account-99")]);
}

#[tokio::test]
async fn account_create_with_explicit_path_and_curve_skips_the_lookup() {
    let server = MockServer::start().await;
    mount_activity(
        &server,
        "create_wallet_accounts",
        "ACTIVITY_STATUS_COMPLETED",
    )
    .await;
    record(
        authed(&server.uri()).args([
            "wallet",
            "account",
            "create",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ADDRESS_FORMAT_TRON",
            "--curve",
            "curve_secp256k1",
            "--path",
            "m/44'/195'/0'/0/0",
        ]),
        0,
    );
    let queried = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|request| request.url.path().starts_with("/public/v1/query"));
    assert!(!queried);
    let body = submitted(&server, "create_wallet_accounts").await;
    assert_eq!(
        body["parameters"]["accounts"],
        json!([{
            "curve": "CURVE_SECP256K1",
            "pathFormat": "PATH_FORMAT_BIP32",
            "path": "m/44'/195'/0'/0/0",
            "addressFormat": "ADDRESS_FORMAT_TRON",
            "name": null,
        }])
    );
}

#[tokio::test]
async fn account_create_curve_inference_covers_each_known_format() {
    for (format, curve) in [
        ("ethereum", "CURVE_SECP256K1"),
        ("cosmos", "CURVE_SECP256K1"),
        ("uncompressed", "CURVE_SECP256K1"),
        ("solana", "CURVE_ED25519"),
    ] {
        let parameters = run_flags(
            "create_wallet_accounts",
            "ACTIVITY_TYPE_CREATE_WALLET_ACCOUNTS",
            &[
                "wallet",
                "account",
                "create",
                "--wallet-id",
                WALLET,
                "--address-format",
                format,
                "--path",
                "m/0'",
            ],
        )
        .await;
        assert_eq!(parameters["accounts"][0]["curve"], curve, "{format}");
    }
}

#[test]
fn account_create_without_inferable_curve_or_path_is_invalid_input_before_credentials() {
    for (args, message) in [
        (
            ["--address-format", "tron", "--path", "m/0'"],
            "cannot infer the curve for ADDRESS_FORMAT_TRON; pass --curve",
        ),
        (
            ["--address-format", "tron", "--curve", "p256"],
            "no conventional derivation path for ADDRESS_FORMAT_TRON; pass --path",
        ),
    ] {
        let result = record(
            cli()
                .args(["wallet", "account", "create", "--wallet-id", WALLET])
                .args(args),
            1,
        );
        assert_eq!(result["code"], "invalid_input");
        assert_eq!(result["message"], message);
    }
}

#[tokio::test]
async fn sign_payload_flags_build_the_intent() {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("payload.txt");
    fs::write(&file, "hello\n").unwrap();
    let inline = run_flags(
        "sign_raw_payload",
        "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
        &[
            "sign",
            "payload",
            "--sign-with",
            "0xabc",
            "--payload",
            "hello",
            "--encoding",
            "text_utf8",
            "--hash-function",
            "HASH_FUNCTION_SHA256",
        ],
    )
    .await;
    assert_eq!(
        inline,
        json!({
            "signWith": "0xabc",
            "payload": "hello",
            "encoding": "PAYLOAD_ENCODING_TEXT_UTF8",
            "hashFunction": "HASH_FUNCTION_SHA256",
        })
    );
    let from_file = run_flags(
        "sign_raw_payload",
        "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
        &[
            "sign",
            "payload",
            "--sign-with",
            "0xabc",
            "--payload-file",
            file.to_str().unwrap(),
            "--encoding",
            "PAYLOAD_ENCODING_HEXADECIMAL",
            "--hash-function",
            "no_op",
        ],
    )
    .await;
    assert_eq!(
        from_file,
        json!({
            "signWith": "0xabc",
            "payload": "hello\n",
            "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
            "hashFunction": "HASH_FUNCTION_NO_OP",
        })
    );
}

#[tokio::test]
async fn sign_transaction_flags_build_the_intent() {
    let temp = TempDir::new().unwrap();
    let file = temp.path().join("tx.hex");
    fs::write(&file, "02ab\n").unwrap();
    let expected = json!({
        "signWith": "0xabc",
        "unsignedTransaction": "02ab",
        "type": "TRANSACTION_TYPE_ETHEREUM",
    });
    let inline = run_flags(
        "sign_transaction",
        "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
        &[
            "sign",
            "transaction",
            "--sign-with",
            "0xabc",
            "--unsigned-transaction",
            "02ab",
            "--type",
            "transaction_type_ethereum",
        ],
    )
    .await;
    assert_eq!(inline, expected);
    let from_file = run_flags(
        "sign_transaction",
        "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
        &[
            "sign",
            "transaction",
            "--sign-with",
            "0xabc",
            "--unsigned-transaction-file",
            file.to_str().unwrap(),
            "--type",
            "ethereum",
        ],
    )
    .await;
    assert_eq!(from_file, expected);
}

#[tokio::test]
async fn flag_forms_keep_the_pending_exit_contract() {
    let server = MockServer::start().await;
    mount_activity(
        &server,
        "sign_transaction",
        "ACTIVITY_STATUS_CONSENSUS_NEEDED",
    )
    .await;
    let pending = record(
        authed(&server.uri()).args([
            "sign",
            "transaction",
            "--sign-with",
            "0xabc",
            "--unsigned-transaction",
            "02ab",
            "--type",
            "ethereum",
        ]),
        0,
    );
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["activity"]["id"], "activity-id");
}

#[test]
fn raw_json_and_flags_are_mutually_exclusive_and_exit_two() {
    for args in [
        vec!["wallet", "create", "--input-json", "{}", "--name", "x"],
        vec![
            "wallet",
            "create",
            "--input-json",
            "{}",
            "--account",
            "ethereum",
        ],
        vec![
            "wallet",
            "account",
            "create",
            "--input-json",
            "{}",
            "--curve",
            "p256",
        ],
        vec![
            "wallet",
            "account",
            "create",
            "--input-file",
            "x",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ethereum",
        ],
        vec!["sign", "payload", "--input-json", "{}", "--sign-with", "a"],
        vec![
            "sign",
            "payload",
            "--input-json",
            "{}",
            "--encoding",
            "text_utf8",
        ],
        vec![
            "sign",
            "transaction",
            "--input-json",
            "{}",
            "--type",
            "ethereum",
        ],
    ] {
        let result = record(cli().args(&args), 2);
        assert_eq!(result["code"], "usage_error", "{args:?}");
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("cannot be used with"),
            "{args:?}"
        );
    }
}

#[test]
fn missing_flags_are_usage_errors() {
    let tx = "--unsigned-transaction";
    for (args, missing) in [
        (vec!["wallet", "create", "--account", "ethereum"], "--name"),
        (
            vec!["wallet", "account", "create", "--wallet-id", WALLET],
            "--address-format",
        ),
        (
            vec![
                "sign",
                "payload",
                "--sign-with",
                "a",
                "--payload",
                "x",
                "--hash-function",
                "sha256",
            ],
            "--encoding",
        ),
        (
            vec![
                "sign",
                "payload",
                "--sign-with",
                "a",
                "--payload",
                "x",
                "--encoding",
                "text_utf8",
            ],
            "--hash-function",
        ),
        (
            vec![
                "sign",
                "payload",
                "--sign-with",
                "a",
                "--encoding",
                "text_utf8",
                "--hash-function",
                "sha256",
            ],
            "--payload",
        ),
        (
            vec!["sign", "transaction", "--sign-with", "a", tx, "00"],
            "--type",
        ),
        (
            vec![
                "sign",
                "transaction",
                "--sign-with",
                "a",
                "--type",
                "ethereum",
            ],
            "--unsigned-transaction",
        ),
    ] {
        let result = record(cli().args(&args), 2);
        assert_eq!(result["code"], "usage_error", "{args:?}");
        assert!(
            result["message"].as_str().unwrap().contains(missing),
            "{args:?}"
        );
    }
}

#[test]
fn unknown_enum_values_and_double_inputs_are_usage_errors() {
    for args in [
        vec![
            "sign",
            "transaction",
            "--sign-with",
            "a",
            "--unsigned-transaction",
            "00",
            "--type",
            "unspecified",
        ],
        vec![
            "sign",
            "payload",
            "--sign-with",
            "a",
            "--payload",
            "x",
            "--payload-file",
            "y",
            "--encoding",
            "text_utf8",
            "--hash-function",
            "sha256",
        ],
        vec!["wallet", "create", "--name", "x", "--mnemonic-length", "13"],
        vec!["wallet", "create", "--name", "x", "--account", "nonsense"],
    ] {
        let result = record(cli().args(&args), 2);
        assert_eq!(result["code"], "usage_error", "{args:?}");
    }
}
