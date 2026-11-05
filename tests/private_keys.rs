//! Tests for the `private-key` commands against a mock API.
// Test helpers may panic.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use serde_json::{Value, json};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
const KEY_ID: &str = "3d7b9d7c-2a0e-4b7f-8f8e-5e1f2d3c4b5a";

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
        .arg(base)
        .arg("--non-interactive");
    cmd
}

fn record(cmd: &mut Command, code: i32) -> Value {
    let result = cmd.assert().code(code);
    assert!(result.get_output().stderr.is_empty());
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}

fn private_key() -> Value {
    json!({
        "privateKeyId": KEY_ID,
        "publicKey": "02ab",
        "privateKeyName": "treasury",
        "curve": "CURVE_SECP256K1",
        "addresses": [],
        "privateKeyTags": [],
        "exported": false,
        "imported": false,
    })
}

async fn mock_json(server: &MockServer, endpoint: &str, kind: &str, body: Value) {
    Mock::given(method("POST"))
        .and(path(endpoint))
        .and(body_partial_json(json!({"organizationId": ORG})))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .named(kind)
        .mount(server)
        .await;
}

#[tokio::test]
async fn list_prints_every_private_key() {
    let server = MockServer::start().await;
    mock_json(
        &server,
        "/public/v1/query/list_private_keys",
        "list",
        json!({"privateKeys": [private_key()]}),
    )
    .await;
    let result = record(authed(&server.uri()).args(["private-key", "list"]), 0);
    assert_eq!(result["command"], "private-key.list");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["privateKeys"][0]["privateKeyId"], KEY_ID);
}

#[tokio::test]
async fn get_prints_one_private_key_and_reports_a_missing_one() {
    let server = MockServer::start().await;
    mock_json(
        &server,
        "/public/v1/query/get_private_key",
        "get",
        json!({"privateKey": private_key()}),
    )
    .await;
    let result = record(
        authed(&server.uri()).args(["private-key", "get", "--id", KEY_ID]),
        0,
    );
    assert_eq!(result["command"], "private-key.get");
    assert_eq!(result["data"]["privateKey"]["privateKeyName"], "treasury");

    let server = MockServer::start().await;
    mock_json(
        &server,
        "/public/v1/query/get_private_key",
        "get",
        json!({}),
    )
    .await;
    let result = record(
        authed(&server.uri()).args(["private-key", "get", "--id", KEY_ID]),
        1,
    );
    assert_eq!(result["code"], "not_found");
}

#[tokio::test]
async fn create_from_flags_submits_one_private_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/create_private_keys"))
        .and(body_partial_json(json!({
            "type": "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
            "organizationId": ORG,
            "parameters": {"privateKeys": [{
                "privateKeyName": "treasury",
                "curve": "CURVE_SECP256K1",
                "privateKeyTags": [],
                "addressFormats": ["ADDRESS_FORMAT_ETHEREUM"],
            }]},
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"activity": {
                "id": "activity-id",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {"createPrivateKeysResultV2": {"privateKeys": [
                    {"privateKeyId": KEY_ID, "addresses": []}
                ]}},
            }})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = record(
        authed(&server.uri()).args([
            "private-key",
            "create",
            "--name",
            "treasury",
            "--curve",
            "secp256k1",
            "--address-format",
            "ethereum",
        ]),
        0,
    );
    assert_eq!(result["command"], "private-key.create");
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["data"]["activity"]["result"]["createPrivateKeysResultV2"]["privateKeys"][0]["privateKeyId"],
        KEY_ID
    );
}

#[tokio::test]
async fn create_from_json_that_needs_consensus_exits_zero_as_pending() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/create_private_keys"))
        .and(body_partial_json(json!({
            "parameters": {"privateKeys": [{"privateKeyName": "treasury", "curve": "CURVE_ED25519"}]},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"activity": {
            "id": "pending-id",
            "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
        }})))
        .expect(1)
        .mount(&server)
        .await;
    let result = record(
        authed(&server.uri()).args([
            "private-key",
            "create",
            "--input-json",
            r#"{"privateKeys":[{"privateKeyName":"treasury","curve":"CURVE_ED25519"}]}"#,
        ]),
        0,
    );
    assert_eq!(result["command"], "private-key.create");
    assert_eq!(result["status"], "pending");
    assert_eq!(result["activity"]["id"], "pending-id");
}

#[test]
fn usage_errors_exit_two_before_any_request() {
    for args in [
        vec!["private-key", "create"],
        vec!["private-key", "create", "--name", "k"],
        vec!["private-key", "create", "--name", "k", "--curve", "rsa"],
        vec!["private-key", "get", "--id", "not-a-uuid"],
        vec![
            "private-key",
            "create",
            "--name",
            "k",
            "--curve",
            "ed25519",
            "--input-json",
            "{}",
        ],
    ] {
        let result = record(cli().args(&args), 2);
        assert_eq!(result["reason"], "command_error", "{args:?}");
        assert_eq!(result["code"], "usage_error", "{args:?}");
    }
}

#[test]
fn malformed_or_empty_parameters_are_invalid_input_before_credentials() {
    for json in ["{", r#"{"privateKeys":[]}"#] {
        let result = record(
            cli().args(["private-key", "create", "--input-json", json]),
            1,
        );
        assert_eq!(result["code"], "invalid_input", "{json}");
    }
}
