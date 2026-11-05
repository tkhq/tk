//! Mock-API tests for `private-key` failure modes the live API cannot produce on demand.
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
const BAD_TAG: &str = "not-a-uuid";

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

#[tokio::test]
async fn get_of_an_absent_private_key_is_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_private_key"))
        .and(body_partial_json(
            json!({"organizationId": ORG, "privateKeyId": KEY_ID}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    let result = record(
        authed(&server.uri()).args(["private-key", "get", "--id", KEY_ID]),
        1,
    );
    assert_eq!(result["code"], "not_found");
}

#[test]
fn a_usage_error_exits_two_with_the_usage_error_code() {
    let result = record(cli().args(["private-key", "create", "--name", "k"]), 2);
    assert_eq!(result["reason"], "command_error");
    assert_eq!(result["code"], "usage_error");
}

#[test]
fn malformed_or_empty_parameters_are_invalid_input_before_credentials() {
    let malformed_tag = json!({"privateKeys": [{
        "privateKeyName": "k",
        "curve": "CURVE_ED25519",
        "privateKeyTags": [BAD_TAG],
    }]})
    .to_string();
    for json in ["{", r#"{"privateKeys":[]}"#, malformed_tag.as_str()] {
        let result = record(
            cli().args(["private-key", "create", "--input-json", json]),
            1,
        );
        assert_eq!(result["code"], "invalid_input", "{json}");
    }
}
