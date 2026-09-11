use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string, method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in [
        "HOME",
        "TK_CONFIG",
        "TK_PROFILE",
        "TURNKEY_TK_CONFIG_PATH",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_PRIVATE_KEY_ID",
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
#[test]
fn malformed_local_inputs_are_rejected_before_credentials() {
    for args in [
        vec![
            "request",
            "--path",
            "/public/v1/query/whoami",
            "--body",
            "{",
        ],
        vec!["user", "create", "--input-json", "{"],
        vec!["wallet", "create", "--input-json", "{"],
        vec!["sign", "payload", "--input-json", "{"],
    ] {
        let result = record(cli().args(args), 1);
        assert_eq!(result["code"], "invalid_input");
        assert!(!result["message"].as_str().unwrap().contains("HOME"));
    }
}
#[test]
fn offline_generation_needs_no_identity_and_never_overwrites() {
    let temp = TempDir::new().unwrap();
    let key = temp.path().join("key.json");
    let result = record(cli().args(["api-key", "generate", "--output"]).arg(&key), 0);
    assert_eq!(result["command"], "api-key.generate");
    let bytes = std::fs::read(&key).unwrap();
    let stored: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        !result
            .to_string()
            .contains(stored["private_key"].as_str().unwrap())
    );
    record(cli().args(["api-key", "generate", "--output"]).arg(&key), 1);
    assert_eq!(std::fs::read(key).unwrap(), bytes);
}
#[tokio::test]
async fn signed_request_preserves_body_and_pending_vs_rejected_exit_codes() {
    let server = MockServer::start().await;
    let body = format!(
        r#"{{
  "organizationId": "{ORG}"
}}
"#
    );
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/example"))
        .and(body_string(&body))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"activity":{"id":"pending-id","status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let pending = record(
        authed(&server.uri()).args([
            "request",
            "--path",
            "/public/v1/submit/example",
            "--body",
            &body,
        ]),
        0,
    );
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["activity"]["id"], "pending-id");
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_activity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"activity":{"id":"rejected-id","status":"ACTIVITY_STATUS_REJECTED"}}),
        ))
        .expect(2)
        .mount(&server)
        .await;
    let inspected = record(
        authed(&server.uri()).args(["activity", "get", "rejected-id"]),
        0,
    );
    assert_eq!(inspected["activity"]["status"], "ACTIVITY_STATUS_REJECTED");
    let waited = record(
        authed(&server.uri()).args(["activity", "wait", "rejected-id"]),
        1,
    );
    assert_eq!(waited["reason"], "command_error");
    assert_eq!(waited["code"], "api_error");
    assert_eq!(
        waited["activity"],
        json!({"id":"rejected-id","status":"ACTIVITY_STATUS_REJECTED"})
    );
}

#[tokio::test]
async fn raw_request_http_status_keeps_the_api_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_activity"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"message":"organization mismatch for activity"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let result = record(
        authed(&server.uri()).args(["activity", "get", "some-id"]),
        1,
    );
    assert_eq!(result["reason"], "command_error");
    assert_eq!(result["code"], "api_error");
    assert_eq!(result["httpStatus"], 400);
    assert!(
        result["message"]
            .as_str()
            .unwrap()
            .contains("organization mismatch for activity")
    );
}

#[tokio::test]
async fn wait_timeout_is_a_resumable_error_record() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_activity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"activity":{"id":"slow-id","status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}}),
        ))
        .mount(&server)
        .await;
    let result = record(
        authed(&server.uri()).args(["activity", "wait", "slow-id", "--timeout", "1"]),
        1,
    );
    assert_eq!(result["code"], "wait_timeout");
    assert_eq!(
        result["activity"],
        json!({"id":"slow-id","status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"})
    );
}

#[test]
fn human_mode_errors_go_to_stderr_for_api_commands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in ["HOME", "TK_CONFIG", "TK_PROFILE", "TURNKEY_ORGANIZATION_ID"] {
        cmd.env_remove(name);
    }
    cmd.args([
        "request",
        "--path",
        "/public/v1/query/whoami",
        "--body",
        "{",
    ])
    .assert()
    .code(1)
    .stdout(predicates::str::is_empty())
    .stderr(predicates::str::contains("error: body must be valid JSON"));
}
