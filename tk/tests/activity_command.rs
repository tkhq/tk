use assert_cmd::Command;
use predicates::prelude::*;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn activity_help_lists_subcommands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("activity").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("approve"))
        .stdout(predicate::str::contains("reject"))
        .stdout(predicate::str::contains("tk activity <COMMAND>"));
}

#[tokio::test]
async fn activity_approve_does_not_require_private_key_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/approve_activity"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "id": "approve-act-id",
                "organizationId": "org-id",
                "fingerprint": "approve-fp",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_APPROVE_ACTIVITY"
            }
        })))
        .mount(&server)
        .await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("activity")
        .arg("approve")
        .arg("test-fingerprint")
        .env("TURNKEY_ORGANIZATION_ID", "org-id")
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(api_key.compressed_public_key()),
        )
        .env(
            "TURNKEY_API_PRIVATE_KEY",
            hex::encode(api_key.private_key()),
        )
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env("TURNKEY_API_BASE_URL", server.uri());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Activity approved."));
}

#[tokio::test]
async fn activity_reject_does_not_require_private_key_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/reject_activity"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "id": "reject-act-id",
                "organizationId": "org-id",
                "fingerprint": "reject-fp",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_REJECT_ACTIVITY"
            }
        })))
        .mount(&server)
        .await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("activity")
        .arg("reject")
        .arg("test-fingerprint")
        .env("TURNKEY_ORGANIZATION_ID", "org-id")
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(api_key.compressed_public_key()),
        )
        .env(
            "TURNKEY_API_PRIVATE_KEY",
            hex::encode(api_key.private_key()),
        )
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env("TURNKEY_API_BASE_URL", server.uri());

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Activity rejected."));
}
