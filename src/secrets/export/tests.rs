// Asserts on the classified error code.
#![allow(clippy::disallowed_types)]
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path as route};

use super::*;
use crate::errors::{ErrorCode, classify};

const ORG: &str = "00000000-0000-4000-8000-000000000001";

fn fixture(server: &MockServer) -> (TempDir, ResolvedAuth, Uuid) {
    let auth = ResolvedAuth::for_tests(ORG, &server.uri(), TurnkeyP256ApiKey::generate());
    (TempDir::new().unwrap(), auth, Uuid::new_v4())
}

#[tokio::test]
async fn a_submission_that_fails_leaves_no_recipient_key_on_disk() {
    let server = MockServer::start().await;
    Mock::given(route("/public/v1/submit/export_secrets"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"message": "unavailable"})))
        .mount(&server)
        .await;
    let (dir, auth, secret_id) = fixture(&server);
    let binding = Binding::of(&auth);
    let pending_dir = binding.pending_dir(dir.path());

    let error = export_value(
        &pending_dir,
        &QuorumPublicKey::production_signer(),
        binding,
        &auth,
        secret_id,
        UniqueKeyValues::parse(vec![], "--context").unwrap(),
    )
    .await
    .err()
    .expect("export should have failed");

    assert_eq!(classify(&error).code, ErrorCode::ApiError);
    assert!(!PendingExport::path(&pending_dir, secret_id).exists());
}

#[tokio::test]
async fn state_written_against_another_endpoint_is_refused() {
    let server = MockServer::start().await;
    let (dir, auth, secret_id) = fixture(&server);
    let binding = Binding::of(&auth);
    let pending_dir = binding.pending_dir(dir.path());
    let path = PendingExport::path(&pending_dir, secret_id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        to_vec(&json!({
            "version": 1,
            "organizationId": binding.organization_id,
            "apiBaseUrl": "https://api.turnkey.com",
            "apiPublicKey": binding.api_public_key,
            "secretId": secret_id,
            "activityId": "a1",
            "targetPublicKey": "04aabb",
            "keyMaterial": "11".repeat(32),
        }))
        .unwrap(),
    )
    .unwrap();

    let error = export_value(
        &pending_dir,
        &QuorumPublicKey::production_signer(),
        binding,
        &auth,
        secret_id,
        UniqueKeyValues::parse(vec![], "--context").unwrap(),
    )
    .await
    .err()
    .expect("export should have failed");

    assert_eq!(classify(&error).code, ErrorCode::InvalidInput);
    let InvalidInput(message) = error
        .downcast_ref::<InvalidInput>()
        .expect("refused state is an InvalidInput error");
    assert_eq!(
        *message,
        format!(
            "pending export state {} belongs to a different API base URL (https://api.turnkey.com, not {}); resume it with the identity that started it",
            path.display(),
            server.uri()
        )
    );
}
