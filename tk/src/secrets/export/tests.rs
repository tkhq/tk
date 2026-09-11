use super::*;
use crate::errors::{ErrorCode, classify};
use serde_json::Value;
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::path as route;
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "00000000-0000-4000-8000-000000000001";

fn fixture(server: &MockServer) -> (TempDir, ResolvedAuth, Uuid) {
    let auth = ResolvedAuth::for_tests(ORG, &server.uri(), TurnkeyP256ApiKey::generate());
    (TempDir::new().unwrap(), auth, Uuid::new_v4())
}

fn mock(route_path: &str, status: u16, body: Value) -> Mock {
    Mock::given(route(format!("/public/v1/{route_path}")))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
}

/// A submission that never answers `pending` leaves no recovery key.
#[tokio::test]
async fn a_submission_that_fails_leaves_no_recipient_key_on_disk() {
    let server = MockServer::start().await;
    mock(
        "submit/export_secrets",
        500,
        json!({"message": "unavailable"}),
    )
    .mount(&server)
    .await;
    let (dir, auth, secret_id) = fixture(&server);
    let binding = Binding::of(&auth);

    let error = export(
        dir.path(),
        QuorumPublicKey::production_signer(),
        auth,
        SecretRef::Id(secret_id),
        None,
        vec![],
    )
    .await
    .err()
    .expect("export should have failed");

    assert_eq!(classify(&error).code, ErrorCode::ApiError);
    assert!(!PendingExport::path(dir.path(), &binding, secret_id).exists());
}

/// State bound to another endpoint cannot finish this export.
#[tokio::test]
async fn state_written_against_another_endpoint_is_refused() {
    let server = MockServer::start().await;
    let (dir, auth, secret_id) = fixture(&server);
    let binding = Binding::of(&auth);
    let path = PendingExport::path(dir.path(), &binding, secret_id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
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

    let error = export(
        dir.path(),
        QuorumPublicKey::production_signer(),
        auth,
        SecretRef::Id(secret_id),
        None,
        vec![],
    )
    .await
    .err()
    .expect("export should have failed");

    assert_eq!(classify(&error).code, ErrorCode::InvalidInput);
    let message = format!("{error:#}");
    assert!(
        message.contains("different API base URL") && message.contains("https://api.turnkey.com"),
        "{message}"
    );
}
