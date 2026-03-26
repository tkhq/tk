use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn whoami_displays_identity() {
    let server = MockServer::start().await;
    let api_key = TurnkeyP256ApiKey::generate();
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    fs::write(
        &config_path,
        format!(
            r#"[turnkey]
organizationId = "org-id"
apiPublicKey = "{}"
apiPrivateKey = "{}"
signingAddress = "signing-addr"
signingPublicKey = "6666666666666666666666666666666666666666666666666666666666666666"
apiBaseUrl = "{}"
"#,
            hex::encode(api_key.compressed_public_key()),
            hex::encode(api_key.private_key()),
            server.uri(),
        ),
    )
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "organizationId": "org-id",
                    "organizationName": "My Org",
                    "userId": "user-123",
                    "username": "testuser"
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("whoami")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_API_BASE_URL");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("My Org"))
        .stdout(predicate::str::contains("org-id"))
        .stdout(predicate::str::contains("testuser"))
        .stdout(predicate::str::contains("user-123"));
}

#[test]
fn whoami_suggests_init_when_config_missing() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("nonexistent.toml");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("whoami")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_API_BASE_URL");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("tk init"));
}
