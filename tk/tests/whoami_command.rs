use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn whoami_displays_identity() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "organizationId": "org-123",
            "organizationName": "Test Org",
            "userId": "user-456",
            "username": "testuser"
        })))
        .mount(&server)
        .await;

    let api_key = TurnkeyP256ApiKey::generate();
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"[turnkey]
organizationId = "org-123"
apiPublicKey = "{}"
apiPrivateKey = "{}"
signingAddress = "test-address"
signingPublicKey = "6666666666666666666666666666666666666666666666666666666666666666"
apiBaseUrl = "{}"
"#,
            hex::encode(api_key.compressed_public_key()),
            hex::encode(api_key.private_key()),
            server.uri(),
        ),
    )
    .unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("whoami")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Organization:  Test Org (org-123)",
        ))
        .stdout(predicate::str::contains(
            "User:          testuser (user-456)",
        ));
}

#[tokio::test]
async fn whoami_suggests_init_when_config_missing() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

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
