//! Tests for `tk login --device` against a mock identity service and API.
// Test helpers may panic.
#![allow(clippy::unwrap_used)]

use std::fs;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header_exists, method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
const USER: &str = "00000000-0000-4000-8000-000000000002";

fn login(home: &TempDir, server: &MockServer) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in [
        "TK_PROFILE",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_API_BASE_URL",
        "TK_IDENTITY_ISSUER_URL",
        "XDG_CONFIG_HOME",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home.path())
        .arg("--message-format=json")
        .args([
            "login",
            "--device",
            "--profile-name",
            "agent",
            "--issuer-url",
        ])
        .arg(format!("{}/login", server.uri()))
        .arg("--api-base-url")
        .arg(server.uri());
    cmd
}

async fn device_code(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .and(body_string_contains("client_id=tk"))
        .and(body_string_contains("public_key=0"))
        .and(body_string_contains("session_expiration_seconds=28800"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "device-code",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://app.turnkey.com/device",
            "expires_in": 600,
            "interval": 0,
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn api_keys(home: &TempDir) -> Vec<String> {
    let dir = home.path().join(".config/turnkey/tk/api-keys");
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn an_approved_device_login_saves_and_selects_the_profile() {
    let server = MockServer::start().await;
    let home = TempDir::new().unwrap();
    device_code(&server).await;
    Mock::given(method("POST"))
        .and(path("/login/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/login/token"))
        .and(header_exists("DPoP"))
        .and(body_string_contains("device_code=device-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "session.jwt.value",
            "token_type": "N_A",
            "expires_in": 28800,
            "user_id": USER,
            "organization_id": ORG,
        })))
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "organizationId": ORG,
            "organizationName": "Acme",
            "userId": USER,
            "username": "agent",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let output = login(&home, &server)
        .args(["--expires-in", "8h"])
        .assert()
        .code(0)
        .get_output()
        .clone();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("https://app.turnkey.com/device"),
        "{stderr}"
    );
    assert!(stderr.contains("WDJB-MJHT"), "{stderr}");

    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["command"], "auth.login");
    let result = &record["data"];
    assert_eq!(result["profile"], "agent");
    assert_eq!(result["userId"], USER);
    assert_eq!(result["sessionExpiresInSeconds"], 28800);
    assert_eq!(result["previousKeyRemoved"], false);
    assert_eq!(result["identity"]["organizationId"], ORG);

    let keys = api_keys(&home);
    assert_eq!(
        keys,
        [format!("{}.json", result["publicKey"].as_str().unwrap())]
    );

    let config = fs::read_to_string(home.path().join(".config/turnkey/tk.config.toml")).unwrap();
    assert!(config.contains(r#"active_profile = "agent""#), "{config}");
    assert!(
        config.contains(&format!(r#"organization_id = "{ORG}""#)),
        "{config}"
    );
}

#[tokio::test]
async fn a_denied_device_login_saves_nothing() {
    let server = MockServer::start().await;
    let home = TempDir::new().unwrap();
    device_code(&server).await;
    Mock::given(method("POST"))
        .and(path("/login/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "access_denied"})))
        .mount(&server)
        .await;

    let output = login(&home, &server)
        .args(["--expires-in", "8h"])
        .assert()
        .code(1)
        .get_output()
        .clone();

    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["code"], "unauthorized");
    assert_eq!(
        record["message"],
        "device login was denied in the dashboard"
    );
    assert_eq!(
        api_keys(&home),
        Vec::<String>::new(),
        "the generated key is removed"
    );
    assert!(!home.path().join(".config/turnkey/tk.config.toml").exists());
}

#[test]
fn expires_in_needs_device() {
    let home = TempDir::new().unwrap();
    Command::new(env!("CARGO_BIN_EXE_tk"))
        .env("HOME", home.path())
        .args(["login", "--expires-in", "8h"])
        .assert()
        .code(2);
}
