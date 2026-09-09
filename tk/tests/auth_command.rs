use assert_cmd::Command;
use serde_json::{Value, json};
use std::{fs, path::Path};
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
fn command(temp: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in [
        "TK_CONFIG",
        "TK_PROFILE",
        "TURNKEY_TK_CONFIG_PATH",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_PRIVATE_KEY_ID",
        "TURNKEY_API_BASE_URL",
    ] {
        command.env_remove(name);
    }
    command
        .env("HOME", temp.path())
        .arg("--message-format=json");
    command
}
fn key(path: &Path) -> (String, String) {
    let key = TurnkeyP256ApiKey::generate();
    let public = hex::encode(key.compressed_public_key());
    let private = hex::encode(key.private_key());
    fs::write(
        path,
        serde_json::to_vec(&json!({"public_key": public, "private_key": private, "curve": "p256"}))
            .unwrap(),
    )
    .unwrap();
    (public, private)
}
fn registry(temp: &TempDir) -> (String, String) {
    let directory = temp.path().join(".config/turnkey");
    fs::create_dir_all(&directory).unwrap();
    let (admin, _) = key(&directory.join("admin.json"));
    let (agent, _) = key(&directory.join("agent.json"));
    fs::write(
        directory.join("tk.config.toml"),
        format!(
            r#"version = 1
active_profile = "admin"
[profiles.admin]
organization_id = "{ORG}"
api_base_url = "https://api.turnkey.com"
api_key_file = "{}/admin.json"
[profiles.agent]
organization_id = "{ORG}"
api_base_url = "https://api.turnkey.com"
api_key_file = "{}/agent.json"
"#,
            directory.display(),
            directory.display()
        ),
    )
    .unwrap();
    (admin, agent)
}
fn output(command: &mut Command) -> Value {
    let result = command.assert().success();
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}
#[test]
fn two_identities_share_an_org_and_explicit_selection_ignores_ambient_credentials() {
    let temp = TempDir::new().unwrap();
    let (admin, agent) = registry(&temp);
    let result = output(command(&temp).args(["auth", "status"]));
    assert_eq!(result["data"]["publicKey"], admin);
    let result = output(
        command(&temp)
            .env("TURNKEY_API_PRIVATE_KEY", "unused-secret")
            .args(["--profile", "agent", "auth", "status"]),
    );
    assert_eq!(
        result["data"],
        json!({"ready": true, "profile": "agent", "organizationId": ORG, "apiBaseUrl": "https://api.turnkey.com", "publicKey": agent, "credentialSource": "profile"})
    );
}
#[test]
fn environment_auth_does_not_require_home_or_read_bad_registry() {
    let temp = TempDir::new().unwrap();
    let (public, private) = key(&temp.path().join("key.json"));
    let config = temp.path().join("bad.toml");
    fs::write(&config, "not valid toml").unwrap();
    let result = output(
        command(&temp)
            .env_remove("HOME")
            .env("TK_CONFIG", &config)
            .env("TURNKEY_ORGANIZATION_ID", ORG)
            .env("TURNKEY_API_PUBLIC_KEY", &public)
            .env("TURNKEY_API_PRIVATE_KEY", private)
            .args(["auth", "status"]),
    );
    assert_eq!(result["data"]["credentialSource"], "environment");
    assert_eq!(result["data"]["publicKey"], public);
}
#[test]
fn partial_bundles_fail_without_leaking_secrets() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let result = command(&temp)
        .env("TURNKEY_API_PRIVATE_KEY", "never-print-this")
        .args(["auth", "status"])
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&result.get_output().stdout);
    assert!(!stdout.contains("never-print-this"));
    let parsed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["reason"], "command_error");
    assert_eq!(parsed["code"], "invalid_input");
}
#[test]
fn malformed_selected_registry_reports_invalid_input_without_source_text() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    fs::write(
        temp.path().join(".config/turnkey/tk.config.toml"),
        "secret-pasted-on-invalid-line",
    )
    .unwrap();
    let result = command(&temp)
        .args(["--profile", "agent", "auth", "status"])
        .assert()
        .failure();
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
    assert!(
        !parsed["message"]
            .as_str()
            .unwrap()
            .contains("secret-pasted")
    );
}
#[test]
fn profile_delete_and_logout_keep_credentials() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    output(command(&temp).args(["profile", "use", "agent"]));
    output(command(&temp).args(["auth", "logout"]));
    let list = output(command(&temp).args(["profile", "list"]));
    assert!(list["data"]["activeProfile"].is_null());
    output(command(&temp).args(["profile", "delete", "agent"]));
    assert!(temp.path().join(".config/turnkey/agent.json").exists());
    assert!(temp.path().join(".config/turnkey/admin.json").exists());
}
#[tokio::test]
async fn login_verifies_identity_and_selects_the_new_profile() {
    let temp = TempDir::new().unwrap();
    let key_path = temp.path().join("key.json");
    key(&key_path);
    let server = MockServer::start().await;
    let identity = json!({"organizationId": ORG, "organizationName": "test", "userId": "user-1", "username": "alice"});
    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .and(body_json(json!({"organizationId": ORG})))
        .respond_with(ResponseTemplate::new(200).set_body_json(&identity))
        .expect(2)
        .mount(&server)
        .await;
    let login = output(
        command(&temp)
            .args([
                "--organization-id",
                ORG,
                "--api-base-url",
                &server.uri(),
                "login",
                "admin",
                "--api-key-file",
            ])
            .arg(&key_path),
    );
    assert_eq!(login["data"]["identity"], identity);
    let whoami = output(command(&temp).arg("whoami"));
    assert_eq!(whoami["data"], identity);

    // An ambient TK_PROFILE must not silently name a new profile.
    let result = command(&temp)
        .env("TK_PROFILE", "ambient")
        .args(["--organization-id", ORG, "login", "other", "--api-key-file"])
        .arg(&key_path)
        .assert()
        .code(1);
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
}

#[tokio::test]
async fn typed_client_does_not_follow_redirects() {
    let temp = TempDir::new().unwrap();
    let key_path = temp.path().join("key.json");
    key(&key_path);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", "/leak"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/leak"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&server)
        .await;
    let result = command(&temp)
        .args([
            "--organization-id",
            ORG,
            "--api-base-url",
            &server.uri(),
            "login",
            "admin",
            "--api-key-file",
        ])
        .arg(&key_path)
        .assert()
        .code(1);
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "api_error");
    // The mock expectations prove the redirect target was never requested.
    server.verify().await;
}

#[tokio::test]
async fn typed_client_http_status_is_classified_end_to_end() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_user"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message":"no such user"})))
        .expect(1)
        .mount(&server)
        .await;
    let result = command(&temp)
        .args([
            "--api-base-url",
            &server.uri(),
            "user",
            "get",
            "00000000-0000-4000-8000-000000000002",
        ])
        .assert()
        .code(1);
    assert!(result.get_output().stderr.is_empty());
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["reason"], "command_error");
    assert_eq!(parsed["code"], "not_found");
    assert_eq!(parsed["httpStatus"], 404);
    assert!(parsed["message"].as_str().unwrap().contains("no such user"));
}

#[test]
fn invalid_key_length_is_an_error_without_panic() {
    let temp = TempDir::new().unwrap();
    let result = command(&temp)
        .env("TURNKEY_ORGANIZATION_ID", ORG)
        .env("TURNKEY_API_PUBLIC_KEY", "00")
        .env("TURNKEY_API_PRIVATE_KEY", "01")
        .args(["auth", "status"])
        .assert()
        .code(1);
    assert!(result.get_output().stderr.is_empty());
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["reason"], "command_error");
    assert_eq!(parsed["code"], "invalid_input");
    // Key material must not be echoed back, not even one character.
    assert!(!parsed["message"].as_str().unwrap().contains("'0'"));
}

#[test]
fn no_selected_identity_is_invalid_input() {
    let temp = TempDir::new().unwrap();
    let result = command(&temp).args(["auth", "status"]).assert().code(1);
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
    assert!(parsed["message"].as_str().unwrap().contains("tk login"));
}

#[test]
fn stale_lock_file_from_a_dead_process_does_not_block() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let lock = temp.path().join(".config/turnkey/tk.config.lock");
    fs::write(&lock, "99999").unwrap();
    output(command(&temp).args(["profile", "use", "agent"]));
}

#[test]
fn empty_environment_bundle_does_not_fall_back_to_saved_admin() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let result = command(&temp)
        .env("TURNKEY_API_PRIVATE_KEY", "")
        .args(["auth", "status"])
        .assert()
        .code(1);
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
    output(command(&temp).env("TURNKEY_API_PRIVATE_KEY", "").args([
        "--profile",
        "agent",
        "auth",
        "status",
    ]));
}

#[cfg(unix)]
#[test]
fn nonunicode_credential_environment_does_not_fall_back() {
    use std::os::unix::ffi::OsStringExt;
    let temp = TempDir::new().unwrap();
    registry(&temp);
    command(&temp)
        .env(
            "TURNKEY_API_PRIVATE_KEY",
            std::ffi::OsString::from_vec(vec![255]),
        )
        .args(["auth", "status"])
        .assert()
        .code(1);
}
