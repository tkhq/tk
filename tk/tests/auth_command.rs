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

fn key(path: &Path) {
    let key = TurnkeyP256ApiKey::generate();
    let stored = json!({
        "public_key": hex::encode(key.compressed_public_key()),
        "private_key": hex::encode(key.private_key()),
        "curve": "p256",
    });
    fs::write(path, serde_json::to_vec(&stored).unwrap()).unwrap();
}

fn registry(temp: &TempDir) {
    let directory = temp.path().join(".config/turnkey");
    fs::create_dir_all(&directory).unwrap();
    key(&directory.join("admin.json"));
    key(&directory.join("agent.json"));
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
}

fn output(command: &mut Command) -> Value {
    let result = command.assert().success();
    serde_json::from_slice(&result.get_output().stdout).unwrap()
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
fn relative_credential_path_in_registry_is_invalid_input() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    fs::write(
        temp.path().join(".config/turnkey/tk.config.toml"),
        format!(
            r#"version = 1
active_profile = "admin"
[profiles.admin]
organization_id = "{ORG}"
api_base_url = "https://api.turnkey.com"
api_key_file = "admin.json"
"#
        ),
    )
    .unwrap();
    let result = command(&temp)
        .current_dir(temp.path().join(".config/turnkey"))
        .args(["auth", "status"])
        .assert()
        .failure();
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
    assert!(
        parsed["message"]
            .as_str()
            .unwrap()
            .contains("relative api_key_file admin.json")
    );
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
            "--id",
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
    assert!(!parsed["message"].as_str().unwrap().contains("'0'"));
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
