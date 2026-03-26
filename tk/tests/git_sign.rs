use std::process::Stdio;

use predicates::prelude::*;
use tempfile::tempdir;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::ssh;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TURNKEY_TEST_V: &str = "00";

#[tokio::test]
async fn git_sign_writes_verifiable_sshsig_file() {
    let temp = tempdir().expect("temp dir should exist");
    let key_path = temp.path().join("id_ed25519");
    let public_key_path = temp.path().join("id_ed25519.pub");
    let payload_path = temp.path().join("payload.txt");
    let allowed_signers_path = temp.path().join("allowed_signers");
    let config_path = temp.path().join("tk.toml");

    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .status()
        .await
        .expect("ssh-keygen should run");
    assert!(status.success());

    fs::write(&payload_path, b"hello world")
        .await
        .expect("payload should be written");

    let raw_signature = extract_raw_signature(&key_path, &payload_path).await;
    let public_key_line = fs::read_to_string(&public_key_path)
        .await
        .expect("public key should exist");
    let parsed_public_key =
        ssh::parse_public_key_line(&public_key_line).expect("public key should parse");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "id": "activity-id",
                "organizationId": "org-id",
                "fingerprint": "fingerprint",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                "result": {
                    "signRawPayloadResult": {
                        "r": hex::encode(&raw_signature[..32]),
                        "s": hex::encode(&raw_signature[32..]),
                        "v": TURNKEY_TEST_V
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    let api_key = TurnkeyP256ApiKey::generate();
    write_test_config(
        &config_path,
        &api_key,
        &server.uri(),
        &hex::encode(&parsed_public_key.public_key),
    );

    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("git-sign")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg("git")
        .arg("-f")
        .arg(&public_key_path)
        .arg(&payload_path)
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert().success();

    let signature_path = payload_path.with_extension("txt.sig");
    assert!(
        fs::try_exists(&signature_path)
            .await
            .expect("signature path should be readable"),
        "signature file should be created"
    );

    fs::write(
        &allowed_signers_path,
        format!("git {}", public_key_line.trim()),
    )
    .await
    .expect("allowed signers should be written");

    let payload = fs::read(&payload_path)
        .await
        .expect("payload should be readable");
    let mut verify = Command::new("ssh-keygen");
    verify
        .args(["-Y", "verify", "-n", "git", "-I", "git", "-f"])
        .arg(&allowed_signers_path)
        .arg("-s")
        .arg(&signature_path)
        .stdin(Stdio::piped());
    let mut child = verify.spawn().expect("ssh-keygen verify should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(&payload)
        .await
        .expect("payload should write to stdin");
    let status = child.wait().await.expect("ssh-keygen verify should run");

    assert!(status.success(), "ssh-keygen should verify auth output");
}

#[tokio::test]
async fn direct_ssh_signer_invocation_writes_verifiable_sshsig_file() {
    let temp = tempdir().expect("temp dir should exist");
    let key_path = temp.path().join("id_ed25519");
    let public_key_path = temp.path().join("id_ed25519.pub");
    let payload_path = temp.path().join("payload.txt");
    let allowed_signers_path = temp.path().join("allowed_signers");
    let config_path = temp.path().join("tk.toml");

    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .status()
        .await
        .expect("ssh-keygen should run");
    assert!(status.success());

    fs::write(&payload_path, b"hello world")
        .await
        .expect("payload should be written");

    let raw_signature = extract_raw_signature(&key_path, &payload_path).await;
    let public_key_line = fs::read_to_string(&public_key_path)
        .await
        .expect("public key should exist");
    let parsed_public_key =
        ssh::parse_public_key_line(&public_key_line).expect("public key should parse");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "id": "activity-id",
                "organizationId": "org-id",
                "fingerprint": "fingerprint",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                "result": {
                    "signRawPayloadResult": {
                        "r": hex::encode(&raw_signature[..32]),
                        "s": hex::encode(&raw_signature[32..]),
                        "v": TURNKEY_TEST_V
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    let api_key = TurnkeyP256ApiKey::generate();
    write_test_config(
        &config_path,
        &api_key,
        &server.uri(),
        &hex::encode(&parsed_public_key.public_key),
    );

    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg("git")
        .arg("-f")
        .arg(&public_key_path)
        .arg(&payload_path)
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert().success();

    let signature_path = payload_path.with_extension("txt.sig");
    assert!(
        fs::try_exists(&signature_path)
            .await
            .expect("signature path should be readable"),
        "signature file should be created"
    );

    fs::write(
        &allowed_signers_path,
        format!("git {}", public_key_line.trim()),
    )
    .await
    .expect("allowed signers should be written");

    let payload = fs::read(&payload_path)
        .await
        .expect("payload should be readable");
    let mut verify = Command::new("ssh-keygen");
    verify
        .args(["-Y", "verify", "-n", "git", "-I", "git", "-f"])
        .arg(&allowed_signers_path)
        .arg("-s")
        .arg(&signature_path)
        .stdin(Stdio::piped());
    let mut child = verify.spawn().expect("ssh-keygen verify should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(&payload)
        .await
        .expect("payload should write to stdin");
    let status = child.wait().await.expect("ssh-keygen verify should run");

    assert!(status.success(), "ssh-keygen should verify auth output");
}

#[tokio::test]
async fn git_sign_rejects_public_key_that_does_not_match_configured_turnkey_key() {
    let temp = tempdir().expect("temp dir should exist");
    let key_path = temp.path().join("id_ed25519");
    let public_key_path = temp.path().join("id_ed25519.pub");
    let payload_path = temp.path().join("payload.txt");
    let config_path = temp.path().join("tk.toml");

    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .status()
        .await
        .expect("ssh-keygen should run");
    assert!(status.success());

    fs::write(&payload_path, b"hello world")
        .await
        .expect("payload should be written");

    let server = MockServer::start().await;
    let api_key = TurnkeyP256ApiKey::generate();
    // Use a DIFFERENT public key so it does not match the generated ssh key
    write_test_config(
        &config_path,
        &api_key,
        &server.uri(),
        "1111111111111111111111111111111111111111111111111111111111111111",
    );

    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("git-sign")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg("git")
        .arg("-f")
        .arg(&public_key_path)
        .arg(&payload_path)
        .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert().failure().stderr(predicate::str::contains(
        "does not match the configured Turnkey key",
    ));

    let signature_path = payload_path.with_extension("txt.sig");
    assert!(
        !fs::try_exists(&signature_path)
            .await
            .expect("signature path should be readable"),
        "signature file should not be created"
    );
}

fn write_test_config(
    config_path: &std::path::Path,
    api_key: &TurnkeyP256ApiKey,
    api_base_url: &str,
    signing_public_key: &str,
) {
    std::fs::write(
        config_path,
        format!(
            r#"[turnkey]
organizationId = "org-id"
apiPublicKey = "{}"
apiPrivateKey = "{}"
signingAddress = "signing-addr"
signingPublicKey = "{}"
apiBaseUrl = "{}"
"#,
            hex::encode(api_key.compressed_public_key()),
            hex::encode(api_key.private_key()),
            signing_public_key,
            api_base_url,
        ),
    )
    .unwrap();
}

async fn extract_raw_signature(
    key_path: &std::path::Path,
    payload_path: &std::path::Path,
) -> Vec<u8> {
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(key_path)
        .arg(payload_path)
        .status()
        .await
        .expect("ssh-keygen sign should run");
    assert!(status.success());

    let signature_path = payload_path.with_extension("txt.sig");
    let armored = fs::read_to_string(signature_path)
        .await
        .expect("signature should exist");
    parse_raw_signature_from_armored(&armored)
}

fn parse_raw_signature_from_armored(armored: &str) -> Vec<u8> {
    use base64::Engine;

    let base64 = armored
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .expect("signature body should decode");

    let mut cursor = blob.as_slice();
    assert_eq!(&cursor[..6], b"SSHSIG");
    cursor = &cursor[6 + 4..];

    let _public_key = read_ssh_bytes(&mut cursor);
    let _namespace = read_ssh_bytes(&mut cursor);
    let _reserved = read_ssh_bytes(&mut cursor);
    let _hash_algorithm = read_ssh_bytes(&mut cursor);
    let signature_blob = read_ssh_bytes(&mut cursor);

    let mut signature_cursor = signature_blob.as_slice();
    let algorithm = read_ssh_bytes(&mut signature_cursor);
    assert_eq!(std::str::from_utf8(&algorithm).unwrap(), "ssh-ed25519");
    read_ssh_bytes(&mut signature_cursor)
}

fn read_ssh_bytes(cursor: &mut &[u8]) -> Vec<u8> {
    let length = u32::from_be_bytes(cursor[..4].try_into().expect("ssh length should exist"));
    *cursor = &cursor[4..];
    let length = length as usize;
    let value = cursor[..length].to_vec();
    *cursor = &cursor[length..];
    value
}
