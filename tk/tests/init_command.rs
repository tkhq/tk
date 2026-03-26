use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn api_key_env(cmd: &mut Command, api_key: &TurnkeyP256ApiKey) {
    cmd.env(
        "TURNKEY_API_PUBLIC_KEY",
        hex::encode(api_key.compressed_public_key()),
    )
    .env(
        "TURNKEY_API_PRIVATE_KEY",
        hex::encode(api_key.private_key()),
    );
}

#[tokio::test]
async fn init_uses_existing_wallet_with_ed25519_account() {
    let server = MockServer::start().await;

    // Mock list wallets returning one wallet.
    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallets"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": [{
                "walletId": "existing-wallet-id",
                "walletName": "my-wallet",
                "createdAt": null,
                "updatedAt": null,
                "exported": false,
                "imported": false
            }]
        })))
        .mount(&server)
        .await;

    // Mock list wallet accounts returning an Ed25519 account.
    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallet_accounts"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accounts": [{
                "walletAccountId": "acct-id",
                "organizationId": "org-id",
                "walletId": "existing-wallet-id",
                "curve": "CURVE_ED25519",
                "pathFormat": "PATH_FORMAT_BIP32",
                "path": "m/44'/501'/0'/0'",
                "addressFormat": "ADDRESS_FORMAT_COMPRESSED",
                "address": "test-address",
                "publicKey": "aabbccdd",
                "createdAt": null,
                "updatedAt": null
            }]
        })))
        .mount(&server)
        .await;

    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let api_key = TurnkeyP256ApiKey::generate();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("init")
        .arg("--organization-id")
        .arg("org-id")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env("TURNKEY_API_BASE_URL", server.uri());
    api_key_env(&mut cmd, &api_key);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Found existing Ed25519 account"))
        .stdout(predicate::str::contains("Signing address: test-address"))
        .stdout(predicate::str::contains("Configuration saved to"));

    // Verify config was written with signing address and public key.
    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(contents.contains("test-address"));
    assert!(contents.contains("aabbccdd"));
    assert!(contents.contains("org-id"));

    // Verify permissions are 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&config_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn init_creates_wallet_when_none_exist() {
    let server = MockServer::start().await;

    // Mock list wallets returning empty.
    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallets"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wallets": []
        })))
        .mount(&server)
        .await;

    // Mock create wallet.
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/create_wallet"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "id": "activity-id",
                "organizationId": "org-id",
                "fingerprint": "fingerprint",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_CREATE_WALLET",
                "result": {
                    "createWalletResult": {
                        "walletId": "new-wallet-id",
                        "addresses": ["new-address"]
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    // Mock list wallet accounts for the newly created wallet.
    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallet_accounts"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accounts": [{
                "walletAccountId": "new-acct-id",
                "organizationId": "org-id",
                "walletId": "new-wallet-id",
                "curve": "CURVE_ED25519",
                "pathFormat": "PATH_FORMAT_BIP32",
                "path": "m/44'/501'/0'/0'",
                "addressFormat": "ADDRESS_FORMAT_COMPRESSED",
                "address": "new-address",
                "publicKey": "ddeeff00",
                "createdAt": null,
                "updatedAt": null
            }]
        })))
        .mount(&server)
        .await;

    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    let api_key = TurnkeyP256ApiKey::generate();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.arg("init")
        .arg("--organization-id")
        .arg("org-id")
        .env("TURNKEY_TK_CONFIG_PATH", &config_path)
        .env("TURNKEY_API_BASE_URL", server.uri());
    api_key_env(&mut cmd, &api_key);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Created new wallet"))
        .stdout(predicate::str::contains("Signing address: new-address"));

    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(contents.contains("new-address"));
    assert!(contents.contains("ddeeff00"));
}
