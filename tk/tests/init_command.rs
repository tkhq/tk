use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn init_uses_existing_wallet_with_ed25519_account() {
    let server = MockServer::start().await;
    let api_key = TurnkeyP256ApiKey::generate();
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "wallets": [{
                        "walletId": "wallet-1",
                        "walletName": "existing-wallet",
                        "exported": false,
                        "imported": false
                    }]
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallet_accounts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "accounts": [{
                        "walletAccountId": "account-1",
                        "organizationId": "org-id",
                        "walletId": "wallet-1",
                        "curve": "CURVE_ED25519",
                        "pathFormat": "PATH_FORMAT_BIP32",
                        "path": "m/44'/501'/0'/0'",
                        "addressFormat": "ADDRESS_FORMAT_COMPRESSED",
                        "address": "ed25519-address",
                        "publicKey": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    }]
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.args([
        "init",
        "--org-id",
        "org-id",
        "--api-public-key",
        &hex::encode(api_key.compressed_public_key()),
        "--api-base-url",
        &server.uri(),
    ])
    .env(
        "TURNKEY_API_PRIVATE_KEY",
        hex::encode(api_key.private_key()),
    )
    .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Found existing Ed25519 wallet account",
        ))
        .stdout(predicate::str::contains("ed25519-address"));

    let stored = std::fs::read_to_string(&config_path).unwrap();
    assert!(stored.contains("signingAddress = \"ed25519-address\""));
    assert!(stored.contains(
        "signingPublicKey = \"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\""
    ));
}

#[tokio::test]
async fn init_creates_wallet_when_none_exist() {
    let server = MockServer::start().await;
    let api_key = TurnkeyP256ApiKey::generate();
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("tk.toml");

    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallets"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "wallets": []
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/create_wallet"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "activity": {
                        "id": "activity-id",
                        "organizationId": "org-id",
                        "fingerprint": "fingerprint",
                        "status": "ACTIVITY_STATUS_COMPLETED",
                        "type": "ACTIVITY_TYPE_CREATE_WALLET",
                        "result": {
                            "createWalletResult": {
                                "walletId": "new-wallet-id",
                                "addresses": ["new-ed25519-address"]
                            }
                        }
                    }
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/public/v1/query/list_wallet_accounts"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "accounts": [{
                        "walletAccountId": "new-account-1",
                        "organizationId": "org-id",
                        "walletId": "new-wallet-id",
                        "curve": "CURVE_ED25519",
                        "pathFormat": "PATH_FORMAT_BIP32",
                        "path": "m/44'/501'/0'/0'",
                        "addressFormat": "ADDRESS_FORMAT_COMPRESSED",
                        "address": "new-ed25519-address",
                        "publicKey": "1111111111111111111111111111111111111111111111111111111111111111"
                    }]
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.args([
        "init",
        "--org-id",
        "org-id",
        "--api-public-key",
        &hex::encode(api_key.compressed_public_key()),
        "--api-base-url",
        &server.uri(),
    ])
    .env(
        "TURNKEY_API_PRIVATE_KEY",
        hex::encode(api_key.private_key()),
    )
    .env("TURNKEY_TK_CONFIG_PATH", &config_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Created new Ed25519 wallet account",
        ))
        .stdout(predicate::str::contains("new-ed25519-address"));

    let stored = std::fs::read_to_string(&config_path).unwrap();
    assert!(stored.contains("signingAddress = \"new-ed25519-address\""));
}
