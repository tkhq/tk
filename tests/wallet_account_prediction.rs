//! Mock-API tests for wallet account path prediction against pages the live API cannot produce on demand.
// Unwraps read mock-server requests and CLI JSON output, which these tests expect to be present and well-formed.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use serde_json::{Value, json};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
const WALLET: &str = "00000000-0000-4000-8000-0000000000aa";

fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in [
        "HOME",
        "TK_PROFILE",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_API_BASE_URL",
    ] {
        cmd.env_remove(name);
    }
    cmd.arg("--message-format=json");
    cmd
}

fn authed(base: &str) -> Command {
    let mut cmd = cli();
    let key = TurnkeyP256ApiKey::generate();
    cmd.env("TURNKEY_ORGANIZATION_ID", ORG)
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(key.compressed_public_key()),
        )
        .env("TURNKEY_API_PRIVATE_KEY", hex::encode(key.private_key()))
        .arg("--api-base-url")
        .arg(base);
    cmd
}

fn record(cmd: &mut Command, code: i32) -> Value {
    let result = cmd.assert().code(code);
    assert!(result.get_output().stderr.is_empty());
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}

async fn mount_activity(server: &MockServer, endpoint: &str, status: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/public/v1/submit/{endpoint}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"activity":{"id":"activity-id","status":status}})),
        )
        .mount(server)
        .await;
}

async fn mount_accounts(server: &MockServer, pages: Vec<Value>) {
    for (index, accounts) in pages.into_iter().enumerate() {
        let mock = Mock::given(method("POST"))
            .and(path("/public/v1/query/get_wallet_accounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accounts": accounts})));
        if index == 0 {
            mock.up_to_n_times(1).mount(server).await;
        } else {
            mock.mount(server).await;
        }
    }
}

fn account(id: usize, format: &str, account_path: &str) -> Value {
    json!({
        "walletAccountId": format!("account-{id}"),
        "organizationId": ORG,
        "walletId": WALLET,
        "curve": "CURVE_SECP256K1",
        "pathFormat": "PATH_FORMAT_BIP32",
        "path": account_path,
        "addressFormat": format,
        "address": format!("0x{id}"),
    })
}

async fn submitted(server: &MockServer, endpoint: &str) -> Value {
    let requests = server.received_requests().await.unwrap();
    let submit_path = format!("/public/v1/submit/{endpoint}");
    let mut bodies = requests
        .iter()
        .filter(|request| request.url.path() == submit_path)
        .map(|request| request.body_json::<Value>().unwrap());
    let body = bodies.next().unwrap();
    assert!(bodies.next().is_none(), "submitted more than once");
    assert_eq!(body["organizationId"], ORG);
    body
}

fn eth_account(account_path: &str) -> Value {
    json!({
        "curve": "CURVE_SECP256K1",
        "pathFormat": "PATH_FORMAT_BIP32",
        "path": account_path,
        "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
        "name": null,
    })
}

#[tokio::test]
async fn account_create_prediction_ignores_address_formats_this_client_does_not_know() {
    let server = MockServer::start().await;
    mount_accounts(
        &server,
        vec![json!([
            account(1, "ADDRESS_FORMAT_ETHEREUM", "m/44'/60'/0'/0/0"),
            account(2, "ADDRESS_FORMAT_FUTURE_CHAIN", "m/44'/60'/1'/0/0"),
        ])],
    )
    .await;
    mount_activity(
        &server,
        "create_wallet_accounts",
        "ACTIVITY_STATUS_COMPLETED",
    )
    .await;
    record(
        authed(&server.uri()).args([
            "wallet",
            "account",
            "create",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ethereum",
        ]),
        0,
    );
    let body = submitted(&server, "create_wallet_accounts").await;
    assert_eq!(
        body["parameters"]["accounts"],
        json!([eth_account("m/44'/60'/1'/0/0")])
    );
}

#[tokio::test]
async fn account_create_prediction_reads_every_page() {
    let server = MockServer::start().await;
    let first_page: Vec<Value> = (0..100)
        .map(|index| {
            account(
                index,
                "ADDRESS_FORMAT_ETHEREUM",
                &format!("m/44'/60'/{index}'/0/0"),
            )
        })
        .collect();
    mount_accounts(
        &server,
        vec![
            Value::Array(first_page),
            json!([account(
                100,
                "ADDRESS_FORMAT_ETHEREUM",
                "m/44'/60'/100'/0/0"
            )]),
        ],
    )
    .await;
    mount_activity(
        &server,
        "create_wallet_accounts",
        "ACTIVITY_STATUS_COMPLETED",
    )
    .await;
    record(
        authed(&server.uri()).args([
            "wallet",
            "account",
            "create",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ethereum",
        ]),
        0,
    );
    let body = submitted(&server, "create_wallet_accounts").await;
    assert_eq!(
        body["parameters"]["accounts"],
        json!([eth_account("m/44'/60'/101'/0/0")])
    );
    let queries = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path().ends_with("get_wallet_accounts"))
        .map(|request| request.body_json::<Value>().unwrap()["paginationOptions"]["after"].clone())
        .collect::<Vec<_>>();
    assert_eq!(queries, [json!(""), json!("account-99")]);
}

#[tokio::test]
async fn account_create_prediction_stops_when_pages_do_not_advance() {
    let server = MockServer::start().await;
    let page: Vec<Value> = (0..100)
        .map(|index| {
            account(
                index,
                "ADDRESS_FORMAT_ETHEREUM",
                &format!("m/44'/60'/{index}'/0/0"),
            )
        })
        .collect();
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_wallet_accounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accounts": page})))
        .mount(&server)
        .await;
    let result = record(
        authed(&server.uri()).args([
            "wallet",
            "account",
            "create",
            "--wallet-id",
            WALLET,
            "--address-format",
            "ethereum",
        ]),
        1,
    );
    assert_eq!(
        result["message"],
        "wallet account pages stopped advancing after account-99"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
}
