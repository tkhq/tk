//! Tests for `tk token` against a mock identity service and API.
// Test helpers may panic.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
const USER: &str = "00000000-0000-4000-8000-000000000002";
const PARENT: &str = "00000000-0000-4000-8000-000000000003";
const RESOURCE: &str = "https://mcp.example.com/mcp";

fn token(server: &MockServer) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in ["HOME", "TK_PROFILE", "TK_IDENTITY_ORIGIN"] {
        cmd.env_remove(name);
    }
    let key = TurnkeyP256ApiKey::generate();
    cmd.env("TURNKEY_ORGANIZATION_ID", ORG)
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(key.compressed_public_key()),
        )
        .env("TURNKEY_API_PRIVATE_KEY", hex::encode(key.private_key()))
        .arg("--message-format=json")
        .args(["token", "--resource", RESOURCE, "--scope", "mcp"])
        .args(["--parent-organization-id", PARENT])
        .arg("--identity-origin")
        .arg(server.uri())
        .arg("--api-base-url")
        .arg(server.uri());
    cmd
}

async fn whoami(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "organizationId": ORG,
            "organizationName": "Agents",
            "userId": USER,
            "username": "agent",
        })))
        .mount(server)
        .await;
}

fn claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn form(request: &Request) -> Vec<(String, String)> {
    let body = String::from_utf8(request.body.clone()).unwrap();
    reqwest::Url::parse(&format!("http://form/?{body}"))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

fn field<'a>(form: &'a [(String, String)], name: &str) -> &'a str {
    &form.iter().find(|(key, _)| key == name).unwrap().1
}

async fn token_requests(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.url.path() == format!("/t/{PARENT}/token"))
        .collect()
}

#[tokio::test]
async fn a_bound_token_retries_with_the_servers_dpop_nonce() {
    let server = MockServer::start().await;
    whoami(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/t/{PARENT}/token")))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("DPoP-Nonce", "nonce-1")
                .set_body_json(json!({"error": "use_dpop_nonce"})),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/t/{PARENT}/token")))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "header.claims.signature",
            "token_type": "DPoP",
            "expires_in": 300,
            "scope": "mcp",
        })))
        .with_priority(2)
        .mount(&server)
        .await;

    let output = token(&server).assert().code(0).get_output().clone();
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["command"], "token");
    assert_eq!(
        record["data"],
        json!({
            "resource": RESOURCE,
            "clientId": format!("urn:turnkey:user:{USER}"),
            "tokenType": "DPoP",
            "accessToken": "header.claims.signature",
            "expiresIn": 300,
            "scope": "mcp",
        })
    );

    let requests = token_requests(&server).await;
    assert_eq!(requests.len(), 2);

    let first = form(&requests[0]);
    let issuer = format!("{}/t/{PARENT}", server.uri());
    assert_eq!(
        field(&first, "client_assertion_type"),
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    assert_eq!(field(&first, "resource"), RESOURCE);
    assert_eq!(field(&first, "scope"), "mcp");
    let assertion = claims(field(&first, "client_assertion"));
    assert_eq!(assertion["iss"], format!("urn:turnkey:user:{USER}"));
    assert_eq!(assertion["sub"], format!("urn:turnkey:user:{USER}"));
    assert_eq!(assertion["aud"], issuer);

    let first_proof = claims(requests[0].headers.get("DPoP").unwrap().to_str().unwrap());
    assert_eq!(first_proof["htu"], format!("{issuer}/token"));
    assert!(first_proof.get("nonce").is_none());

    let second_proof = claims(requests[1].headers.get("DPoP").unwrap().to_str().unwrap());
    assert_eq!(second_proof["nonce"], "nonce-1");
    assert_ne!(second_proof["jti"], first_proof["jti"]);
    assert_eq!(
        field(&form(&requests[1]), "client_assertion"),
        field(&first, "client_assertion"),
        "the retry reuses the assertion"
    );
}

#[tokio::test]
async fn a_bearer_token_sends_no_proof() {
    let server = MockServer::start().await;
    whoami(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/t/{PARENT}/token")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "header.claims.signature",
            "token_type": "Bearer",
            "expires_in": 300,
        })))
        .mount(&server)
        .await;

    token(&server).arg("--bearer").assert().code(0);

    let requests = token_requests(&server).await;
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("DPoP").is_none());
}

#[tokio::test]
async fn a_refused_client_is_unauthorized() {
    let server = MockServer::start().await;
    whoami(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/t/{PARENT}/token")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed.",
        })))
        .mount(&server)
        .await;

    let output = token(&server).assert().code(1).get_output().clone();
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["code"], "unauthorized");
    assert_eq!(token_requests(&server).await.len(), 1, "no retry");
}
