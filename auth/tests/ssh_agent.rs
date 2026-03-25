use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::config::Config;
use turnkey_auth::turnkey::TurnkeySigner;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn turnkey_signer_signs_raw_payloads_for_ssh_use_cases() {
    let server = MockServer::start().await;
    let payload = b"ssh-agent-challenge";
    let signature = [0x55; 64];

    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header_exists("X-Stamp"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "activity": {
                        "id": "activity-id",
                        "organizationId": "org-id",
                        "fingerprint": "fingerprint",
                        "status": "ACTIVITY_STATUS_COMPLETED",
                        "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                        "result": {
                            "signRawPayloadResult": {
                                "r": hex::encode(&signature[..32]),
                                "s": hex::encode(&signature[32..]),
                                "v": "00"
                            }
                        }
                    }
                }))
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    let api_key = TurnkeyP256ApiKey::generate();
    let signer = TurnkeySigner::new(Config {
        organization_id: "org-id".to_string(),
        api_public_key: hex::encode(api_key.compressed_public_key()),
        api_private_key: hex::encode(api_key.private_key()),
        private_key_id: "pk-id".to_string(),
        api_base_url: server.uri(),
    })
    .unwrap();

    let result = signer.sign_ed25519(payload).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert_eq!(body["type"], "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2");
    assert_eq!(body["organizationId"], "org-id");
    assert_eq!(body["parameters"]["signWith"], "pk-id");
    assert_eq!(body["parameters"]["payload"], hex::encode(payload));
    assert_eq!(
        body["parameters"]["encoding"],
        "PAYLOAD_ENCODING_HEXADECIMAL"
    );
    assert_eq!(
        body["parameters"]["hashFunction"],
        "HASH_FUNCTION_NOT_APPLICABLE"
    );
    assert_eq!(result, signature.to_vec());
}
