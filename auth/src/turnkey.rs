use anyhow::{Context, Result, anyhow};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::immutable::common::v1::HashFunction;
use turnkey_client::generated::immutable::common::v1::PayloadEncoding;
use turnkey_client::generated::{GetActivityRequest, GetPrivateKeyRequest, SignRawPayloadIntentV2};
use turnkey_client::{TurnkeyClient, TurnkeyClientError};

use crate::config::Config;

/// Turnkey-backed signer for fetching public keys and producing Ed25519 signatures.
pub struct TurnkeySigner {
    client: TurnkeyClient<TurnkeyP256ApiKey>,
    config: Config,
}

impl TurnkeySigner {
    /// Builds a signer from an already resolved auth config.
    pub fn new(config: Config) -> Result<Self> {
        let api_key =
            TurnkeyP256ApiKey::from_strings(&config.api_private_key, Some(&config.api_public_key))
                .context("failed to load Turnkey API key")?;

        let client = TurnkeyClient::builder()
            .api_key(api_key)
            .base_url(&config.api_base_url)
            .build()
            .context("failed to build Turnkey client")?;

        Ok(Self { client, config })
    }

    /// Returns a reference to the underlying Turnkey API client.
    pub fn client(&self) -> &TurnkeyClient<TurnkeyP256ApiKey> {
        &self.client
    }

    /// Returns the organization ID from the resolved config.
    pub fn organization_id(&self) -> &str {
        &self.config.organization_id
    }

    /// Fetches the configured Ed25519 public key bytes from Turnkey.
    pub async fn get_public_key(&self) -> Result<Vec<u8>> {
        let private_key_id = self.required_private_key_id()?;
        let response = self
            .client
            .get_private_key(GetPrivateKeyRequest {
                organization_id: self.config.organization_id.clone(),
                private_key_id: private_key_id.to_string(),
            })
            .await
            .map_err(map_turnkey_error)?;

        let private_key = response
            .private_key
            .ok_or_else(|| anyhow!("Turnkey did not return a private key object"))?;

        decode_public_key(&private_key.public_key)
    }

    /// Signs a raw Ed25519 payload through Turnkey and returns the 64-byte signature.
    pub async fn sign_raw_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let private_key_id = self.required_private_key_id()?;
        match self
            .client
            .sign_raw_payload(
                self.config.organization_id.clone(),
                self.client.current_timestamp(),
                SignRawPayloadIntentV2 {
                    sign_with: private_key_id.to_string(),
                    payload: hex::encode(payload),
                    encoding: PayloadEncoding::Hexadecimal,
                    hash_function: HashFunction::NotApplicable,
                },
            )
            .await
        {
            Ok(response) => {
                decode_signature_parts(&response.result.r, &response.result.s, &response.result.v)
            }
            Err(TurnkeyClientError::ActivityRequiresApproval(activity_id)) => {
                Err(self.consensus_required_error(&activity_id).await)
            }
            Err(other) => Err(map_turnkey_error(other)),
        }
    }

    /// Builds a consensus-needed error and enriches it with the activity fingerprint when available.
    async fn consensus_required_error(&self, activity_id: &str) -> anyhow::Error {
        match self.get_activity_fingerprint(activity_id).await {
            Ok(fingerprint) => anyhow!(
                "signing requires consensus approval (fingerprint: {fingerprint}, activity id: {activity_id})"
            ),
            Err(_) => anyhow!("signing requires consensus approval (activity id: {activity_id})"),
        }
    }

    async fn get_activity_fingerprint(&self, activity_id: &str) -> Result<String> {
        let response = self
            .client
            .get_activity(GetActivityRequest {
                organization_id: self.config.organization_id.clone(),
                activity_id: activity_id.to_string(),
            })
            .await
            .map_err(map_turnkey_error)?;

        let activity = response
            .activity
            .ok_or_else(|| anyhow!("Turnkey did not return an activity object"))?;

        if activity.fingerprint.is_empty() {
            return Err(anyhow!("Turnkey activity fingerprint was empty"));
        }

        Ok(activity.fingerprint)
    }

    fn required_private_key_id(&self) -> Result<&str> {
        if self.config.private_key_id.is_empty() {
            return Err(anyhow!("missing required config value: turnkey.privateKeyId"));
        }

        Ok(&self.config.private_key_id)
    }
}

fn map_turnkey_error(error: TurnkeyClientError) -> anyhow::Error {
    anyhow!("Turnkey API request failed: {error}")
}

fn decode_public_key(encoded: &str) -> Result<Vec<u8>> {
    let trimmed = encoded.trim().trim_start_matches("0x");
    hex::decode(trimmed).map_err(|_| anyhow!("expected hex-encoded Turnkey public key"))
}

fn decode_signature_parts(r: &str, s: &str, v: &str) -> Result<Vec<u8>> {
    let r = decode_hex(r).context("failed to decode Turnkey signature field r")?;
    let s = decode_hex(s).context("failed to decode Turnkey signature field s")?;
    let v = decode_hex(v).context("failed to decode Turnkey signature field v")?;

    if r.len() == 32 && s.len() == 32 && v.len() == 1 {
        return Ok([r, s].concat());
    }

    Err(anyhow!(
        "unsupported Ed25519 signature layout from Turnkey: r={} bytes, s={} bytes, v={} bytes",
        r.len(),
        s.len(),
        v.len()
    ))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("expected non-empty hex value"));
    }

    let trimmed = trimmed.trim_start_matches("0x");
    hex::decode(trimmed).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{TurnkeySigner, decode_public_key, decode_signature_parts};
    use crate::config::Config;
    use turnkey_api_key_stamper::TurnkeyP256ApiKey;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_signer(server: &MockServer) -> TurnkeySigner {
        let api_key = TurnkeyP256ApiKey::generate();
        TurnkeySigner::new(Config {
            organization_id: "org-id".to_string(),
            api_public_key: hex::encode(api_key.compressed_public_key()),
            api_private_key: hex::encode(api_key.private_key()),
            private_key_id: "pk-id".to_string(),
            api_base_url: server.uri(),
        })
        .expect("signer should build")
    }

    #[test]
    fn decode_public_key_rejects_base64_input() {
        let error = decode_public_key("ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=")
            .expect_err("base64 public keys should be rejected");

        assert_eq!(error.to_string(), "expected hex-encoded Turnkey public key");
    }

    #[test]
    fn decode_signature_parts_rejects_empty_v() {
        let r = "11".repeat(32);
        let s = "22".repeat(32);
        let error = decode_signature_parts(&r, &s, "").expect_err("empty v should be rejected");

        assert_eq!(
            error.to_string(),
            "failed to decode Turnkey signature field v"
        );
    }

    #[tokio::test]
    async fn sign_returns_signature_on_immediate_success() {
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

        let signer = test_signer(&server);
        let result = signer
            .sign_raw_payload(payload)
            .await
            .expect("raw payload should sign");

        assert_eq!(result, signature.to_vec());

        let requests = server
            .received_requests()
            .await
            .expect("request recording should be enabled");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = requests[0]
            .body_json()
            .expect("request body should be valid JSON");
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
    }

    #[tokio::test]
    async fn sign_returns_error_when_consensus_needed() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "consensus-activity-id",
                    "organizationId": "org-id",
                    "fingerprint": "consensus-fingerprint",
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_activity"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "consensus-activity-id",
                    "organizationId": "org-id",
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                    "intent": null,
                    "result": null,
                    "votes": [],
                    "appProofs": [],
                    "fingerprint": "consensus-fingerprint",
                    "canApprove": false,
                    "canReject": true,
                    "createdAt": null,
                    "updatedAt": null,
                    "failure": null
                }
            })))
            .mount(&server)
            .await;

        let signer = test_signer(&server);
        let error = signer
            .sign_raw_payload(b"test-payload")
            .await
            .expect_err("sign should fail when consensus needed");

        let message = error.to_string();
        assert!(
            message.contains("consensus")
                && message.contains("consensus-fingerprint")
                && message.contains("consensus-activity-id"),
            "error should mention consensus and contain both activity fingerprint and id: {message}"
        );
    }

    #[tokio::test]
    async fn sign_falls_back_to_activity_id_when_fingerprint_lookup_fails() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "consensus-activity-id",
                    "organizationId": "org-id",
                    "fingerprint": "consensus-fingerprint",
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_activity"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let signer = test_signer(&server);
        let error = signer
            .sign_raw_payload(b"test-payload")
            .await
            .expect_err("sign should fail when consensus needed");

        assert_eq!(
            error.to_string(),
            "signing requires consensus approval (activity id: consensus-activity-id)"
        );
    }

    #[tokio::test]
    async fn sign_requires_private_key_id() {
        let server = MockServer::start().await;
        let api_key = TurnkeyP256ApiKey::generate();
        let signer = TurnkeySigner::new(Config {
            organization_id: "org-id".to_string(),
            api_public_key: hex::encode(api_key.compressed_public_key()),
            api_private_key: hex::encode(api_key.private_key()),
            private_key_id: String::new(),
            api_base_url: server.uri(),
        })
        .expect("signer should build");

        let error = signer
            .sign_raw_payload(b"test-payload")
            .await
            .expect_err("sign should require a private key id");

        assert_eq!(
            error.to_string(),
            "missing required config value: turnkey.privateKeyId"
        );
    }

}
