use anyhow::{Context, Result};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::{
    ActivityResult, TurnkeyClient,
    generated::{
        GetPrivateKeyRequest, GetPrivateKeyResponse, GetPrivateKeysRequest, GetPrivateKeysResponse,
        external::data::v1::PrivateKey,
        immutable::{
            activity::v1::{
                CreatePrivateKeysIntentV2, CreatePrivateKeysResultV2, PrivateKeyParams,
                PrivateKeyResult,
            },
            common::v1::Curve,
        },
    },
};
use uuid::Uuid;

use crate::{
    errors::{ActivityError, ActivityErrorKind, InvalidInput, MissingResource},
    ssh::registry::PrivateKeyId,
    wire::ssh::Ed25519PublicKey,
};

pub struct NamedPrivateKey {
    pub id: PrivateKeyId,
    pub public_key: Ed25519PublicKey,
    pub created: bool,
}

pub async fn create_private_key(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    organization_id: Uuid,
    name: String,
) -> Result<NamedPrivateKey> {
    let GetPrivateKeysResponse { private_keys } = client
        .get_private_keys(GetPrivateKeysRequest {
            organization_id: organization_id.to_string(),
        })
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| format!("list private keys before creating {name}"))?;
    if let Some(existing) = private_keys
        .into_iter()
        .find(|key| key.private_key_name == name)
    {
        let (id, public_key) = ed25519_public_key(existing)?;
        return Ok(NamedPrivateKey {
            id,
            public_key,
            created: false,
        });
    }
    let ActivityResult {
        result: CreatePrivateKeysResultV2 { private_keys },
        activity_id,
        status: _,
        app_proofs: _,
    } = client
        .create_private_keys(
            organization_id.to_string(),
            client.current_timestamp(),
            CreatePrivateKeysIntentV2 {
                private_keys: vec![PrivateKeyParams {
                    private_key_name: name.clone(),
                    curve: Curve::Ed25519,
                    private_key_tags: Vec::new(),
                    address_formats: Vec::new(),
                }],
            },
        )
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| format!("create private key {name}"))?;
    let id = match <[PrivateKeyResult; 1]>::try_from(private_keys) {
        Ok(
            [
                PrivateKeyResult {
                    private_key_id,
                    addresses: _,
                },
            ],
        ) => PrivateKeyId::from(private_key_id),
        Err(other) => {
            return Err(ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                format!(
                    "create_private_keys activity {activity_id} returned {} private keys",
                    other.len()
                ),
            )
            .into());
        }
    };
    let public_key = get_private_key(client, organization_id, &id).await?;
    Ok(NamedPrivateKey {
        id,
        public_key,
        created: true,
    })
}

pub async fn get_private_key(
    client: &TurnkeyClient<TurnkeyP256ApiKey>,
    organization_id: Uuid,
    requested_id: &PrivateKeyId,
) -> Result<Ed25519PublicKey> {
    let GetPrivateKeyResponse { private_key } = client
        .get_private_key(GetPrivateKeyRequest {
            organization_id: organization_id.to_string(),
            private_key_id: requested_id.to_string(),
        })
        .await
        .map_err(anyhow::Error::new)
        .with_context(|| format!("get private key {requested_id}"))?;
    let private_key =
        private_key.ok_or_else(|| MissingResource::new("private key", requested_id.to_string()))?;
    let (_, public_key) = ed25519_public_key(private_key)?;
    Ok(public_key)
}

fn ed25519_public_key(private_key: PrivateKey) -> Result<(PrivateKeyId, Ed25519PublicKey)> {
    let PrivateKey {
        private_key_id,
        public_key,
        private_key_name: _,
        curve,
        addresses: _,
        private_key_tags: _,
        created_at: _,
        updated_at: _,
        exported: _,
        imported: _,
    } = private_key;
    let id = PrivateKeyId::from(private_key_id);
    if curve != Curve::Ed25519 {
        return Err(InvalidInput(format!(
            "private key {id} has curve {}; tk signs SSH payloads with CURVE_ED25519 keys",
            curve.as_str_name()
        ))
        .into());
    }
    let encoded = public_key
        .trim()
        .strip_prefix("0x")
        .unwrap_or(public_key.trim());
    let bytes = hex::decode(encoded).map_err(|error| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            format!("private key {id} publicKey is not hex"),
        )
        .with_source(error)
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_wrong_length: Vec<u8>| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            format!("private key {id} publicKey is not 32 bytes"),
        )
    })?;
    Ok((id, Ed25519PublicKey::from_bytes(bytes)))
}

// Asserts on the classified error code.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod tests {
    use serde_json::{Value, json};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

    use super::*;
    use crate::{
        auth::{ResolvedAuth, build_turnkey_client},
        errors::{ErrorCode, assert_malformed_response, classify},
    };

    const ORG: &str = "00000000-0000-4000-8000-000000000001";
    const KEY_ID: &str = "3d7b9d7c-2a0e-4b7f-8f8e-5e1f2d3c4b5a";

    fn private_key(curve: &str, public_key: &str) -> Value {
        json!({
            "privateKeyId": KEY_ID,
            "publicKey": public_key,
            "privateKeyName": "ssh",
            "curve": curve,
            "addresses": [],
            "privateKeyTags": [],
            "exported": false,
            "imported": false,
        })
    }

    async fn lookup(response: Value) -> anyhow::Error {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/query/get_private_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let auth = ResolvedAuth::for_tests(ORG, &server.uri(), TurnkeyP256ApiKey::generate());
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url).unwrap();
        get_private_key(
            &client,
            auth.org_id,
            &PrivateKeyId::from(KEY_ID.to_string()),
        )
        .await
        .expect_err("the lookup should fail")
    }

    #[tokio::test]
    async fn a_key_of_another_curve_is_an_invalid_input_naming_the_curve() {
        let error = lookup(json!({"privateKey": private_key("CURVE_SECP256K1", "02ab")})).await;
        assert_eq!(classify(&error).code, ErrorCode::InvalidInput);
        assert_eq!(
            error.to_string(),
            format!(
                "private key {KEY_ID} has curve CURVE_SECP256K1; tk signs SSH payloads with CURVE_ED25519 keys"
            )
        );
    }

    #[tokio::test]
    async fn a_short_public_key_is_a_malformed_response_naming_the_field() {
        let error = lookup(json!({
            "privateKey": private_key("CURVE_ED25519", &"ab".repeat(31)),
        }))
        .await;
        assert_malformed_response(
            &error,
            &[&format!("private key {KEY_ID} publicKey is not 32 bytes")],
        );

        let error = lookup(json!({
            "privateKey": private_key("CURVE_ED25519", "not-hex"),
        }))
        .await;
        assert_malformed_response(
            &error,
            &[
                &format!("private key {KEY_ID} publicKey is not hex"),
                "Odd number of digits",
            ],
        );
    }

    #[tokio::test]
    async fn an_absent_private_key_is_a_missing_resource() {
        let error = lookup(json!({})).await;
        assert_eq!(classify(&error).code, ErrorCode::NotFound);
        assert_eq!(
            error
                .downcast_ref::<MissingResource>()
                .map(ToString::to_string),
            Some(format!("private key not found: {KEY_ID}"))
        );
    }
}
