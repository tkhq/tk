//! Registers an agent's public key as an expiring API key. Runs as the
//! provisioner; re-running after approval reports the registered key instead
//! of minting another.

use anyhow::Result;
use clap::Args;
use serde_json::json;
use turnkey_client::generated::{
    external::data::v1::{ApiKey, Timestamp},
    immutable::{
        activity::v1::{ApiKeyParamsV2, CreateApiKeysIntentV2},
        common::v1::ApiKeyCurve,
    },
    services::coordinator::public::v1::{GetApiKeysRequest, GetApiKeysResponse},
};
use uuid::Uuid;

use super::{
    duration::{ExpiresIn, human_seconds},
    public_key::CompressedPublicKey,
};
use crate::{
    auth::ResolvedAuth,
    errors::{ActivityError, ActivityErrorKind},
    operations::{OperationOutput, query, submit_activity, unix_now},
};

const COMMAND: &str = "session.provision";

#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// User who will own the new expiring API key.
    #[arg(long)]
    user_id: Uuid,
    /// Compressed P256 public key (hex) printed by `tk session request`.
    #[arg(long)]
    public_key: CompressedPublicKey,
    /// Lifetime of the key, for example 7d, 48h, 30m.
    #[arg(long, default_value = "7d")]
    expires_in: ExpiresIn,
    /// Label of the API key; defaults to `session-EXPIRES_IN-UNIX_SECONDS`, for
    /// example session-7d-1789000000.
    #[arg(long)]
    label: Option<String>,
}

pub(super) async fn run(auth: ResolvedAuth, args: ProvisionArgs) -> Result<OperationOutput> {
    let ProvisionArgs {
        user_id,
        public_key,
        expires_in,
        label,
    } = args;
    let existing: GetApiKeysResponse = query(
        "/public/v1/query/get_api_keys",
        &GetApiKeysRequest {
            organization_id: auth.org_id.to_string(),
            user_id: Some(user_id.to_string()),
        },
        &auth,
    )
    .await?;
    if let Some(key) = existing
        .api_keys
        .into_iter()
        .find(|key| public_key.matches(key))
    {
        let ApiKey {
            credential: _,
            api_key_id,
            api_key_name,
            created_at,
            updated_at: _,
            expiration_seconds,
        } = key;
        return Ok(OperationOutput::result(
            COMMAND,
            json!({
                "userId": user_id,
                "expiresIn": expiration_seconds.map(human_seconds),
                "expirationSeconds": expiration_seconds.map(|seconds| seconds.to_string()),
                "publicKey": public_key,
                "apiKeyId": api_key_id,
                "apiKeyName": api_key_name,
                "createdAt": created_at.map(|Timestamp { seconds, nanos: _ }| seconds),
                "alreadyRegistered": true,
            }),
        ));
    }

    let api_key_name = match label {
        Some(label) => label,
        None => format!("session-{expires_in}-{}", unix_now()?.as_secs()),
    };
    let submitted = submit_activity(
        &auth,
        COMMAND,
        "create_api_keys",
        "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        &CreateApiKeysIntentV2 {
            api_keys: vec![ApiKeyParamsV2 {
                api_key_name: api_key_name.clone(),
                public_key: public_key.to_string(),
                curve_type: ApiKeyCurve::P256,
                expiration_seconds: Some(expires_in.seconds().to_string()),
            }],
            user_id: user_id.to_string(),
        },
    )
    .await?;
    let activity = &submitted.data()["activity"];
    let (api_key_id, next_step) = match submitted.pending_activity_id() {
        Some(activity_id) => (
            None,
            Some(format!(
                "approve activity {activity_id} (expiring key for user {user_id}, lifetime {expires_in}), then re-run this command or tk activity wait --id {activity_id}"
            )),
        ),
        None => {
            let api_key_id = activity["result"]["createApiKeysResult"]["apiKeyIds"][0]
                .as_str()
                .ok_or_else(|| {
                    ActivityError::new(
                        ActivityErrorKind::MalformedResponse,
                        "create_api_keys completed without an apiKeyId",
                    )
                })?;
            (Some(api_key_id), None)
        }
    };
    let mut data = json!({
        "userId": user_id,
        "expiresIn": expires_in.to_string(),
        "expirationSeconds": expires_in.seconds().to_string(),
        "publicKey": public_key,
        "apiKeyName": api_key_name,
        "apiKeyId": api_key_id,
        "activity": {
            "id": activity["id"],
            "status": activity["status"],
            "type": activity["type"],
        },
    });
    if let Some(step) = next_step {
        data["nextStep"] = step.into();
    }
    Ok(OperationOutput::result(COMMAND, data))
}
