//! Reports how long a saved profile's credential remains valid.

use anyhow::Result;
use clap::Args;
use serde_json::json;
use turnkey_client::generated::{
    external::data::v1::{ApiKey, Timestamp},
    services::coordinator::public::v1::GetApiKeysRequest,
};

use super::{
    duration::{ExpiresIn, human_seconds},
    public_key::CompressedPublicKey,
};
use crate::{
    auth::{Profile, build_turnkey_client, read_key, saved_profile, whoami},
    errors::{MissingResource, SessionExpiring},
    operations::{OperationOutput, unix_now},
    resources::expires_at_unix_ms,
};

const COMMAND: &str = "session.status";

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Saved profile to inspect.
    #[arg(long = "profile-name")]
    name: String,
    /// Fail with `session_expiring` when less than this remains.
    #[arg(long, default_value = "48h")]
    warn_before: ExpiresIn,
}

pub(super) async fn run(args: StatusArgs) -> Result<OperationOutput> {
    let StatusArgs { name, warn_before } = args;
    let Profile {
        organization_id,
        api_base_url,
        api_key_file,
    } = saved_profile(&name).await?;
    let key = read_key(&api_key_file).await?;
    let public_key = CompressedPublicKey::from(&key);
    let client = build_turnkey_client(key, &api_base_url)?;
    let identity = whoami(&client, organization_id).await?;
    let listed = client
        .get_api_keys(GetApiKeysRequest {
            organization_id: organization_id.to_string(),
            user_id: Some(identity.user_id.clone()),
        })
        .await?;
    let key = listed
        .api_keys
        .into_iter()
        .find(|key| public_key.matches(key))
        .ok_or_else(|| MissingResource::new("api key", public_key.to_string()))?;
    let now_ms = u64::try_from(unix_now()?.as_millis())?;
    let expiry =
        expires_at_unix_ms(&key)?.map(|at_ms| (at_ms, at_ms.saturating_sub(now_ms) / 1000));
    let ApiKey {
        credential: _,
        api_key_id,
        api_key_name,
        created_at,
        updated_at: _,
        expiration_seconds,
    } = key;

    let data = json!({
        "profile": name,
        "userId": identity.user_id,
        "publicKey": public_key,
        "apiKeyId": api_key_id,
        "apiKeyName": api_key_name,
        "createdAt": created_at.map(|Timestamp { seconds, nanos: _ }| seconds),
        "expirationSeconds": expiration_seconds.map(|seconds| seconds.to_string()),
        "expiresAt": expiry.map(|(at_ms, _)| at_ms.to_string()),
        "secondsLeft": expiry.map(|(_, seconds_left)| seconds_left),
        "expiresIn": expiry.map(|(_, seconds_left)| human_seconds(seconds_left)),
        "warnBefore": warn_before.to_string(),
    });
    if let Some((expires_at_ms, seconds_left)) = expiry
        && seconds_left < warn_before.seconds()
    {
        return Err(SessionExpiring {
            profile: name,
            public_key,
            expires_at_unix_ms: expires_at_ms,
            seconds_left,
            warn_before_seconds: warn_before.seconds(),
        }
        .into());
    }
    Ok(OperationOutput::result(COMMAND, data))
}
