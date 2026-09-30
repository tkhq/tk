//! Generates a credential for a saved profile and records it as pending.

use anyhow::Result;
use serde_json::json;
use tokio::fs;
use tracing::debug;
use turnkey_client::generated::GetWhoamiResponse;

use super::pending::PendingSession;
use crate::{
    auth::{
        Profile, SecureCreateError, build_turnkey_client, read_key, remove_generated_key,
        saved_profile, state_dir, whoami,
    },
    errors::{InvalidInput, is_unauthorized},
    keygen::{GeneratedApiKey, generate},
    operations::OperationOutput,
};

const COMMAND: &str = "session.request";

pub(super) async fn run(name: String, replace: bool) -> Result<OperationOutput> {
    let profile = saved_profile(&name).await?;
    let user_id = current_user_id(&profile).await?;
    let state = state_dir()?;

    if let Some(pending) = PendingSession::load(&state, &name).await? {
        if !replace {
            return Err(InvalidInput(format!(
                "a session request for profile {name} is already pending (public key {}); run tk session activate --profile-name {name}, or pass --replace to start over",
                pending.public_key
            ))
            .into());
        }
        remove_generated_key(&pending.key_file).await;
        PendingSession::remove(&state, &name).await?;
    }

    let GeneratedApiKey {
        public_key,
        path: key_file,
    } = generate(None).await?;
    let pending = PendingSession {
        version: 1,
        public_key,
        key_file,
    };
    if let Err(error) = pending.create(&state, &name).await {
        let _ = fs::remove_file(&pending.key_file).await;
        return Err(match error.downcast_ref::<SecureCreateError>() {
            Some(SecureCreateError::Exists) => InvalidInput(format!(
                "a session request for profile {name} is already pending; run tk session activate --profile-name {name}, or pass --replace to start over"
            ))
            .into(),
            Some(SecureCreateError::Io(_)) | None => error,
        });
    }

    let organization_id = profile.organization_id;
    let PendingSession {
        version: _,
        public_key,
        key_file,
    } = pending;
    let user_hint = user_id.as_deref().unwrap_or("<USER_ID>");
    Ok(OperationOutput::result(
        COMMAND,
        json!({
            "profile": name,
            "organizationId": organization_id,
            "userId": user_id,
            "publicKey": public_key,
            "curve": "p256",
            "keyFile": key_file,
            "nextStep": format!(
                "give the public key and user id to the provisioner: tk session provision --user-id {user_hint} --public-key {public_key} --expires-in 7d; then run tk session activate --profile-name {name} here"
            ),
        }),
    ))
}

async fn current_user_id(profile: &Profile) -> Result<Option<String>> {
    let Profile {
        organization_id,
        api_base_url,
        api_key_file,
    } = profile;
    let client = build_turnkey_client(read_key(api_key_file).await?, api_base_url)?;
    match whoami(&client, *organization_id).await {
        Ok(GetWhoamiResponse { user_id, .. }) => Ok(Some(user_id)),
        Err(error) if is_unauthorized(&error) => {
            debug!(%error, "current credential did not identify the user");
            Ok(None)
        }
        Err(error) => Err(error.context("identify the profile's current user")),
    }
}
