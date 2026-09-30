//! Switches a saved profile to its pending credential once Turnkey knows it.

use anyhow::{Context, Result};
use serde_json::json;

use super::{pending::PendingSession, public_key::CompressedPublicKey};
use crate::{
    auth::{
        Profile, build_turnkey_client, read_key, remove_generated_key, saved_profile,
        set_profile_key, state_dir, whoami,
    },
    errors::InvalidInput,
    operations::OperationOutput,
};

const COMMAND: &str = "session.activate";

pub(super) async fn run(name: String) -> Result<OperationOutput> {
    let Profile {
        organization_id,
        api_base_url,
        api_key_file: _,
    } = saved_profile(&name).await?;
    let state = state_dir()?;
    let Some(pending) = PendingSession::load(&state, &name).await? else {
        return Err(InvalidInput(format!(
            "no pending session request for profile {name}; run tk session request --profile-name {name} first"
        ))
        .into());
    };
    let PendingSession {
        public_key: _,
        key_file,
        ..
    } = pending;

    let key = read_key(&key_file).await?;
    let public_key = CompressedPublicKey::from(&key);
    let client = build_turnkey_client(key, &api_base_url)?;
    let identity = whoami(&client, organization_id)
        .await
        .with_context(|| {
            format!(
                "pending credential {public_key} is not registered yet; have the provisioner run tk session provision --public-key {public_key}, or approve its activity, then retry"
            )
        })?;

    let previous = set_profile_key(&name, key_file.clone()).await?;
    let previous_public_key = read_key(&previous)
        .await
        .ok()
        .map(|key| CompressedPublicKey::from(&key));
    let previous_removed = remove_generated_key(&previous).await;
    PendingSession::remove(&state, &name).await?;

    Ok(OperationOutput::result(
        COMMAND,
        json!({
            "profile": name,
            "publicKey": public_key,
            "keyFile": key_file,
            "previousPublicKey": previous_public_key,
            "previousKeyFile": previous,
            "previousKeyFileRemoved": previous_removed,
            "identity": identity,
        }),
    ))
}
