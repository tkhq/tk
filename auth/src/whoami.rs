use anyhow::{Context, Result, anyhow};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::GetWhoamiRequest;
use turnkey_client::{TurnkeyClient, TurnkeyClientError};

use crate::config::Config;

/// Authenticated identity information returned by the Turnkey API.
pub struct Identity {
    /// Turnkey organization identifier.
    pub organization_id: String,
    /// Turnkey organization name.
    pub organization_name: String,
    /// Authenticated user identifier.
    pub user_id: String,
    /// Authenticated username.
    pub username: String,
}

/// Fetches the authenticated identity for the current configuration.
pub async fn get_identity(config: &Config) -> Result<Identity> {
    let api_key =
        TurnkeyP256ApiKey::from_strings(&config.api_private_key, Some(&config.api_public_key))
            .map_err(|e| anyhow!("failed to load Turnkey API key: {e}"))?;

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&config.api_base_url)
        .build()
        .context("failed to build Turnkey client")?;

    let response = client
        .get_whoami(GetWhoamiRequest {
            organization_id: config.organization_id.clone(),
        })
        .await
        .map_err(|e: TurnkeyClientError| anyhow!("Turnkey API request failed: {e}"))?;

    Ok(Identity {
        organization_id: response.organization_id,
        organization_name: response.organization_name,
        user_id: response.user_id,
        username: response.username,
    })
}
