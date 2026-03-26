use anyhow::{Context, Result};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;
use turnkey_client::generated::GetWhoamiRequest;

use crate::config::Config;

/// Authenticated Turnkey identity information.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The organization ID.
    pub organization_id: String,
    /// The organization name.
    pub organization_name: String,
    /// The authenticated user ID.
    pub user_id: String,
    /// The authenticated username.
    pub username: String,
}

/// Fetches the authenticated identity from Turnkey.
pub async fn get_identity(config: &Config) -> Result<Identity> {
    let api_key =
        TurnkeyP256ApiKey::from_strings(&config.api_private_key, Some(&config.api_public_key))
            .context("failed to load Turnkey API key")?;

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
        .context("failed to fetch identity from Turnkey")?;

    Ok(Identity {
        organization_id: response.organization_id,
        organization_name: response.organization_name,
        user_id: response.user_id,
        username: response.username,
    })
}
