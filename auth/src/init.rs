use anyhow::{Context, Result, anyhow};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;
use turnkey_client::generated::immutable::common::v1::{AddressFormat, Curve, PathFormat};
use turnkey_client::generated::{
    CreateWalletIntent, GetWalletAccountsRequest, GetWalletsRequest, WalletAccountParams,
};

use crate::config;

const DEFAULT_API_BASE_URL: &str = "https://api.turnkey.com";
const WALLET_NAME: &str = "tk-default";

/// Result of a successful `tk init` operation.
#[derive(Debug, Clone)]
pub struct InitResult {
    /// The signing address for the resolved Ed25519 account.
    pub signing_address: String,
    /// The hex-encoded Ed25519 public key for the resolved account.
    pub signing_public_key: String,
    /// The organization ID used for the operation.
    pub organization_id: String,
    /// Whether a new wallet was created during init.
    pub created: bool,
}

/// Initializes a Turnkey configuration by finding or creating an Ed25519 wallet account.
#[allow(clippy::too_many_lines)]
pub async fn initialize(
    org_id: &str,
    api_public_key: &str,
    api_private_key: &str,
    api_base_url: Option<&str>,
) -> Result<InitResult> {
    let base_url = api_base_url.unwrap_or(DEFAULT_API_BASE_URL);

    let api_key = TurnkeyP256ApiKey::from_strings(api_private_key, Some(api_public_key))
        .context("failed to load Turnkey API key")?;

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .build()
        .context("failed to build Turnkey client")?;

    // List existing wallets.
    let wallets_response = client
        .get_wallets(GetWalletsRequest {
            organization_id: org_id.to_string(),
        })
        .await
        .context("failed to list wallets")?;

    // Search each wallet for an Ed25519 account.
    for wallet in &wallets_response.wallets {
        let accounts_response = client
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: org_id.to_string(),
                wallet_id: Some(wallet.wallet_id.clone()),
                include_wallet_details: None,
                pagination_options: None,
            })
            .await
            .context("failed to list wallet accounts")?;

        if let Some(account) = accounts_response
            .accounts
            .iter()
            .find(|a| a.curve == Curve::Ed25519)
        {
            let public_key = account
                .public_key
                .as_ref()
                .ok_or_else(|| anyhow!("Ed25519 account missing public key"))?;

            config::save_init_config(
                org_id,
                api_public_key,
                api_private_key,
                &account.address,
                public_key,
                api_base_url,
            )
            .await?;

            return Ok(InitResult {
                signing_address: account.address.clone(),
                signing_public_key: public_key.clone(),
                organization_id: org_id.to_string(),
                created: false,
            });
        }
    }

    // No Ed25519 account found, create a new wallet.
    let create_result = client
        .create_wallet(
            org_id.to_string(),
            client.current_timestamp(),
            CreateWalletIntent {
                wallet_name: WALLET_NAME.to_string(),
                accounts: vec![WalletAccountParams {
                    curve: Curve::Ed25519,
                    path_format: PathFormat::Bip32,
                    path: "m/44'/501'/0'/0'".to_string(),
                    address_format: AddressFormat::Compressed,
                }],
                mnemonic_length: None,
            },
        )
        .await
        .context("failed to create wallet")?;

    let wallet_id = create_result.result.wallet_id;

    // Fetch accounts for the newly created wallet.
    let accounts_response = client
        .get_wallet_accounts(GetWalletAccountsRequest {
            organization_id: org_id.to_string(),
            wallet_id: Some(wallet_id),
            include_wallet_details: None,
            pagination_options: None,
        })
        .await
        .context("failed to list accounts for new wallet")?;

    let account = accounts_response
        .accounts
        .iter()
        .find(|a| a.curve == Curve::Ed25519)
        .ok_or_else(|| anyhow!("newly created wallet has no Ed25519 account"))?;

    let public_key = account
        .public_key
        .as_ref()
        .ok_or_else(|| anyhow!("Ed25519 account missing public key"))?;

    config::save_init_config(
        org_id,
        api_public_key,
        api_private_key,
        &account.address,
        public_key,
        api_base_url,
    )
    .await?;

    Ok(InitResult {
        signing_address: account.address.clone(),
        signing_public_key: public_key.clone(),
        organization_id: org_id.to_string(),
        created: true,
    })
}
