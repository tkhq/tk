use anyhow::{Context, Result, anyhow};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::immutable::common::v1::{AddressFormat, Curve, PathFormat};
use turnkey_client::generated::{
    CreateWalletIntent, GetWalletAccountsRequest, GetWalletsRequest, WalletAccountParams,
};
use turnkey_client::{TurnkeyClient, TurnkeyClientError};

use crate::config;

/// Result of the init process.
pub struct InitResult {
    /// The wallet account signing address.
    pub signing_address: String,
    /// The hex-encoded Ed25519 public key.
    pub signing_public_key: String,
    /// The organization identifier used.
    pub organization_id: String,
    /// Whether a new wallet was created.
    pub created: bool,
}

/// Runs the interactive initialization flow.
///
/// Validates the provided credentials, searches existing wallets for one
/// with an Ed25519 account, creates a new wallet if none found,
/// and persists the resolved signing address and public key to the config.
pub async fn run_init(
    organization_id: &str,
    api_public_key: &str,
    api_private_key: &str,
    api_base_url: Option<&str>,
) -> Result<InitResult> {
    let base_url = api_base_url.unwrap_or("https://api.turnkey.com");

    let api_key = TurnkeyP256ApiKey::from_strings(api_private_key, Some(api_public_key))
        .context("invalid API key pair")?;

    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .build()
        .context("failed to build Turnkey client")?;

    // Search existing wallets for one with an Ed25519 account.
    let wallets = client
        .get_wallets(GetWalletsRequest {
            organization_id: organization_id.to_string(),
        })
        .await
        .map_err(|e: TurnkeyClientError| anyhow!("failed to list wallets: {e}"))?;

    let mut found_account: Option<(String, String)> = None; // (address, public_key)

    for wallet in &wallets.wallets {
        let accounts = client
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: organization_id.to_string(),
                wallet_id: Some(wallet.wallet_id.clone()),
                include_wallet_details: None,
                pagination_options: None,
            })
            .await
            .map_err(|e: TurnkeyClientError| anyhow!("failed to list wallet accounts: {e}"))?;

        if let Some(account) = accounts.accounts.iter().find(|a| a.curve == Curve::Ed25519) {
            let pk = account
                .public_key
                .as_ref()
                .ok_or_else(|| anyhow!("Ed25519 wallet account missing public key"))?;
            found_account = Some((account.address.clone(), pk.clone()));
            break;
        }
    }

    let (signing_address, signing_public_key, created) = match found_account {
        Some((addr, pk)) => (addr, pk, false),
        None => {
            let result = client
                .create_wallet(
                    organization_id.to_string(),
                    client.current_timestamp(),
                    CreateWalletIntent {
                        wallet_name: "tk-default".to_string(),
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
                .map_err(|e: TurnkeyClientError| anyhow!("failed to create wallet: {e}"))?;

            // Fetch the newly created account to get its public key and address.
            let wallet_id = &result.result.wallet_id;
            let accounts = client
                .get_wallet_accounts(GetWalletAccountsRequest {
                    organization_id: organization_id.to_string(),
                    wallet_id: Some(wallet_id.clone()),
                    include_wallet_details: None,
                    pagination_options: None,
                })
                .await
                .map_err(|e: TurnkeyClientError| {
                    anyhow!("failed to list new wallet accounts: {e}")
                })?;

            let account = accounts
                .accounts
                .iter()
                .find(|a| a.curve == Curve::Ed25519)
                .ok_or_else(|| anyhow!("newly created wallet has no Ed25519 account"))?;

            let pk = account
                .public_key
                .as_ref()
                .ok_or_else(|| anyhow!("newly created Ed25519 account missing public key"))?;

            (account.address.clone(), pk.clone(), true)
        }
    };

    config::save_init_config(
        organization_id,
        api_public_key,
        api_private_key,
        &signing_address,
        &signing_public_key,
        api_base_url,
    )
    .await?;

    Ok(InitResult {
        signing_address,
        signing_public_key,
        organization_id: organization_id.to_string(),
        created,
    })
}
