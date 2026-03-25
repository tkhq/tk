use turnkey_auth::turnkey::TurnkeySigner;

use crate::ssh::encode_public_key_line;

/// Fetches the configured Turnkey public key and renders it in OpenSSH format.
pub async fn get_public_key_line(signer: &TurnkeySigner) -> anyhow::Result<String> {
    let public_key = signer.get_public_key().await?;
    encode_public_key_line(&public_key, None)
}
