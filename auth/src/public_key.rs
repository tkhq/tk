use crate::config::Config;
use crate::ssh::encode_public_key_line;
use crate::turnkey::TurnkeySigner;

/// Returns the configured Turnkey public key rendered in OpenSSH format.
pub async fn get_public_key_line() -> anyhow::Result<String> {
    let signer = TurnkeySigner::new(Config::resolve().await?)?;
    let public_key = signer.get_public_key()?;
    encode_public_key_line(&public_key, None)
}
