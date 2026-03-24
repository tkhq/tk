use anyhow::anyhow;

use crate::config::Config;
use crate::ssh;
use crate::turnkey::TurnkeySigner;

/// Runs a Git SSH signer invocation and writes the detached signature file.
pub async fn run_git_sign(ssh_keygen_args: &[String]) -> anyhow::Result<()> {
    let invocation = ssh::git::GitSignInvocation::parse(ssh_keygen_args)?;
    let signer = TurnkeySigner::new(Config::resolve().await?)?;
    let payload = tokio::fs::read(&invocation.payload_path).await?;
    let public_key = tokio::fs::read_to_string(&invocation.public_key_path).await?;
    let parsed_public_key = ssh::parse_public_key_line(&public_key)?;
    let configured_public_key = signer.get_public_key().await?;
    if parsed_public_key.public_key != configured_public_key {
        return Err(anyhow!(
            "requested SSH public key does not match the configured Turnkey key"
        ));
    }
    let signed_data = ssh::build_signed_data("git", &payload);
    let signature = signer.sign_ed25519(&signed_data).await?;
    let armored = ssh::encode_armored_signature(
        &parsed_public_key.public_key_blob,
        "git",
        ssh::DEFAULT_HASH_ALGORITHM,
        &signature,
    )?;

    let signature_path = invocation.signature_path();
    tokio::fs::write(&signature_path, armored).await?;
    Ok(())
}
