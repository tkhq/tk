use anyhow::{Result, bail};
use clap::Args as ClapArgs;

use turnkey_auth::config;

/// Arguments for the `tk init` subcommand.
#[derive(Debug, ClapArgs)]
#[command(
    about = "Initialize Turnkey credentials and wallet configuration",
    long_about = None,
    after_help = "\
The API private key must be provided via the TURNKEY_API_PRIVATE_KEY environment \
variable. It is never accepted as a CLI flag to prevent exposure in shell history.

Example:
  export TURNKEY_API_PRIVATE_KEY=\"<your-api-private-key>\"
  tk init --org-id <org-id> --api-public-key <api-public-key>
"
)]
pub struct Args {
    /// Turnkey organization ID.
    #[arg(long)]
    pub org_id: String,

    /// Turnkey API public key.
    #[arg(long)]
    pub api_public_key: String,

    /// Optional API base URL override.
    #[arg(long)]
    pub api_base_url: Option<String>,

    #[arg(skip)]
    pub api_private_key: Option<String>,
}

/// Runs the `tk init` subcommand.
pub async fn run(mut args: Args) -> Result<()> {
    args.api_private_key = std::env::var("TURNKEY_API_PRIVATE_KEY").ok();

    let api_private_key = match &args.api_private_key {
        Some(key) if !key.trim().is_empty() => key.as_str(),
        _ => bail!(
            "TURNKEY_API_PRIVATE_KEY environment variable is required.\n\
             Set it before running tk init:\n\n  \
             export TURNKEY_API_PRIVATE_KEY=\"<your-api-private-key>\""
        ),
    };

    let result = turnkey_auth::init::initialize(
        &args.org_id,
        &args.api_public_key,
        api_private_key,
        args.api_base_url.as_deref(),
    )
    .await?;

    let config_path = config::global_config_path()?;

    if result.created {
        println!("Created new Ed25519 wallet account.");
    } else {
        println!("Found existing Ed25519 wallet account.");
    }
    println!("  Signing address:    {}", result.signing_address);
    println!("  Signing public key: {}", result.signing_public_key);
    println!("  Organization:       {}", result.organization_id);
    println!();
    println!("Config saved to {}", config_path.display());

    Ok(())
}
