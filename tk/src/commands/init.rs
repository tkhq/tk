use clap::Args as ClapArgs;
use turnkey_auth::config;

#[derive(Debug, ClapArgs)]
#[command(
    about = "Initialize tk with Turnkey credentials and wallet setup.",
    long_about = None,
    after_help = "The API private key must be provided via the TURNKEY_API_PRIVATE_KEY \
                  environment variable (not as a CLI flag) to prevent secrets from \
                  appearing in process listings."
)]
pub struct Args {
    /// Turnkey organization identifier.
    #[arg(long, env = "TURNKEY_ORGANIZATION_ID")]
    pub organization_id: String,

    /// Turnkey API public key (hex-encoded P256 compressed public key).
    #[arg(long, env = "TURNKEY_API_PUBLIC_KEY")]
    pub api_public_key: String,

    /// Turnkey API private key (hex-encoded P256 private key).
    /// Accepted only via the `TURNKEY_API_PRIVATE_KEY` environment variable
    /// to avoid leaking secrets in process listings.
    #[arg(skip)]
    pub api_private_key: Option<String>,

    /// Turnkey API base URL override.
    #[arg(long, env = "TURNKEY_API_BASE_URL")]
    pub api_base_url: Option<String>,
}

/// Runs the `tk init` subcommand.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let api_private_key = args
        .api_private_key
        .or_else(|| std::env::var("TURNKEY_API_PRIVATE_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TURNKEY_API_PRIVATE_KEY environment variable is required.\n\
                 Set it before running init to avoid exposing secrets in process listings."
            )
        })?;

    println!("Validating credentials and checking for existing wallets...");

    let result = turnkey_auth::init::run_init(
        &args.organization_id,
        &args.api_public_key,
        &api_private_key,
        args.api_base_url.as_deref(),
    )
    .await?;

    if result.created {
        println!("Created new wallet with Ed25519 account");
    } else {
        println!("Found existing Ed25519 account");
    }
    println!("Signing address: {}", result.signing_address);

    let config_path = config::global_config_path()?;
    println!("Configuration saved to {}", config_path.display());
    println!("\nRun `tk whoami` to verify your setup.");
    Ok(())
}
