use clap::Args as ClapArgs;
use turnkey_auth::{config::Config, turnkey::TurnkeySigner};

/// Arguments for the `tk ssh public-key` subcommand.
#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {}

/// Runs the `tk ssh public-key` subcommand.
pub async fn run(_args: Args) -> anyhow::Result<()> {
    let signer = TurnkeySigner::new(Config::resolve().await?)?;
    println!(
        "{}",
        turnkey_ssh::public_key::get_public_key_line(&signer).await?
    );
    Ok(())
}
