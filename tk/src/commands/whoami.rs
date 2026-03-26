use clap::Args as ClapArgs;
use turnkey_auth::config::Config;

#[derive(Debug, ClapArgs)]
#[command(about = "Display the authenticated Turnkey identity.", long_about = None)]
pub struct Args {}

/// Runs the `tk whoami` subcommand.
pub async fn run(_args: Args) -> anyhow::Result<()> {
    let config = Config::resolve()
        .await
        .map_err(|e| anyhow::anyhow!("{e}\n\nRun `tk init` to set up your credentials."))?;

    let identity = turnkey_auth::whoami::get_identity(&config).await?;

    println!(
        "Organization:  {} ({})",
        identity.organization_name, identity.organization_id
    );
    println!(
        "User:          {} ({})",
        identity.username, identity.user_id
    );
    Ok(())
}
