use clap::{Args as ClapArgs, Subcommand};

/// Top-level arguments for `tk activity`.
#[derive(Debug, ClapArgs)]
#[command(about = "Activity approval and rejection commands.", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Runs the `tk activity` subcommand tree.
pub async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Approve(args) => approve(args).await,
        Command::Reject(args) => reject(args).await,
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Approve a pending activity that requires consensus.
    Approve(ApproveArgs),
    /// Reject a pending activity that requires consensus.
    Reject(RejectArgs),
}

/// Arguments for `tk activity approve`.
#[derive(Debug, ClapArgs)]
pub struct ApproveArgs {
    /// The fingerprint of the activity to approve.
    pub fingerprint: String,
}

/// Arguments for `tk activity reject`.
#[derive(Debug, ClapArgs)]
pub struct RejectArgs {
    /// The fingerprint of the activity to reject.
    pub fingerprint: String,
}

async fn approve(args: ApproveArgs) -> anyhow::Result<()> {
    let config = turnkey_auth::config::Config::resolve_api_credentials().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    signer.approve_activity(&args.fingerprint).await?;
    println!("Activity approved.");
    Ok(())
}

async fn reject(args: RejectArgs) -> anyhow::Result<()> {
    let config = turnkey_auth::config::Config::resolve_api_credentials().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    signer.reject_activity(&args.fingerprint).await?;
    println!("Activity rejected.");
    Ok(())
}
