use anyhow::{Result, anyhow};
use clap::{Args as ClapArgs, Subcommand};
use turnkey_client::generated::immutable::activity::v1 as activity;

/// Top-level arguments for `tk activity`.
#[derive(Debug, ClapArgs)]
#[command(about = "Activity approval and rejection commands.", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Runs the `tk activity` subcommand tree.
pub async fn run(args: Args) -> Result<()> {
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

async fn approve(args: ApproveArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    client
        .approve_activity(
            org_id,
            client.current_timestamp(),
            activity::ApproveActivityIntent {
                fingerprint: args.fingerprint,
            },
        )
        .await
        .map_err(|e| anyhow!("failed to approve activity: {e}"))?;

    println!("Activity approved.");
    Ok(())
}

async fn reject(args: RejectArgs) -> Result<()> {
    let config = turnkey_auth::config::Config::resolve().await?;
    let signer = turnkey_auth::turnkey::TurnkeySigner::new(config)?;
    let client = signer.client();
    let org_id = signer.organization_id().to_string();

    client
        .reject_activity(
            org_id,
            client.current_timestamp(),
            activity::RejectActivityIntent {
                fingerprint: args.fingerprint,
            },
        )
        .await
        .map_err(|e| anyhow!("failed to reject activity: {e}"))?;

    println!("Activity rejected.");
    Ok(())
}
