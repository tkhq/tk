use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;
use std::fmt::{self, Display, Formatter};

use crate::outcome::Outcome;
use crate::output::StdCtx;

/// Top-level arguments for `tk activity`.
#[derive(Debug, ClapArgs)]
#[command(about = "Activity approval and rejection commands.", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Runs the `tk activity` subcommand tree.
pub async fn run(_ctx: &mut StdCtx, args: Args) -> anyhow::Result<Outcome> {
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

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ActivityApproved {
    pub fingerprint: String,
}

impl Display for ActivityApproved {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Activity approved.")
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ActivityRejected {
    pub fingerprint: String,
}

impl Display for ActivityRejected {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Activity rejected.")
    }
}

async fn signer() -> anyhow::Result<turnkey_auth::turnkey::TurnkeySigner> {
    let config = turnkey_auth::config::Config::resolve().await?;
    turnkey_auth::turnkey::TurnkeySigner::new(config)
}

async fn approve(args: ApproveArgs) -> anyhow::Result<Outcome> {
    signer().await?.approve_activity(&args.fingerprint).await?;
    Ok(Outcome::ActivityApproved(ActivityApproved {
        fingerprint: args.fingerprint,
    }))
}

async fn reject(args: RejectArgs) -> anyhow::Result<Outcome> {
    signer().await?.reject_activity(&args.fingerprint).await?;
    Ok(Outcome::ActivityRejected(ActivityRejected {
        fingerprint: args.fingerprint,
    }))
}
