use clap::{Args as ClapArgs, Subcommand};

use crate::commands::{agent, git_sign, public_key};
use crate::outcome::Outcome;
use crate::output::StdCtx;

/// Top-level arguments for `tk ssh`.
#[derive(Debug, ClapArgs)]
#[command(about = "SSH related commands.", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Runs the `tk ssh` subcommand tree.
pub async fn run(ctx: &mut StdCtx, args: Args) -> anyhow::Result<Outcome> {
    match args.command {
        Command::Agent(args) => agent::run(ctx, args).await,
        Command::GitSign(args) => git_sign::run(ctx, args).await,
        Command::PublicKey(args) => public_key::run(ctx, args).await,
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage a background SSH agent over a Unix socket.
    Agent(agent::Args),
    /// Sign a payload using the Git SSH signer interface.
    GitSign(git_sign::Args),
    /// Print the configured SSH public key.
    PublicKey(public_key::Args),
}
