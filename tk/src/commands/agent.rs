use std::path::PathBuf;

use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
#[command(about = "Run a foreground SSH agent over a Unix socket.", long_about = None)]
pub struct Args {
    /// Unix socket path to bind for SSH agent connections.
    #[arg(long, value_name = "path")]
    pub socket: PathBuf,
}

/// Runs the `tk ssh-agent` subcommand.
pub async fn run(args: Args) -> anyhow::Result<()> {
    turnkey_auth::ssh::agent::run(args.socket).await
}
