use clap::Args as ClapArgs;

use crate::outcome::{MachineOnly, Outcome};
use crate::output::StdCtx;

/// Arguments for the `tk ssh git-sign` subcommand.
#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub ssh_keygen_args: Vec<String>,
}

/// Runs the `tk ssh git-sign` subcommand. Its terminal outcome is
/// machine-only: the signature artifact itself follows ssh-keygen's file
/// contract, not tk's output protocol.
pub async fn run(_ctx: &mut StdCtx, args: Args) -> anyhow::Result<Outcome> {
    turnkey_auth::git_sign::run_git_sign(&args.ssh_keygen_args).await?;
    Ok(Outcome::GitSignCompleted(MachineOnly {}))
}
