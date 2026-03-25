use clap::Args as ClapArgs;
use turnkey_auth::{config::Config, turnkey::TurnkeySigner};

/// Arguments for the `tk ssh git-sign` subcommand or direct SSH signer invocation.
#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub ssh_keygen_args: Vec<String>,
}

/// Runs the `tk ssh git-sign` subcommand or direct SSH signer invocation.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let signer = TurnkeySigner::new(Config::resolve().await?)?;
    turnkey_ssh::git_sign::run_git_sign(&signer, &args.ssh_keygen_args).await
}
