use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub ssh_keygen_args: Vec<String>,
}

/// Runs the `tk git-sign` subcommand or direct SSH signer invocation.
pub async fn run(args: Args) -> anyhow::Result<()> {
    turnkey_auth::git_sign::run_git_sign(&args.ssh_keygen_args).await
}
