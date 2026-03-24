use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {}

/// Runs the `tk public-key` subcommand.
pub async fn run(_args: Args) -> anyhow::Result<()> {
    println!("{}", turnkey_auth::public_key::get_public_key_line().await?);
    Ok(())
}
