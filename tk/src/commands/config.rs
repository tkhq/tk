use clap::{Args as ClapArgs, Subcommand};

use turnkey_auth::config::{self, ConfigKey};

#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the resolved value for one config key.
    Get(GetArgs),
    /// Persist a config value to the global config file.
    Set(SetArgs),
    /// Print the resolved effective config.
    List,
}

#[derive(Debug, ClapArgs)]
struct GetArgs {
    key: String,
}

#[derive(Debug, ClapArgs)]
struct SetArgs {
    key: String,
    value: String,
}

/// Runs the `tk config` subcommand.
pub async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Get(args) => {
            let key = ConfigKey::parse(&args.key)?;
            println!("{}", config::get_resolved_config_value(key).await?);
        }
        Command::Set(args) => {
            let key = ConfigKey::parse(&args.key)?;
            if key == ConfigKey::ApiPrivateKey {
                anyhow::bail!(
                    "cannot set turnkey.apiPrivateKey via the command line.\n\
                     Use the TURNKEY_API_PRIVATE_KEY environment variable or `tk init` instead."
                );
            }
            config::set_config_value(key, &args.value).await?;
        }
        Command::List => {
            print!("{}", config::render_config().await?);
        }
    }

    Ok(())
}
