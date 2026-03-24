use crate::commands;
use clap::{Parser, Subcommand};

const AFTER_HELP: &str = "\
Environment:
  TURNKEY_ORGANIZATION_ID
  TURNKEY_API_PUBLIC_KEY
  TURNKEY_API_PRIVATE_KEY
  TURNKEY_PRIVATE_KEY_ID
  TURNKEY_API_BASE_URL

Config file:
  Set TURNKEY_AUTH_CONFIG_PATH to override the config file location.
  Otherwise tk uses ~/.config/turnkey/auth.toml.
";

#[derive(Debug, Parser)]
#[command(
    about = "CLI for Turnkey backed auth workflows",
    long_about = None,
    after_help = AFTER_HELP
)]
/// Top-level CLI arguments for the `tk` binary.
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    /// Parses CLI arguments and dispatches to the selected subcommand.
    pub async fn run() -> anyhow::Result<()> {
        let args = Self::parse();

        match args.command {
            Commands::Config(args) => commands::config::run(args).await,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
}
