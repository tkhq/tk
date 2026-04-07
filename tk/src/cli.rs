use crate::commands;
use clap::{Parser, Subcommand};
use turnkey_auth::config::DEFAULT_CONFIG_DIR_DISPLAY;

/// Top-level CLI arguments for the `tk` binary.
#[derive(Debug, Parser)]
#[command(
    about = "CLI for Turnkey backed auth workflows",
    long_about = None,
    after_help = after_help()
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    /// Parses CLI arguments and dispatches to the selected subcommand.
    pub async fn run() -> anyhow::Result<()> {
        let args = Self::parse();

        match args.command {
            Commands::Activity(args) => commands::activity::run(args).await,
            Commands::Config(args) => commands::config::run(args).await,
            Commands::Keys(args) => commands::keys::run(args).await,
            Commands::Policies(args) => commands::policies::run(args).await,
            Commands::Ssh(args) => commands::ssh::run(args).await,
            Commands::Users(args) => commands::users::run(args).await,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Activity approval and rejection commands.
    Activity(commands::activity::Args),
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
    /// Private key management commands.
    Keys(commands::keys::Args),
    /// Policy management commands.
    Policies(commands::policies::Args),
    /// SSH related commands.
    Ssh(commands::ssh::Args),
    /// User management commands.
    Users(commands::users::Args),
}

fn after_help() -> String {
    format!(
        "\
Environment:
  TURNKEY_ORGANIZATION_ID
  TURNKEY_API_PUBLIC_KEY
  TURNKEY_API_PRIVATE_KEY
  TURNKEY_PRIVATE_KEY_ID
  TURNKEY_API_BASE_URL

Config file:
  Set TURNKEY_TK_CONFIG_PATH to override the config file location.
  Otherwise tk uses {DEFAULT_CONFIG_DIR_DISPLAY}/tk.toml.

SSH agent:
  tk ssh agent start
  export SSH_AUTH_SOCK={DEFAULT_CONFIG_DIR_DISPLAY}/ssh-agent.sock
",
    )
}
