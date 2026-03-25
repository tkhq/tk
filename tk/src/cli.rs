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
            Commands::Config(args) => commands::config::run(args).await,
            Commands::Ssh(args) => commands::ssh::run(args).await,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
    /// SSH-related commands.
    Ssh(commands::ssh::Args),
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
