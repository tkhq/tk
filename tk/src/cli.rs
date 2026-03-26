use crate::commands;
use clap::{Parser, Subcommand};
use turnkey_auth::config::DEFAULT_CONFIG_DIR_DISPLAY;

/// Top-level CLI arguments for the `tk` binary.
#[derive(Debug, Parser)]
#[command(
    version,
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
            Commands::Init(args) => commands::init::run(args).await,
            Commands::Whoami(args) => commands::whoami::run(args).await,
            Commands::Config(args) => commands::config::run(args).await,
            Commands::SshAgent(args) => commands::agent::run(args).await,
            Commands::GitSign(args) => commands::git_sign::run(args).await,
            Commands::PublicKey(args) => commands::public_key::run(args).await,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize Turnkey credentials and wallet configuration.
    Init(commands::init::Args),
    /// Display the authenticated Turnkey identity.
    Whoami(commands::whoami::Args),
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
    /// Manage a background SSH agent over a Unix socket.
    SshAgent(commands::agent::Args),
    /// Sign a payload using the Git SSH signer interface.
    GitSign(commands::git_sign::Args),
    /// Print the configured SSH public key.
    PublicKey(commands::public_key::Args),
}

fn after_help() -> String {
    format!(
        "\
Quick start:
  export TURNKEY_API_PRIVATE_KEY=\"<your-api-private-key>\"
  tk init --org-id <org-id> --api-public-key <api-public-key>
  tk whoami

Environment:
  TURNKEY_ORGANIZATION_ID
  TURNKEY_API_PUBLIC_KEY
  TURNKEY_API_PRIVATE_KEY
  TURNKEY_API_BASE_URL

Config file:
  Set TURNKEY_TK_CONFIG_PATH to override the config file location.
  Otherwise tk uses {DEFAULT_CONFIG_DIR_DISPLAY}/tk.toml.

SSH agent:
  tk ssh-agent start
  export SSH_AUTH_SOCK={DEFAULT_CONFIG_DIR_DISPLAY}/ssh-agent.sock
",
    )
}
