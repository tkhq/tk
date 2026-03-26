use crate::commands;
use clap::{Parser, Subcommand};

const AFTER_HELP: &str = "\
Environment:
  TURNKEY_ORGANIZATION_ID
  TURNKEY_API_PUBLIC_KEY
  TURNKEY_API_PRIVATE_KEY
  TURNKEY_API_BASE_URL

Config file:
  Set TURNKEY_TK_CONFIG_PATH to override the config file location.
  Otherwise tk uses ~/.config/turnkey/tk.toml.

Quick start:
  TURNKEY_API_PRIVATE_KEY=<priv> tk init --organization-id <org> --api-public-key <pub>
  tk whoami
  tk public-key

SSH agent:
  tk ssh-agent start
  eval $(tk ssh-agent status)
";

#[derive(Debug, Parser)]
#[command(
    version,
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
    /// Initialize tk with Turnkey credentials and wallet setup.
    Init(commands::init::Args),
    /// Display the authenticated Turnkey identity.
    Whoami(commands::whoami::Args),
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
    /// Manage the Turnkey SSH agent.
    SshAgent(commands::agent::Args),
    /// Sign a payload using the Git SSH signer interface.
    GitSign(commands::git_sign::Args),
    /// Print the configured SSH public key.
    PublicKey(commands::public_key::Args),
}
