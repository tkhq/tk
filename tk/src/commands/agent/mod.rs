mod daemon;

use std::path::PathBuf;

use clap::{Args as ClapArgs, Subcommand};

/// Top-level arguments for `tk ssh-agent`.
#[derive(Debug, ClapArgs)]
#[command(
    about = "Manage a background SSH agent over a Unix socket.",
    long_about = None
)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Runs the `tk ssh-agent` subcommand.
pub async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Start(args) => daemon::start(args).await,
        Command::Stop(args) => daemon::stop(args).await,
        Command::Status(args) => daemon::status(args).await,
        Command::InternalRun(args) => daemon::internal_run(args).await,
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the SSH agent in the background.
    Start(StartArgs),
    /// Stop the background SSH agent.
    Stop(StopArgs),
    /// Report the background SSH agent state.
    Status(StatusArgs),
    #[command(hide = true)]
    InternalRun(InternalRunArgs),
}

/// Arguments for starting the SSH agent.
#[derive(Debug, ClapArgs)]
pub struct StartArgs {
    /// Unix socket path to bind for SSH agent connections.
    #[arg(long, value_name = "path")]
    pub socket: Option<PathBuf>,

    /// PID file path for tracking the background SSH agent.
    #[arg(long, value_name = "path")]
    pub pid_file: Option<PathBuf>,
}

/// Arguments for stopping the SSH agent.
#[derive(Debug, ClapArgs)]
pub struct StopArgs {
    /// Unix socket path bound for SSH agent connections.
    #[arg(long, value_name = "path")]
    pub socket: Option<PathBuf>,

    /// PID file path for tracking the background SSH agent.
    #[arg(long, value_name = "path")]
    pub pid_file: Option<PathBuf>,
}

/// Arguments for checking the SSH agent status.
#[derive(Debug, ClapArgs)]
pub struct StatusArgs {
    /// Unix socket path bound for SSH agent connections.
    #[arg(long, value_name = "path")]
    pub socket: Option<PathBuf>,

    /// PID file path for tracking the background SSH agent.
    #[arg(long, value_name = "path")]
    pub pid_file: Option<PathBuf>,
}

/// Arguments for the internal SSH agent entrypoint.
#[derive(Debug, ClapArgs)]
pub struct InternalRunArgs {
    /// Unix socket path to bind for SSH agent connections.
    #[arg(long, value_name = "path")]
    pub socket: PathBuf,

    /// PID file path for tracking the background SSH agent.
    #[arg(long, value_name = "path", hide = true)]
    pub pid_file: PathBuf,
}
