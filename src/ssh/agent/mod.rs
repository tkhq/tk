//! Background SSH agent lifecycle and registry-backed key serving.

mod daemon;
mod lock;

use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use serde::Serialize;

pub use daemon::is_default_running;

use crate::auth::AuthOptions;
use crate::outcome::Outcome;
use crate::ssh::registry::SshKeyName;

#[derive(Debug, ClapArgs)]
#[command(
    about = "Manage a background SSH agent over a Unix socket.",
    long_about = None
)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

pub async fn run(args: Args, options: &AuthOptions) -> Result<Outcome> {
    match args.command {
        Command::Start(args) => daemon::start(args, options).await,
        Command::Stop(args) => daemon::stop(args).await,
        Command::Status(args) => daemon::status(args).await,
        Command::InternalRun(args) => daemon::internal_run(args, options.clone()).await,
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct AgentRunning {
    pub pid: u32,
    pub socket: String,
    pub keys: Vec<String>,
}

impl Display for AgentRunning {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ssh-agent running with pid {} on {}",
            self.pid, self.socket
        )?;
        for key in &self.keys {
            write!(f, "\n{key}")?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct AgentStopped {}

impl Display for AgentStopped {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("ssh-agent stopped")
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct AgentNotRunning {}

impl Display for AgentNotRunning {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("ssh-agent was not running")
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the SSH agent in the background.
    Start(StartArgs),
    /// Stop the background SSH agent.
    Stop(AgentPathArgs),
    /// Report the background SSH agent state.
    Status(AgentPathArgs),
    #[command(hide = true)]
    InternalRun(InternalRunArgs),
}

#[derive(Debug, ClapArgs)]
struct StartArgs {
    /// Serve only this registered key.
    #[arg(long, value_name = "KEY")]
    key: Vec<SshKeyName>,

    /// Unix socket path for SSH agent connections.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// PID file path of the background SSH agent.
    #[arg(long, value_name = "PATH")]
    pid_file: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
struct AgentPathArgs {
    /// Unix socket path for SSH agent connections.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// PID file path of the background SSH agent.
    #[arg(long, value_name = "PATH")]
    pid_file: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
struct InternalRunArgs {
    /// Serve only this registered key.
    #[arg(long, value_name = "KEY")]
    key: Vec<SshKeyName>,

    /// Unix socket path for SSH agent connections.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,

    /// PID file path of the background SSH agent.
    #[arg(long, value_name = "PATH", hide = true)]
    pid_file: PathBuf,
}
