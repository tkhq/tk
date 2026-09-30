//! Background SSH agent lifecycle and registry-backed key serving.

mod allowed_hosts;
mod daemon;
mod lock;

use std::{
    fmt::{self, Display, Formatter},
    path::PathBuf,
};

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
pub use daemon::is_default_running;
use serde::{Deserialize, Serialize};

use crate::{auth::AuthOptions, outcome::Outcome, socket::SocketMode, ssh::registry::SshKeyName};

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
#[serde(rename_all = "camelCase")]
pub struct AgentRunning {
    pub pid: u32,
    pub socket: String,
    pub socket_mode: SocketMode,
    pub keys: Vec<String>,
    #[serde(flatten)]
    pub constraints: Option<DestinationConstraints>,
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "camelCase")]
pub struct DestinationConstraints {
    pub allowed_hosts: Vec<String>,
    pub allowed_namespaces: Vec<String>,
}

#[cfg(test)]
impl Default for AgentRunning {
    fn default() -> Self {
        Self {
            pid: 0,
            socket: String::new(),
            socket_mode: "600".parse().unwrap(),
            keys: Vec::new(),
            constraints: None,
        }
    }
}

impl Display for AgentRunning {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ssh-agent running with pid {} on {}",
            self.pid, self.socket
        )?;
        if let Some(DestinationConstraints {
            allowed_hosts,
            allowed_namespaces,
        }) = &self.constraints
        {
            write!(f, "\nallowed hosts: {}", allowed_hosts.join(", "))?;
            if !allowed_namespaces.is_empty() {
                write!(f, "\nallowed namespaces: {}", allowed_namespaces.join(", "))?;
            }
        }
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
    #[command(flatten)]
    serving: ServingArgs,

    /// Unix socket path for SSH agent connections.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// PID file of the background SSH agent; defaults to `SOCKET.pid` when `--socket` is given.
    #[arg(long, value_name = "PATH")]
    pid_file: Option<PathBuf>,

    /// Octal permissions for the socket.
    ///
    /// Access to the socket grants signing authority.
    #[arg(long, default_value = "600")]
    socket_mode: SocketMode,
}

#[derive(Debug, ClapArgs)]
struct ServingArgs {
    /// Serve only this registered key.
    #[arg(long, value_name = "KEY")]
    key: Vec<SshKeyName>,

    /// Sign SSH connections only for host keys in this `known_hosts` file.
    ///
    /// Refuses SSH connection signatures from clients that do not bind the
    /// connection with `session-bind@openssh.com` (OpenSSH 8.9+).
    #[arg(long, value_name = "PATH")]
    allowed_hosts_file: Option<PathBuf>,

    /// Also sign `ssh-keygen -Y sign` requests in this `SSHSIG` namespace.
    ///
    /// Signs these on any connection without a session-bind, so anything that
    /// can reach this socket can sign. Share it only with the one boundary that
    /// should, such as another OS user or one container or VM through a mount,
    /// and never forward it over SSH or relay it beyond that boundary.
    #[arg(long, value_name = "NAMESPACE", requires = "allowed_hosts_file")]
    allow_namespace: Vec<String>,
}

#[derive(Debug, ClapArgs)]
struct AgentPathArgs {
    /// Unix socket path for SSH agent connections.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// PID file of the background SSH agent; defaults to `SOCKET.pid` when `--socket` is given.
    #[arg(long, value_name = "PATH")]
    pid_file: Option<PathBuf>,
}

#[derive(Debug, ClapArgs)]
struct InternalRunArgs {
    #[command(flatten)]
    serving: ServingArgs,

    /// Unix socket path for SSH agent connections.
    #[arg(long, value_name = "PATH")]
    socket: PathBuf,

    /// PID file path of the background SSH agent.
    #[arg(long, value_name = "PATH", hide = true)]
    pid_file: PathBuf,

    /// Octal permissions for the socket.
    #[arg(long)]
    socket_mode: SocketMode,
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::*;

    #[derive(Debug, Parser)]
    struct AgentParser {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn start_rejects_invalid_socket_modes_during_cli_parsing() {
        for value in ["999", "abc"] {
            let error = AgentParser::try_parse_from(["agent", "start", "--socket-mode", value])
                .unwrap_err();

            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{value}");
        }
    }
}
