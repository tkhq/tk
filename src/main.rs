//! `tk` command-line entry point.

mod auth;
mod cli;
mod errors;
mod gpg;
mod keygen;
mod logging;
mod operations;
mod outcome;
mod output;
mod registry;
mod resources;
mod secrets;
mod sessions;
mod skills;
mod socket;
mod ssh;
mod update;
mod wallets;
mod wire;

use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

use tracing::debug;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    logging::init();
    debug!(version = env!("CARGO_PKG_VERSION"), "starting tk");

    let raw_args = env::args().skip(1).collect::<Vec<_>>();

    // Git invokes `tk -Y ...` through gpg.ssh.program with ssh-keygen style
    // arguments. This path bypasses clap and the output shell entirely: its
    // stdout/stderr and file artifacts are ssh-keygen's contract, not tk's.
    if raw_args.first().is_some_and(|arg| arg == "-Y") {
        let invocation = match ssh::shim::Invocation::parse(raw_args) {
            Ok(invocation) => invocation,
            Err(error) => {
                let _ = writeln!(io::stderr(), "error: {error:#}");
                return ExitCode::FAILURE;
            }
        };
        return ssh::shim::run(invocation).await;
    }

    // Git invokes `tk` through gpg.program with gpg style arguments. Like
    // the ssh path above, this one bypasses clap and the output shell: its
    // stdout, stderr, and exit code are gpg's contract, not tk's.
    if let Some(invocation) = gpg::shim::Invocation::parse(raw_args) {
        return gpg::shim::run(invocation).await;
    }

    Cli::run().await
}
