// Direct print macros bypass tk's output protocol; use `Shell::emit` for
// structured output, `Shell::human` for presentation output, and tracing for
// diagnostics.
#![deny(clippy::print_stdout, clippy::print_stderr)]

mod auth;
mod cli;
mod commands;
mod errors;
mod keygen;
mod logging;
mod operations;
mod outcome;
mod output;
mod resources;
mod wallets;

use crate::cli::Cli;
use std::io::Write;
use std::process::ExitCode;
use tracing::debug;

#[tokio::main]
async fn main() -> ExitCode {
    logging::init();
    debug!(version = env!("CARGO_PKG_VERSION"), "starting tk");

    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();

    // Git invokes `tk -Y ...` through gpg.ssh.program with ssh-keygen style
    // arguments. This path bypasses clap and the output shell entirely: its
    // stdout/stderr and file artifacts are ssh-keygen's contract, not tk's.
    if raw_args.first().is_some_and(|arg| arg == "-Y") {
        return match turnkey_auth::git_sign::run_git_sign(&raw_args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "error: {error:#}");
                ExitCode::FAILURE
            }
        };
    }

    Cli::run().await
}
