mod cli;
mod commands;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();

    if raw_args.first().is_some_and(|arg| arg == "-Y") {
        return commands::git_sign::run(commands::git_sign::Args {
            ssh_keygen_args: raw_args,
        })
        .await;
    }

    Cli::run().await
}
