mod cli;
mod commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::Cli::run().await
}
