use std::io::IsTerminal;
use tracing_subscriber::EnvFilter;

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));

    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();
}
