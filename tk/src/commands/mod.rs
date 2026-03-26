/// SSH agent command with start/stop/status subcommands.
pub mod agent;
/// Persistent configuration inspection and mutation commands.
pub mod config;
/// Git SSH signing command implementation.
pub mod git_sign;
/// Interactive initialization command.
pub mod init;
/// Public key printing command implementation.
pub mod public_key;
/// Identity verification command.
pub mod whoami;
