//! Git hooks that `tk` serves in commits it signs.

use std::{
    fs,
    io::Write,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Error, Result, bail};
use clap::Subcommand;

const CO_AUTHOR_TRAILER: &str = "Co-authored-by: Turnkey <noreply@turnkey.com>";
// Git's `commit -v` and `--cleanup=scissors` drop everything from this line on, after the comment character.
const SCISSORS: &[u8] = b" ------------------------ >8 ------------------------";

#[derive(Debug, Subcommand)]
pub enum GitCommand {
    /// Add a `Co-authored-by: Turnkey` trailer to a commit message, as Git's `commit-msg` hook.
    ///
    /// A message that already carries the trailer, or that is empty so Git aborts the commit, is left unchanged.
    CoAuthor {
        /// Commit message file Git passes to the hook.
        #[arg(value_name = "MESSAGE_FILE")]
        message_file: PathBuf,
    },
}

/// Replaces this process with `git interpret-trailers` unless the message is empty.
pub fn run(command: GitCommand) -> Result<()> {
    let GitCommand::CoAuthor { message_file } = command;
    let message = fs::read(&message_file)
        .with_context(|| format!("read the commit message {}", message_file.display()))?;
    let written: Vec<u8> = message
        .split_inclusive(|&byte| byte == b'\n')
        .take_while(|line| !line.trim_ascii_end().ends_with(SCISSORS))
        .flatten()
        .copied()
        .collect();
    let mut stripspace = Command::new("git")
        .args(["stripspace", "--strip-comments"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to run git stripspace")?;
    // `git stripspace` reads all of its input before writing, so this write cannot deadlock on its output.
    stripspace
        .stdin
        .take()
        .context("git stripspace has no stdin")?
        .write_all(&written)
        .context("write the commit message to git stripspace")?;
    let stripped = stripspace
        .wait_with_output()
        .context("failed to run git stripspace")?;
    if !stripped.status.success() {
        bail!("git stripspace exited with {}", stripped.status);
    }
    if stripped.stdout.is_empty() {
        return Ok(());
    }
    let error = Command::new("git")
        .args([
            "interpret-trailers",
            "--in-place",
            "--if-exists",
            "addIfDifferent",
            "--trailer",
            CO_AUTHOR_TRAILER,
        ])
        .arg(message_file)
        .exec();
    Err(Error::new(error).context("failed to run git interpret-trailers"))
}
