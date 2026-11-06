//! Git hooks that `tk` serves in commits it signs.

use std::{
    fmt::{self, Display, Formatter},
    fs,
    io::Write,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Error, Result, bail};
use clap::Subcommand;
use serde::Serialize;

use crate::{auth::PRIVATE_KEY_ENV, errors::InvalidInput};

const CO_AUTHOR_HOOK: &str = "turnkey-co-author";
// Git reads `hook.<name>.*` configuration from 2.54 on; older Git ignores it without an error.
const CONFIG_HOOKS_SINCE: (u32, u32) = (2, 54);
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
    /// Check that the Git on `PATH` runs the `turnkey-co-author` hook on `commit-msg` in this repository.
    ///
    /// Git older than 2.54 ignores the hook's configuration without an error; this check fails with `invalid_input` instead.
    CoAuthorCheck,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct CoAuthorHookReady {
    git_version: String,
}

impl Display for CoAuthorHookReady {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Git {} runs the `{CO_AUTHOR_HOOK}` hook on `commit-msg`",
            self.git_version
        )
    }
}

/// Confirms that Git will run the co-author hook, naming the Git version that does.
pub fn check_co_author() -> Result<CoAuthorHookReady> {
    let version = Command::new("git")
        .env_remove(PRIVATE_KEY_ENV)
        .arg("version")
        .output()
        .context("failed to run git version")?;
    if !version.status.success() {
        bail!("git version exited with {}", version.status);
    }
    let version = String::from_utf8_lossy(&version.stdout);
    let git_version = version
        .trim()
        .strip_prefix("git version ")
        .with_context(|| format!("parse the `git version` output {version:?}"))?
        .to_owned();
    let mut numbers = git_version.split(['.', ' ']).map(str::parse::<u32>);
    let (Some(Ok(major)), Some(Ok(minor))) = (numbers.next(), numbers.next()) else {
        bail!("parse the Git version {git_version:?}");
    };
    if (major, minor) < CONFIG_HOOKS_SINCE {
        return Err(InvalidInput(format!(
            "Git {git_version} ignores `hook.*` configuration, so `{CO_AUTHOR_HOOK}` never runs; put Git 2.54 or newer first on `PATH`"
        ))
        .into());
    }
    let hooks = Command::new("git")
        .env_remove(PRIVATE_KEY_ENV)
        .args(["hook", "list", "commit-msg"])
        .output()
        .context("failed to run git hook list")?;
    // `git hook list` exits 1 when no hook is configured for the event.
    if !matches!(hooks.status.code(), Some(0 | 1)) {
        bail!(
            "git hook list exited with {}: {}",
            hooks.status,
            String::from_utf8_lossy(&hooks.stderr).trim()
        );
    }
    if !String::from_utf8_lossy(&hooks.stdout)
        .lines()
        .any(|hook| hook == CO_AUTHOR_HOOK)
    {
        return Err(InvalidInput(format!(
            "Git {git_version} has no `{CO_AUTHOR_HOOK}` hook for `commit-msg` in the current directory"
        ))
        .into());
    }
    Ok(CoAuthorHookReady { git_version })
}

/// Replaces this process with `git interpret-trailers` unless the message is empty.
pub fn co_author(message_file: PathBuf) -> Result<()> {
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
        .env_remove(PRIVATE_KEY_ENV)
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
        .env_remove(PRIVATE_KEY_ENV)
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
