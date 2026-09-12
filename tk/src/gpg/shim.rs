//! The path taken when git calls `tk` as its `gpg.program`. Stdout, stderr,
//! and the exit code are gpg's contract, so this module is its own output
//! boundary. Anything that is not a signing call is handed to the real gpg
//! without loading configuration or credentials. A signing call reads the
//! registered key table, never a wallet, so it costs one Turnkey request.

use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use clap::Parser;
use turnkey_auth::openpgp::entity::{armor_signature, detached_signature};

use crate::auth::{self, AuthOptions};
use crate::errors::{InvalidInput, render_error_chain};
use crate::gpg::registry::SelectError;
use crate::gpg::{client_for_entry, registry_selection_error, signer::TurnkeySigner, unix_now};

/// gpg's own general error code, so a caller that reads the code sees a gpg
/// failure rather than a shell "command not found".
const CANNOT_EXEC: u8 = 2;

const DEFAULT_PROGRAM: &str = "gpg";

/// Clap's own message would name flags git cannot pass.
const ENVIRONMENT_HINT: &str = "set by TK_CONFIG or TK_PROFILE";

pub enum Invocation {
    /// `--status-fd=<n> -bsau <key>`: sign stdin. The descriptor is carried
    /// as written so a malformed value stays distinct from none.
    Sign {
        status_fd: Option<String>,
        key: Option<String>,
    },
    /// Any other gpg shaped call, such as `--verify`: run the real gpg.
    Passthrough,
}

impl Invocation {
    /// `None` when the arguments are not gpg shaped. Only the first argument
    /// decides: git leads every gpg call with `--status-fd`, `--keyid-format`,
    /// `-bsau`, or `-bsa`, and a tk command line leads with a subcommand
    /// name, so no tk argument value can divert tk into this path.
    pub fn parse(args: &[String]) -> Option<Self> {
        let first = args.first()?;
        let gpg_shaped = first.starts_with("--status-fd")
            || first.starts_with("--keyid-format")
            || matches!(first.as_str(), "-bsau" | "-bsa");
        if !gpg_shaped {
            return None;
        }

        let mut status_fd = None;
        let mut key = None;
        let mut signing = false;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                // Verification is gpg's job, whatever else the line asks for.
                "--verify" => return Some(Self::Passthrough),
                // A bare "--status-fd" is malformed rather than absent, so
                // it is carried as an empty value.
                "--status-fd" => status_fd = Some(args.next().cloned().unwrap_or_default()),
                "-bsau" => {
                    signing = true;
                    key = args.next().cloned();
                }
                "-bsa" | "--detach-sign" => signing = true,
                "-u" | "--local-user" => key = args.next().cloned(),
                other => {
                    if let Some(value) = other.strip_prefix("--status-fd=") {
                        status_fd = Some(value.to_string());
                    }
                }
            }
        }

        if signing {
            Some(Self::Sign { status_fd, key })
        } else {
            Some(Self::Passthrough)
        }
    }
}

/// Git passes no tk flags, so clap applies only the environment bindings.
#[derive(Parser)]
struct ShimOptions {
    #[command(flatten)]
    auth: AuthOptions,
}

impl ShimOptions {
    /// Reports a failure as one line naming the environment; clap's usage
    /// block is useless to git.
    fn from_environment() -> Result<Self> {
        Self::try_parse_from(["tk"]).map_err(|error| {
            let rendered = error.to_string();
            let first = rendered.lines().next().unwrap_or_default();
            let detail = first.strip_prefix("error: ").unwrap_or(first);
            InvalidInput(format!("{detail} ({ENVIRONMENT_HINT})")).into()
        })
    }
}

/// Where the `[GNUPG:]` status lines go. Every line ends in a newline: git
/// looks for the literal `"\n[GNUPG:] SIG_CREATED "`.
enum StatusWriter {
    Stderr,
    Discard,
}

impl StatusWriter {
    /// Stdout carries the armored signature, so 2 is the only descriptor
    /// this shim writes status lines to; every other value is bad input.
    fn parse(status_fd: Option<String>) -> Result<Self> {
        match status_fd.as_deref() {
            None => Ok(Self::Discard),
            Some("2") => Ok(Self::Stderr),
            Some(_) => Err(InvalidInput("unsupported --status-fd; git uses 2".to_string()).into()),
        }
    }

    fn line(&self, line: &str) -> Result<()> {
        match self {
            Self::Stderr => writeln!(io::stderr(), "{line}"),
            Self::Discard => Ok(()),
        }
        .context("write a gpg status line")
    }
}

pub async fn run(invocation: Invocation, args: Vec<String>) -> ExitCode {
    let (status_fd, key) = match invocation {
        Invocation::Passthrough => return passthrough(args),
        Invocation::Sign { status_fd, key } => (status_fd, key),
    };
    match sign(status_fd, key).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {}", render_error_chain(&error));
            ExitCode::FAILURE
        }
    }
}

async fn sign(status_fd: Option<String>, key: Option<String>) -> Result<()> {
    let status = StatusWriter::parse(status_fd)?;

    let options = ShimOptions::from_environment()?;
    let entry = auth::load_gpg_keys(&options.auth)
        .await?
        .select_for_git(key.as_deref())
        .map_err(selection_error)?;
    let (client, org_id) = client_for_entry(&options.auth, &entry).await?;

    let mut payload = Vec::new();
    io::stdin()
        .read_to_end(&mut payload)
        .context("read the payload to sign from stdin")?;

    let now = unix_now()?;
    // This line also supplies the newline git's search for
    // "\n[GNUPG:] SIG_CREATED " needs, so it must stay in front.
    status.line("[GNUPG:] BEGIN_SIGNING")?;
    let packet = detached_signature(
        entry.key.signing,
        &payload,
        &TurnkeySigner::new(&client, &org_id),
        now,
    )
    .await?;
    let mut stdout = io::stdout();
    write!(stdout, "{}", armor_signature(&packet)).context("write the signature to stdout")?;
    stdout.flush().context("write the signature to stdout")?;
    // The fields are gpg's: a document signature, ECDSA, SHA-256, no class.
    status.line(&format!(
        "[GNUPG:] SIG_CREATED D 19 8 00 {now} {}",
        entry.fingerprint()
    ))
}

/// A git user can set `user.signingkey` but cannot pass a tk flag. An empty
/// table names a tk command, which the user can still run in a terminal.
fn selection_error(error: SelectError) -> anyhow::Error {
    match &error {
        SelectError::Empty => registry_selection_error(error, ""),
        SelectError::Unnamed { .. }
        | SelectError::NotRegistered { .. }
        | SelectError::Ambiguous { .. } => InvalidInput(format!(
            "{error}; set user.signingkey to the key fingerprint"
        ))
        .into(),
    }
}

/// Replaces this process with the real gpg; returns only when it cannot start.
fn passthrough(args: Vec<String>) -> ExitCode {
    // An empty value is treated as unset, so an exported but blank variable
    // does not turn every verification into a failure to start "".
    let program = env::var_os("TK_GPG_PROGRAM")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_PROGRAM));
    let error = Command::new(&program).args(args).exec();
    let _ = writeln!(
        io::stderr(),
        "error: cannot run {}: {error}; install GnuPG or set TK_GPG_PROGRAM",
        Path::new(&program).display()
    );
    ExitCode::from(CANNOT_EXEC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(error: anyhow::Error) -> String {
        error
            .downcast_ref::<InvalidInput>()
            .expect("a rejected value should be invalid input")
            .0
            .clone()
    }

    #[test]
    fn only_descriptor_two_is_written_and_every_other_value_is_rejected() {
        assert!(matches!(
            StatusWriter::parse(None).expect("a call that names no descriptor wants no lines"),
            StatusWriter::Discard
        ));
        assert!(matches!(
            StatusWriter::parse(Some("2".to_string())).expect("git's descriptor is written"),
            StatusWriter::Stderr
        ));
        for value in ["abc", "", "1", "3"] {
            let Err(error) = StatusWriter::parse(Some(value.to_string())) else {
                panic!("{value:?} should be rejected")
            };
            assert_eq!(message(error), "unsupported --status-fd; git uses 2");
        }
    }
}
