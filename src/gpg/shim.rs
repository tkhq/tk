//! The path taken when git calls `tk` as its `gpg.program`. Stdout, stderr,
//! and the exit code are gpg's contract, so this module is its own output
//! boundary. Anything that is not a signing call is handed to the real gpg
//! without loading configuration or credentials. A signing call reads the
//! registered key table, never a wallet, so it costs one Turnkey request.

use std::{
    env,
    ffi::OsString,
    io::{self, Read, Write},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, ExitCode},
};

use anyhow::{Context, Result};
use clap::Parser;

use crate::{
    auth::{self, AuthOptions},
    errors::{InvalidInput, Malformed, render_error_chain},
    gpg::{
        agent,
        registry::{KeyName, SelectError, SigningKeyName},
        selection_error,
        signer::TurnkeySigner,
        unix_now,
    },
    wire::openpgp::entity::armored_detached_signature,
};

/// gpg's own general error code, so a caller that reads the code sees a gpg
/// failure rather than a shell "command not found".
const CANNOT_EXEC: u8 = 2;

const DEFAULT_PROGRAM: &str = "gpg";

const ENVIRONMENT_HINT: &str = "set by TK_PROFILE";

const SIGNING_KEY_REMEDY: &str = "set user.signingkey to the key fingerprint";

pub enum Invocation {
    /// `--status-fd=<n> -bsau <key>`: sign stdin. The descriptor is carried
    /// as written so a malformed value stays distinct from none.
    Sign {
        status_fd: Option<String>,
        key: Option<String>,
    },
    /// Any other gpg shaped call, such as `--verify`: run the real gpg with
    /// the argument list as given.
    Passthrough(Vec<String>),
}

impl Invocation {
    /// `None` when the arguments are not gpg shaped. Only the first argument
    /// decides: git leads every gpg call with `--status-fd`, `--keyid-format`,
    /// `-bsau`, or `-bsa`, and a tk command line leads with a subcommand
    /// name, so no tk argument value can divert tk into this path.
    pub fn parse(args: Vec<String>) -> Option<Self> {
        let first = args.first()?;
        let gpg_shaped = first.starts_with("--status-fd")
            || first.starts_with("--keyid-format")
            || matches!(first.as_str(), "-bsau" | "-bsa");
        if !gpg_shaped {
            return None;
        }

        let signed: Option<Self> = {
            let mut status_fd = None;
            let mut key = None;
            let mut signing = false;
            let mut rest = args.iter();
            loop {
                let Some(arg) = rest.next() else {
                    break signing.then_some(Self::Sign { status_fd, key });
                };
                match arg.as_str() {
                    // Verification is gpg's job, whatever else the line asks
                    // for.
                    "--verify" => break None,
                    // A bare "--status-fd" is malformed rather than absent, so
                    // it is carried as an empty value.
                    "--status-fd" => status_fd = Some(rest.next().cloned().unwrap_or_default()),
                    "-bsau" => {
                        signing = true;
                        key = rest.next().cloned();
                    }
                    "-bsa" => signing = true,
                    other => {
                        if let Some(value) = other.strip_prefix("--status-fd=") {
                            status_fd = Some(value.to_string());
                        }
                    }
                }
            }
        };

        Some(signed.unwrap_or(Self::Passthrough(args)))
    }
}

#[derive(Parser)]
struct ShimOptions {
    #[command(flatten)]
    auth: AuthOptions,
}

impl ShimOptions {
    fn from_environment() -> Result<Self> {
        Self::try_parse_from(["tk"]).map_err(|error| {
            let rendered = error.to_string();
            let first = rendered.lines().next().unwrap_or_default();
            let detail = first.strip_prefix("error: ").unwrap_or(first);
            Malformed::new(format!("{detail} ({ENVIRONMENT_HINT})"), error).into()
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

pub async fn run(invocation: Invocation) -> ExitCode {
    let (status_fd, key) = match invocation {
        Invocation::Passthrough(args) => return passthrough(args),
        Invocation::Sign { status_fd, key } => (status_fd, key),
    };
    let signed = async {
        let status = StatusWriter::parse(status_fd)?;
        sign(status, key).await
    }
    .await;
    match signed {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {}", render_error_chain(&error));
            ExitCode::FAILURE
        }
    }
}

async fn sign(status: StatusWriter, key: Option<String>) -> Result<()> {
    let signature = match env::var_os(agent::SOCKET_ENV).filter(|v| !v.is_empty()) {
        Some(socket) => {
            let key = match key {
                Some(key) => Some(
                    key.parse::<SigningKeyName>()
                        .with_context(|| format!("parse the signing key {key}"))?,
                ),
                None => None,
            };
            let mut payload = Vec::new();
            io::stdin()
                .take((agent::MAX_PAYLOAD_LEN + 1) as u64)
                .read_to_end(&mut payload)
                .context("read the payload to sign from stdin")?;
            agent::sign(Path::new(&socket), key.as_ref(), &payload).await?
        }
        None => {
            let mut payload = Vec::new();
            io::stdin()
                .read_to_end(&mut payload)
                .context("read the payload to sign from stdin")?;
            let options = ShimOptions::from_environment()?;
            let (entry, client) = auth::open_gpg_key(&options.auth, key.map(KeyName::from))
                .await?
                .map_err(git_selection_error)?;
            let now = unix_now()?;
            armored_detached_signature(
                entry.key.signing,
                &payload,
                &TurnkeySigner::new(&client, entry.organization_id),
                now,
            )
            .await?
        }
    };
    // This line also supplies the newline git's search for
    // "\n[GNUPG:] SIG_CREATED " needs, so it must stay in front.
    status.line("[GNUPG:] BEGIN_SIGNING")?;
    let mut stdout = io::stdout();
    write!(stdout, "{signature}").context("write the signature to stdout")?;
    stdout.flush().context("write the signature to stdout")?;
    // The fields are gpg's: a document signature, ECDSA, SHA-256, no class.
    status.line(&format!(
        "[GNUPG:] SIG_CREATED D 19 8 00 {} {}",
        signature.created(),
        signature.fingerprint()
    ))
}

fn git_selection_error(error: SelectError) -> anyhow::Error {
    match &error {
        SelectError::Empty { .. } => selection_error(error, SIGNING_KEY_REMEDY),
        SelectError::Unnamed { .. }
        | SelectError::NoMatch { .. }
        | SelectError::Ambiguous { .. } => {
            InvalidInput(format!("{error}; {SIGNING_KEY_REMEDY}")).into()
        }
    }
}

fn passthrough(args: Vec<String>) -> ExitCode {
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
