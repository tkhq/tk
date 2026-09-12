//! The path taken when git calls `tk` as its `gpg.program`.
//!
//! Git hands this path a gpg style command line, the bytes to sign on stdin,
//! and expects an armored signature on stdout plus two status lines on the
//! descriptor it names. That contract belongs to gpg, so this module is its
//! own output boundary: it writes through explicit handles and renders its
//! own errors instead of returning an outcome to the CLI output layer.
//!
//! Anything that is not a signing call is handed to the real gpg. That path
//! loads no configuration and reads no credential.

use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use clap::Parser;
use turnkey_auth::openpgp::entity::{armor_signature, detached_signature};
use uuid::Uuid;

use crate::auth::{self, AuthOptions, build_turnkey_client};
use crate::errors::{InvalidInput, render_error_chain};
use crate::gpg::{TargetArgs, keys, keys::SelectError, signer::TurnkeySigner, unix_now};

/// The exit code used when the real gpg cannot be started. It is gpg's own
/// general error code, so a caller that reads the code sees a gpg failure
/// rather than a shell "command not found".
const CANNOT_EXEC: u8 = 2;

/// The program run for every call this shim does not sign itself.
const DEFAULT_PROGRAM: &str = "gpg";

/// How many hex characters a long OpenPGP key ID has. A hex `-u` value this
/// long or longer is matched against fingerprint suffixes. A shorter one is
/// matched against user IDs instead, because GnuPG also accepts a user ID,
/// and git sends the committer ident when `user.signingkey` is unset.
const LONG_KEY_ID_CHARS: usize = 16;

/// The environment a git user can change. No tk flag reaches this path, so
/// clap's own message would name flags nobody can pass.
const ENVIRONMENT_HINT: &str = "set by TK_GPG_WALLET_ID or TK_GPG_KEY_INDEX";

/// A gpg style command line that git hands to its `gpg.program`.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Invocation {
    /// `--status-fd=<n> -bsau <key>`: sign stdin, write the armored
    /// signature to stdout and the status lines to descriptor `n`. The
    /// descriptor is carried as written, so the one place that reads it can
    /// tell a malformed value from a call that named none.
    Sign {
        status_fd: Option<String>,
        key: Option<String>,
    },
    /// Any other gpg shaped call, for example `--verify`: run the real gpg
    /// with the same arguments.
    Passthrough,
}

impl Invocation {
    /// Returns `None` when the arguments are not gpg shaped, so normal tk
    /// parsing continues.
    ///
    /// Only the first argument decides, like the ssh `-Y` check: git leads
    /// every gpg call with `--status-fd` or `--keyid-format`, or with the
    /// bundled `-bsau`/`-bsa` flags. A tk command line leads with a
    /// subcommand name, so no tk argument value can divert tk into this
    /// path.
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
                // "--status-fd" with nothing after it named a descriptor
                // and failed to supply one, which is malformed rather than
                // absent, so it is carried as an empty value.
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

        Some(match signing {
            true => Self::Sign { status_fd, key },
            false => Self::Passthrough,
        })
    }
}

/// The identity and target the shim uses. Git passes no tk flags, so clap
/// parses an empty command line and applies the environment bindings.
#[derive(Parser)]
struct ShimOptions {
    #[command(flatten)]
    auth: AuthOptions,
    #[command(flatten)]
    target: TargetArgs,
}

impl ShimOptions {
    /// Reads the environment clap binds. The only values that can fail here
    /// come from the environment, so a failure is reported as one line that
    /// names the environment. Clap's own rendering carries an `error: `
    /// prefix, a blank line, and a `--help` hint, none of which git can use.
    fn from_environment() -> Result<Self> {
        Self::try_parse_from(["tk"]).map_err(|error| {
            let rendered = error.to_string();
            let first = rendered.lines().next().unwrap_or_default();
            let detail = first.strip_prefix("error: ").unwrap_or(first);
            InvalidInput(format!("{detail} ({ENVIRONMENT_HINT})")).into()
        })
    }
}

/// One candidate key, as a `-u` value is matched against it.
struct Candidate<'a> {
    /// The key's fingerprint, 40 upper case hex characters.
    fingerprint: String,
    /// The key's OpenPGP user ID.
    user_id: &'a str,
}

/// Reads the signing key git asked for and returns its position in
/// `candidates`.
///
/// `user.signingkey` reaches the shim as the `-u` value, and git sends the
/// committer ident instead when `user.signingkey` is unset. Both shapes name
/// a key here: a hex value of at least [`LONG_KEY_ID_CHARS`] characters
/// matches a fingerprint suffix, and any other value must equal a key's user
/// ID exactly. Git asked for a specific identity, so a value that names no
/// key fails rather than falling back to another key.
fn named_key(candidates: &[Candidate<'_>], requested: &str, wallet_id: Uuid) -> Result<usize> {
    let requested = requested.trim();
    // GnuPG accepts a fingerprint written in groups of four and a trailing
    // "!", which means "use exactly this key". Both name a key here too, so
    // they are normalized away before the hex test. A user ID carries spaces
    // of its own, so it is matched against the value as written.
    let hex_form = {
        let value = requested.strip_suffix('!').unwrap_or(requested);
        let value: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let long_enough = value.len() >= LONG_KEY_ID_CHARS;
        (long_enough && value.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| value.to_ascii_uppercase())
    };
    let mut matching = candidates.iter().enumerate().filter(|(_, candidate)| {
        let by_fingerprint = hex_form
            .as_ref()
            .is_some_and(|suffix| candidate.fingerprint.ends_with(suffix));
        by_fingerprint || candidate.user_id == requested
    });
    let Some((position, _)) = matching.next() else {
        return Err(InvalidInput(format!(
            "no OpenPGP key in wallet {wallet_id} matches signing key {requested}; set user.signingkey to the key fingerprint"
        ))
        .into());
    };
    if matching.next().is_some() {
        return Err(InvalidInput(format!(
            "signing key {requested} matches several OpenPGP keys; set user.signingkey to the key fingerprint"
        ))
        .into());
    }
    Ok(position)
}

/// Words a failed key selection for a git user, who can set
/// `user.signingkey` and the gpg environment but cannot pass a tk flag.
/// Only an ambiguous wallet has a different lever here, so every other
/// variant keeps the tk command line's wording and its remediation.
fn selection_error(error: SelectError) -> anyhow::Error {
    match &error {
        SelectError::Ambiguous { .. } => InvalidInput(format!(
            "{error}; choose one with user.signingkey, TK_GPG_KEY_INDEX, or tk gpg use --key-index"
        ))
        .into(),
        // An empty wallet and a missing index both name a tk command, which
        // the user can still run in a terminal, so both read the same in
        // either layer.
        SelectError::NoKeys { .. } | SelectError::Missing { .. } => super::selection_error(error),
    }
}

/// Where the `[GNUPG:]` status lines go. Git asks for descriptor 2, and a
/// call that names no descriptor wants no status lines.
///
/// Every line ends in a newline, and that newline is part of the contract:
/// git looks for the literal `"\n[GNUPG:] SIG_CREATED "`, so the line before
/// `SIG_CREATED` has to supply the newline in front of it.
enum StatusWriter {
    Stderr,
    Discard,
}

impl StatusWriter {
    /// Reads the descriptor gpg was asked to report on. Stdout carries the
    /// armored signature, so writing status lines there would corrupt it.
    /// A call that names no descriptor wants no status lines. Descriptor 2
    /// is the only one this shim writes to, so every other value, malformed
    /// or well formed, is bad input rather than a missing feature.
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

/// Runs the shim. This is an output boundary like the ssh `-Y` path: it
/// writes through explicit handles and renders its own errors.
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

/// Signs stdin and reports the result the way git expects.
async fn sign(status_fd: Option<String>, key: Option<String>) -> Result<()> {
    // The descriptor comes from the command line alone, so it is checked
    // before any configuration, credential, or request.
    let status = StatusWriter::parse(status_fd)?;

    let options = ShimOptions::from_environment()?;
    let auth = auth::resolve(&options.auth).await?;
    let target = options.target.resolve(auth.gpg)?;
    let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;

    let mut payload = Vec::new();
    io::stdin()
        .read_to_end(&mut payload)
        .context("read the payload to sign from stdin")?;

    let mut keys = keys::list_keys(&client, &auth.org_id, target.wallet_id).await?;
    // The saved key index chooses only when git named no key.
    let key = match key {
        Some(requested) => {
            // An empty wallet must say to create a key rather than that no
            // key matches, so it is answered before the name is compared.
            if keys.is_empty() {
                return Err(selection_error(SelectError::NoKeys {
                    wallet_id: target.wallet_id,
                }));
            }
            let position = {
                let candidates: Vec<Candidate<'_>> = keys
                    .iter()
                    .map(|key| Candidate {
                        fingerprint: key.key.fingerprint_hex(),
                        user_id: key.key.user_id.as_str(),
                    })
                    .collect();
                named_key(&candidates, &requested, target.wallet_id)?
            };
            keys.swap_remove(position)
        }
        None => keys::select(keys, target.wallet_id, target.key_index).map_err(selection_error)?,
    }
    .key;

    let now = unix_now()?;
    // This line also supplies the newline git's search for
    // "\n[GNUPG:] SIG_CREATED " needs, so it must stay in front.
    status.line("[GNUPG:] BEGIN_SIGNING")?;
    let packet = detached_signature(
        &key,
        &payload,
        &TurnkeySigner::new(&client, &auth.org_id),
        now,
    )
    .await?;
    let mut stdout = io::stdout();
    write!(stdout, "{}", armor_signature(&packet)).context("write the signature to stdout")?;
    stdout.flush().context("write the signature to stdout")?;
    // The fields are gpg's: a document signature, ECDSA, SHA-256, no class.
    status.line(&format!(
        "[GNUPG:] SIG_CREATED D 19 8 00 {now} {}",
        key.fingerprint_hex()
    ))
}

/// Replaces this process with the real gpg, which owns every call the shim
/// does not sign itself. It returns only when the program cannot start.
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

    fn parse(args: &[&str]) -> Option<Invocation> {
        Invocation::parse(&args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn a_signing_call_carries_the_status_descriptor_and_the_key() {
        assert_eq!(
            parse(&["--status-fd=2", "-bsau", "ABCDEF0123456789"]),
            Some(Invocation::Sign {
                status_fd: Some("2".to_string()),
                key: Some("ABCDEF0123456789".to_string()),
            })
        );
        assert_eq!(
            parse(&["--status-fd", "2", "-bsa", "-u", "KEY"]),
            Some(Invocation::Sign {
                status_fd: Some("2".to_string()),
                key: Some("KEY".to_string()),
            })
        );
        assert_eq!(
            parse(&["--status-fd=abc", "-bsa", "-u", "KEY"]),
            Some(Invocation::Sign {
                status_fd: Some("abc".to_string()),
                key: Some("KEY".to_string()),
            })
        );
        assert_eq!(
            parse(&["-bsa", "--status-fd"]),
            Some(Invocation::Sign {
                status_fd: Some(String::new()),
                key: None,
            })
        );
    }

    /// The descriptor is read once, here, so a value that names no
    /// descriptor this shim writes to fails rather than silently dropping
    /// the status lines git waits for.
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

    #[test]
    fn verification_goes_to_the_real_gpg() {
        assert_eq!(
            parse(&[
                "--keyid-format=long",
                "--status-fd=1",
                "--verify",
                "sig",
                "-"
            ]),
            Some(Invocation::Passthrough)
        );
    }

    #[test]
    fn a_tk_command_line_is_not_gpg_shaped() {
        assert_eq!(parse(&["wallet", "list"]), None);
        assert_eq!(parse(&[]), None);
    }

    /// A gpg marker that arrives as an option value must not divert tk into
    /// the shim: the sniff reads the first argument alone.
    #[test]
    fn a_gpg_marker_in_a_tk_option_value_is_not_gpg_shaped() {
        assert_eq!(
            parse(&["wallet", "list", "--organization-id", "--verify"]),
            None
        );
        assert_eq!(parse(&["config", "set", "--name", "-bsa"]), None);
        assert_eq!(parse(&["gpg", "sign", "--output", "--status-fd=2"]), None);
        assert_eq!(parse(&["--verify", "sig", "-"]), None);
    }

    const WALLET: &str = "9a1e2c4b-0000-4000-8000-000000000001";
    const FIRST: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
    const SECOND: &str = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
    /// Shares its last 16 characters with [`SECOND`], and no more.
    const THIRD: &str = "1111111111111111111111113210FEDCBA9876543210FEDCBA98";
    const FIRST_USER_ID: &str = "Ada Lovelace <ada@example.com>";
    const SECOND_USER_ID: &str = "Grace Hopper <grace@example.com>";

    fn wallet() -> Uuid {
        Uuid::parse_str(WALLET).expect("the test wallet id should parse")
    }

    fn chosen(keys: &[(&str, &str)], requested: &str) -> Result<usize> {
        let candidates: Vec<Candidate<'_>> = keys
            .iter()
            .map(|(fingerprint, user_id)| Candidate {
                fingerprint: fingerprint.to_string(),
                user_id,
            })
            .collect();
        named_key(&candidates, requested, wallet())
    }

    fn two_keys() -> [(&'static str, &'static str); 2] {
        [(FIRST, FIRST_USER_ID), (SECOND, SECOND_USER_ID)]
    }

    fn message(error: anyhow::Error) -> String {
        error
            .downcast_ref::<InvalidInput>()
            .expect("a rejected value should be invalid input")
            .0
            .clone()
    }

    #[test]
    fn a_fingerprint_suffix_names_one_key_whatever_its_case() {
        assert_eq!(
            chosen(&two_keys(), SECOND).expect("a full fingerprint should select"),
            1
        );
        assert_eq!(
            chosen(&two_keys(), &SECOND[24..].to_ascii_lowercase())
                .expect("a long key id should select"),
            1
        );
    }

    #[test]
    fn a_fingerprint_with_groups_or_a_trailing_bang_still_names_its_key() {
        let grouped = SECOND
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        for requested in [format!("{SECOND}!"), format!("{grouped}!"), grouped] {
            assert_eq!(
                chosen(&two_keys(), &requested).expect("the shape should select"),
                1,
                "{requested:?} should name the second key"
            );
        }
    }

    /// Git sends the committer ident when `user.signingkey` is unset, and
    /// that string is the signing account's name, so it names its key.
    #[test]
    fn a_user_id_names_its_key() {
        assert_eq!(
            chosen(&two_keys(), SECOND_USER_ID).expect("a user id should select"),
            1
        );
        assert_eq!(
            chosen(&two_keys(), &format!("  {FIRST_USER_ID}  "))
                .expect("surrounding space should not matter"),
            0
        );
    }

    #[test]
    fn a_signing_key_that_names_no_key_is_rejected() {
        for requested in [SECOND, "ada@example.com", "0123456789ABCDE", "Ada Lovelace"] {
            let error = chosen(&[(FIRST, FIRST_USER_ID)], requested)
                .expect_err("an unknown key should be rejected");
            assert_eq!(
                message(error),
                format!(
                    "no OpenPGP key in wallet {WALLET} matches signing key {requested}; set user.signingkey to the key fingerprint"
                )
            );
        }
    }

    #[test]
    fn a_signing_key_that_names_several_keys_is_rejected() {
        let short = &SECOND[24..];
        let error = chosen(&[(SECOND, SECOND_USER_ID), (THIRD, FIRST_USER_ID)], short)
            .expect_err("an ambiguous key should be rejected");
        assert_eq!(
            message(error),
            format!(
                "signing key {short} matches several OpenPGP keys; set user.signingkey to the key fingerprint"
            )
        );
    }
}
