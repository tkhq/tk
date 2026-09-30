//! Git's ssh-keygen-compatible signing and verification entry point.

use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::fs;

use crate::{
    auth::{self, AuthOptions},
    errors::{InvalidInput, render_error_chain},
    ssh::{
        registry::{SelectError, SshKeyName},
        selection_error,
        signer::{BACKOFF, TurnkeySigner},
    },
    wire::ssh::{
        PublicKeyParseError, build_signed_data, encode_armored_signature, parse_public_key_line,
    },
};

const CANNOT_EXEC: u8 = 2;
const DEFAULT_PROGRAM: &str = "ssh-keygen";
const ENVIRONMENT_HINT: &str = "set by TK_PROFILE";

pub enum Invocation {
    /// A validated `-Y sign -n git -f <key> [-U] <payload>` call.
    Sign {
        public_key_path: PathBuf,
        payload_path: PathBuf,
    },
    /// An ssh-keygen verification operation, with the argument list as given.
    Passthrough(Vec<String>),
}

impl Invocation {
    pub fn parse(args: Vec<String>) -> Result<Self> {
        if matches!(
            args.get(1).map(String::as_str),
            Some("verify" | "find-principals" | "check-novalidate")
        ) {
            return Ok(Self::Passthrough(args));
        }
        let mut operation = None;
        let mut namespace = None;
        let mut public_key_path = None;
        let mut payload_path = None;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "-Y" => {
                    operation = Some(
                        rest.next()
                            .ok_or_else(|| InvalidInput("missing value after -Y".into()))?
                            .as_str(),
                    )
                }
                "-n" => {
                    namespace = Some(
                        rest.next()
                            .ok_or_else(|| InvalidInput("missing value after -n".into()))?
                            .as_str(),
                    )
                }
                "-f" => {
                    public_key_path =
                        Some(PathBuf::from(rest.next().ok_or_else(|| {
                            InvalidInput("missing value after -f".into())
                        })?))
                }
                "-U" => {}
                value if value.starts_with('-') => {
                    return Err(
                        InvalidInput(format!("unsupported ssh signer argument: {value}")).into(),
                    );
                }
                value => payload_path = Some(PathBuf::from(value)),
            }
        }
        match operation {
            Some("sign") => {
                let namespace = namespace
                    .ok_or_else(|| InvalidInput("missing required -n <namespace>".into()))?;
                if namespace != "git" {
                    return Err(InvalidInput(format!(
                        "unsupported SSH signing namespace: {namespace}"
                    ))
                    .into());
                }
                Ok(Self::Sign {
                    public_key_path: public_key_path.ok_or_else(|| {
                        InvalidInput("missing required -f <public-key-file>".into())
                    })?,
                    payload_path: payload_path
                        .ok_or_else(|| InvalidInput("missing payload file path".into()))?,
                })
            }
            Some(operation) => {
                Err(InvalidInput(format!("unsupported SSH signer operation: {operation}")).into())
            }
            None => Err(InvalidInput("missing required -Y <operation>".into()).into()),
        }
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
            InvalidInput(format!("{detail} ({ENVIRONMENT_HINT})")).into()
        })
    }
}

pub async fn run(invocation: Invocation) -> ExitCode {
    let result = match invocation {
        Invocation::Passthrough(args) => return passthrough(args),
        Invocation::Sign {
            public_key_path,
            payload_path,
        } => {
            async {
                let options = ShimOptions::from_environment()?;
                sign_paths(public_key_path, payload_path, &options.auth).await
            }
            .await
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {}", render_error_chain(&error));
            ExitCode::FAILURE
        }
    }
}

pub async fn sign(args: Vec<String>, options: &AuthOptions) -> Result<()> {
    match Invocation::parse(args)? {
        Invocation::Sign {
            public_key_path,
            payload_path,
        } => sign_paths(public_key_path, payload_path, options).await,
        Invocation::Passthrough(_) => Err(InvalidInput(
            "verification passthrough is available only through tk -Y".into(),
        )
        .into()),
    }
}

async fn sign_paths(
    public_key_path: PathBuf,
    payload_path: PathBuf,
    options: &AuthOptions,
) -> Result<()> {
    let key_text = fs::read_to_string(&public_key_path)
        .await
        .with_context(|| format!("read SSH key from {}", public_key_path.display()))?;
    let first_line = key_text.lines().next().unwrap_or_default();
    let key = parse_public_key_line(first_line).map_err(|error| match &error {
        PublicKeyParseError::UnsupportedAlgorithm { algorithm } => InvalidInput(format!(
            "SSH key in {} is {algorithm}; tk signs with ssh-ed25519 keys",
            public_key_path.display()
        )),
        _ => InvalidInput(format!(
            "invalid SSH key in {}: {error}",
            public_key_path.display()
        )),
    })?;
    let payload = fs::read(&payload_path)
        .await
        .with_context(|| format!("read {} to sign", payload_path.display()))?;
    let (entry, client) = auth::open_ssh_key(options, Some(SshKeyName::PublicKey(key)))
        .await?
        .map_err(git_selection_error)?;
    let signed_data = build_signed_data("git", &payload);
    let signature = TurnkeySigner::new(
        &client,
        entry.organization_id,
        &entry.private_key_id,
        BACKOFF,
    )
    .sign_raw_payload(&signed_data)
    .await?;
    let armored = encode_armored_signature(&entry.public_key.blob(), "git", &signature);
    let signature_path = PathBuf::from(format!("{}.sig", payload_path.display()));
    fs::write(&signature_path, armored)
        .await
        .with_context(|| format!("write signature to {}", signature_path.display()))
}

fn git_selection_error(error: SelectError) -> anyhow::Error {
    match &error {
        SelectError::NoMatch { requested: SshKeyName::PublicKey(key) } => InvalidInput(format!(
            "no registered SSH key matches {}; register it with tk ssh keys add --private-key-id <id>, or set user.signingkey to a registered key",
            key.fingerprint()
        )).into(),
        _ => selection_error(error, "set user.signingkey to a registered key"),
    }
}

fn passthrough(args: Vec<String>) -> ExitCode {
    let program = env::var_os("TK_SSH_KEYGEN_PROGRAM")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_PROGRAM));
    let error = Command::new(&program).args(args).exec();
    let _ = writeln!(
        io::stderr(),
        "error: cannot run {}: {error}; install ssh-keygen or set TK_SSH_KEYGEN_PROGRAM",
        Path::new(&program).display()
    );
    ExitCode::from(CANNOT_EXEC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parses_git_sign_with_and_without_public_key_flag() {
        for invocation in [
            args(&["-Y", "sign", "-n", "git", "-f", "key.pub", "payload"]),
            args(&["-Y", "sign", "-n", "git", "-f", "key.pub", "-U", "payload"]),
        ] {
            match Invocation::parse(invocation).expect("git's sign call should parse") {
                Invocation::Sign {
                    public_key_path,
                    payload_path,
                } => {
                    assert_eq!(public_key_path, PathBuf::from("key.pub"));
                    assert_eq!(payload_path, PathBuf::from("payload"));
                }
                Invocation::Passthrough(_) => panic!("a sign call must not be passed through"),
            }
        }
    }

    #[test]
    fn recognizes_ssh_keygen_verification_operations() {
        for operation in ["verify", "find-principals", "check-novalidate"] {
            let forwarded = args(&["-Y", operation]);
            assert!(matches!(
                Invocation::parse(forwarded.clone()),
                Ok(Invocation::Passthrough(passed)) if passed == forwarded
            ));
        }
        let forwarded = args(&[
            "-Y",
            "verify",
            "-n",
            "git",
            "-f",
            "allowed_signers",
            "-I",
            "signer@example.com",
            "-s",
            "commit.sig",
        ]);
        assert!(matches!(
            Invocation::parse(forwarded.clone()),
            Ok(Invocation::Passthrough(passed)) if passed == forwarded
        ));
    }

    #[test]
    fn rejects_unknown_flags() {
        let error = Invocation::parse(args(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "key.pub",
            "--unknown",
            "payload",
        ]))
        .err()
        .expect("an unknown flag should fail");

        assert_eq!(
            error.to_string(),
            "unsupported ssh signer argument: --unknown"
        );
    }

    #[test]
    fn rejects_unknown_operations() {
        let error = Invocation::parse(args(&["-Y", "frobnicate"]))
            .err()
            .expect("an unknown operation should fail");

        assert_eq!(
            error.to_string(),
            "unsupported SSH signer operation: frobnicate"
        );
    }
}
