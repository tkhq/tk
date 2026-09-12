//! The `tk gpg` command family: OpenPGP keys held as Turnkey wallet
//! accounts, plus the exports and detached signatures they produce.
//!
//! Each command parses its local inputs first, then resolves an identity,
//! then talks to Turnkey, so a bad user ID or an unreadable file fails
//! before any credential is read. `use` writes the profile and never leaves
//! the machine.

use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use tokio::fs;
use turnkey_auth::openpgp::OpenPgpError;
use turnkey_auth::openpgp::entity::{
    UserId, armor_signature, detached_signature, export_public_key,
};
use uuid::Uuid;

use crate::auth::{self, AuthOptions, GpgProfile, build_turnkey_client, set_profile_gpg};
use crate::errors::{InvalidInput, MissingResource};
use crate::outcome::Outcome;

use signer::TurnkeySigner;

/// Wallet accounts that hold OpenPGP keys: their derivation paths,
/// listing, creation, and selection.
pub mod keys;

/// The git shim: the gpg style command line git hands to its `gpg.program`,
/// and the signing and passthrough paths it selects.
pub mod shim;

/// A [`turnkey_auth::openpgp::entity::SignDigest`] implementation backed by
/// Turnkey sign raw payload.
pub mod signer;

#[derive(Debug, Subcommand)]
pub enum GpgCommand {
    /// Manage OpenPGP keys held as wallet accounts.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Write an armored detached signature for a file. With no file, tk signs stdin.
    Sign(SignArgs),
    /// Save the wallet and key index the gpg commands and the git shim use.
    Use(UseArgs),
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Create a signing account for a user ID.
    Create(CreateArgs),
    /// List the OpenPGP keys in the wallet.
    List(TargetArgs),
    /// Print the armored public key block. Signs the self certification with the key, so a policy that requires approval blocks it.
    Export(TargetArgs),
}

/// The wallet a command reads from. Every command that reads one flattens
/// this struct, so the flag, the environment variable, and the type are
/// declared once. `use` writes the wallet instead and requires the flag.
#[derive(Debug, Args)]
struct WalletArgs {
    /// Wallet holding the OpenPGP key accounts.
    #[arg(long, env = "TK_GPG_WALLET_ID")]
    wallet_id: Option<Uuid>,
}

/// Which wallet and key a command acts on. Flags win over the environment,
/// which wins over the profile.
#[derive(Debug, Args)]
pub struct TargetArgs {
    #[command(flatten)]
    wallet: WalletArgs,
    /// Which key in the wallet to act on.
    #[arg(long, env = "TK_GPG_KEY_INDEX")]
    key_index: Option<u32>,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[command(flatten)]
    wallet: WalletArgs,
    /// Key index to create at. It must be free. The default is the lowest
    /// free index. This flag reads no environment variable: the saved key
    /// index names the key to sign with, not a slot to create in.
    #[arg(long)]
    at_index: Option<u32>,
    /// The OpenPGP user ID, for example "Ada Lovelace <ada@example.com>".
    #[arg(long, value_parser = parse_user_id)]
    user_id: UserId,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// File to sign. With no file, tk reads stdin.
    file: Option<PathBuf>,
    /// Write the armored signature here instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct UseArgs {
    /// Wallet holding the OpenPGP key accounts.
    #[arg(long)]
    wallet_id: Uuid,
    /// Which key in the wallet to use by default.
    #[arg(long, default_value_t = 0)]
    key_index: u32,
}

/// A resolved command target.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Target {
    /// The wallet the command acts on.
    pub wallet_id: Uuid,
    /// The key index, or `None` when the command should pick the only key.
    pub key_index: Option<u32>,
}

impl WalletArgs {
    /// Merges the flag and the environment with the profile's gpg table.
    /// The "no wallet selected" decision and its remediation live here and
    /// nowhere else.
    fn resolve(self, profile: Option<GpgProfile>) -> Result<Uuid> {
        let Self { wallet_id } = self;
        // No gpg command prompts, so the remediation names the three ways to
        // supply a wallet rather than a terminal.
        wallet_id
            .or_else(|| profile.map(|gpg| gpg.wallet_id))
            .ok_or_else(|| {
                InvalidInput(
                    "no wallet selected; pass --wallet-id, set TK_GPG_WALLET_ID, or run tk gpg use"
                        .into(),
                )
                .into()
            })
    }
}

impl TargetArgs {
    /// Merges flags and environment with the profile's gpg table.
    pub fn resolve(self, profile: Option<GpgProfile>) -> Result<Target> {
        let Self { wallet, key_index } = self;
        Ok(Target {
            wallet_id: wallet.resolve(profile)?,
            key_index: key_index.or_else(|| profile.map(|gpg| gpg.key_index)),
        })
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct KeySummary {
    pub key_index: u32,
    pub fingerprint: String,
    pub user_id: String,
    pub created: u32,
}

impl Display for KeySummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  {}  {}",
            self.fingerprint, self.key_index, self.user_id
        )
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct KeyCreated {
    pub wallet_id: Uuid,
    #[serde(flatten)]
    pub key: KeySummary,
}

impl Display for KeyCreated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "created OpenPGP key {} (key index {}) for {}",
            self.key.fingerprint, self.key.key_index, self.key.user_id
        )
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct KeysListed {
    pub wallet_id: Uuid,
    pub keys: Vec<KeySummary>,
}

impl Display for KeysListed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Some((last, rest)) = self.keys.split_last() else {
            return write!(f, "no OpenPGP keys in wallet {}", self.wallet_id);
        };
        for key in rest {
            writeln!(f, "{key}")?;
        }
        write!(f, "{last}")
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyExported {
    pub fingerprint: String,
    pub armored: String,
}

impl Display for PublicKeyExported {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // The armor ends in a newline and the output boundary adds one, so
        // the block is written without its own.
        f.write_str(self.armored.trim_end_matches('\n'))
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct SignatureCreated {
    pub fingerprint: String,
    pub armored: String,
    pub output: Option<PathBuf>,
}

impl Display for SignatureCreated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.output {
            Some(_) => Ok(()),
            // As in PublicKeyExported, the output boundary adds the newline.
            None => f.write_str(self.armored.trim_end_matches('\n')),
        }
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct ProfileUpdated {
    pub profile: String,
    pub wallet_id: Uuid,
    pub key_index: u32,
}

impl Display for ProfileUpdated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "profile {}: gpg wallet {}, key index {}",
            self.profile, self.wallet_id, self.key_index
        )
    }
}

/// Parses a `--user-id` value while clap reads the command line, so the
/// invariant is enforced once, at the CLI boundary.
fn parse_user_id(value: &str) -> Result<UserId, OpenPgpError> {
    UserId::parse(value.to_owned())
}

/// Words a failed key selection for the tk command line, whose user can pass
/// flags and run other tk commands.
fn selection_error(error: keys::SelectError) -> anyhow::Error {
    match &error {
        keys::SelectError::NoKeys { .. } => {
            InvalidInput(format!("{error}; create one with tk gpg keys create")).into()
        }
        keys::SelectError::Ambiguous { .. } => {
            InvalidInput(format!("{error}; name one with --key-index")).into()
        }
        keys::SelectError::Missing { index, .. } => {
            MissingResource::new("OpenPGP key", index.to_string()).into()
        }
    }
}

/// Runs one gpg command. Parses local inputs, then resolves the identity,
/// then talks to Turnkey.
pub async fn run(command: GpgCommand, options: &AuthOptions) -> Result<Outcome> {
    // Each arm resolves only the identity its own command needs. `use`
    // writes the profile and reads no credential at all, and the payload is
    // loaded before its arm resolves anything, so everything local that can
    // fail still fails before the first credential read.
    let (auth, wallet_id, prepared) = match command {
        GpgCommand::Use(UseArgs {
            wallet_id,
            key_index,
        }) => {
            let profile = set_profile_gpg(
                options,
                GpgProfile {
                    wallet_id,
                    key_index,
                },
            )
            .await?;
            return Ok(Outcome::GpgProfileUpdated(ProfileUpdated {
                profile,
                wallet_id,
                key_index,
            }));
        }
        GpgCommand::Keys {
            command:
                KeysCommand::Create(CreateArgs {
                    wallet,
                    at_index,
                    user_id,
                }),
        } => {
            // Create carries its own index flag and resolves the wallet
            // alone, so neither the saved key index nor TK_GPG_KEY_INDEX can
            // choose the slot.
            let auth = auth::resolve(options).await?;
            let wallet_id = wallet.resolve(auth.gpg)?;
            (
                auth,
                wallet_id,
                Prepared::Create {
                    user_id,
                    index: at_index,
                },
            )
        }
        GpgCommand::Keys {
            command: KeysCommand::List(target),
        } => {
            let auth = auth::resolve(options).await?;
            // A listing names every key, so only the wallet is resolved.
            let TargetArgs {
                wallet,
                key_index: _,
            } = target;
            let wallet_id = wallet.resolve(auth.gpg)?;
            (auth, wallet_id, Prepared::List)
        }
        GpgCommand::Keys {
            command: KeysCommand::Export(target),
        } => {
            let auth = auth::resolve(options).await?;
            let Target {
                wallet_id,
                key_index,
            } = target.resolve(auth.gpg)?;
            (auth, wallet_id, Prepared::Export { key_index })
        }
        GpgCommand::Sign(SignArgs {
            target,
            file,
            output,
        }) => {
            let data = match &file {
                Some(path) => fs::read(path)
                    .await
                    .with_context(|| format!("read {} to sign", path.display()))?,
                // Stdin has no async reader in this build of tokio, so the
                // one blocking read stays.
                None => {
                    let mut bytes = Vec::new();
                    io::stdin()
                        .read_to_end(&mut bytes)
                        .context("read the payload to sign from stdin")?;
                    bytes
                }
            };
            let auth = auth::resolve(options).await?;
            let Target {
                wallet_id,
                key_index,
            } = target.resolve(auth.gpg)?;
            (
                auth,
                wallet_id,
                Prepared::Sign {
                    key_index,
                    data,
                    output,
                },
            )
        }
    };

    let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
    let org_id = auth.org_id;
    let keys::WalletKeys {
        keys: existing,
        occupied,
    } = keys::read_wallet(&client, &org_id, wallet_id).await?;

    match prepared {
        Prepared::Create { user_id, index } => {
            let index = match index {
                Some(index) => {
                    if occupied.contains(&index) {
                        return Err(InvalidInput(format!(
                            "wallet {wallet_id} already has an account at OpenPGP key index {index}"
                        ))
                        .into());
                    }
                    index
                }
                None => keys::next_free_index(&occupied),
            };
            let key = keys::create_key(&client, &org_id, wallet_id, index, user_id).await?;
            Ok(Outcome::GpgKeyCreated(KeyCreated {
                wallet_id,
                key: key.into(),
            }))
        }
        Prepared::List => Ok(Outcome::GpgKeysListed(KeysListed {
            wallet_id,
            keys: existing.into_iter().map(KeySummary::from).collect(),
        })),
        Prepared::Export { key_index } => {
            let key = keys::select(existing, wallet_id, key_index)
                .map_err(selection_error)?
                .key;
            let signer = TurnkeySigner::new(&client, &org_id);
            // Every time in the block comes from the account, never from
            // the clock, so exporting the same key twice yields the same
            // block.
            let armored = export_public_key(&key, &signer).await?;
            Ok(Outcome::GpgPublicKeyExported(PublicKeyExported {
                fingerprint: key.fingerprint_hex(),
                armored,
            }))
        }
        Prepared::Sign {
            key_index,
            data,
            output,
        } => {
            let key = keys::select(existing, wallet_id, key_index)
                .map_err(selection_error)?
                .key;
            let signer = TurnkeySigner::new(&client, &org_id);
            // A detached signature is dated by the clock, unlike the self
            // signature in an export.
            let now = unix_now()?;
            let packet = detached_signature(&key, &data, &signer, now).await?;
            let armored = armor_signature(&packet);
            if let Some(path) = &output {
                fs::write(path, &armored)
                    .await
                    .with_context(|| format!("write the signature to {}", path.display()))?;
            }
            Ok(Outcome::GpgSignatureCreated(SignatureCreated {
                fingerprint: key.fingerprint_hex(),
                armored,
                output,
            }))
        }
    }
}

/// Reads the current time as seconds since the Unix epoch, the form an
/// OpenPGP signature creation time takes. A clock that reads a time before
/// 1970 is rejected rather than defaulted: a signature with a wrong creation time is
/// worse than a failed one. The cast holds until the u32 field overflows in
/// 2106, which the format itself shares.
fn unix_now() -> Result<u32> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InvalidInput("the system clock reads a time before 1970".into()))?;
    Ok(since.as_secs() as u32)
}

/// One command's inputs, parsed and resolved, waiting for the wallet's
/// keys.
enum Prepared {
    Create {
        user_id: UserId,
        index: Option<u32>,
    },
    List,
    Export {
        key_index: Option<u32>,
    },
    Sign {
        key_index: Option<u32>,
        data: Vec<u8>,
        output: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use clap::error::{ContextKind, ErrorKind};

    #[derive(Parser)]
    struct GpgParser {
        #[command(subcommand)]
        command: GpgCommand,
    }

    const WALLET: &str = "9a1e2c4b-0000-4000-8000-000000000001";
    const OTHER_WALLET: &str = "9a1e2c4b-0000-4000-8000-000000000002";

    fn target_of(args: [&str; 3]) -> TargetArgs {
        let parsed = GpgParser::try_parse_from(args).expect("target flags should parse");
        match parsed.command {
            GpgCommand::Keys {
                command: KeysCommand::List(target),
            } => target,
            _ => panic!("expected a keys list command"),
        }
    }

    #[test]
    fn use_requires_a_uuid_wallet_and_defaults_the_key_index() {
        assert!(GpgParser::try_parse_from(["gpg", "use", "--wallet-id", "nope"]).is_err());
        assert!(GpgParser::try_parse_from(["gpg", "use"]).is_err());
        let parsed = GpgParser::try_parse_from(["gpg", "use", "--wallet-id", WALLET])
            .expect("a uuid wallet should parse");
        match parsed.command {
            GpgCommand::Use(UseArgs {
                wallet_id,
                key_index,
            }) => {
                assert_eq!(wallet_id.to_string(), WALLET);
                assert_eq!(key_index, 0);
            }
            _ => panic!("expected a use command"),
        }
    }

    #[test]
    fn flags_win_over_the_profile_table() {
        let profile = GpgProfile {
            wallet_id: Uuid::parse_str(WALLET).expect("test wallet id should parse"),
            key_index: 4,
        };

        let from_profile = target_of(["gpg", "keys", "list"])
            .resolve(Some(profile))
            .expect("the profile should supply the wallet");
        assert_eq!(
            from_profile,
            Target {
                wallet_id: profile.wallet_id,
                key_index: Some(4),
            }
        );

        let parsed = GpgParser::try_parse_from([
            "gpg",
            "keys",
            "list",
            "--wallet-id",
            OTHER_WALLET,
            "--key-index",
            "1",
        ])
        .expect("target flags should parse");
        let GpgCommand::Keys {
            command: KeysCommand::List(target),
        } = parsed.command
        else {
            panic!("expected a keys list command")
        };
        let from_flags = target
            .resolve(Some(profile))
            .expect("flags alone should resolve a target");
        assert_eq!(
            from_flags,
            Target {
                wallet_id: Uuid::parse_str(OTHER_WALLET).expect("test wallet id should parse"),
                key_index: Some(1),
            }
        );
    }

    /// Clap owns the user ID invariant, so an empty value fails during
    /// parsing with the usage exit code and a message that names the flag.
    #[test]
    fn an_empty_user_id_is_rejected_during_parsing() {
        let Err(error) = GpgParser::try_parse_from([
            "gpg",
            "keys",
            "create",
            "--wallet-id",
            WALLET,
            "--user-id",
            "",
        ]) else {
            panic!("an empty user ID should not parse")
        };
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            error
                .get(ContextKind::InvalidArg)
                .map(ToString::to_string)
                .as_deref(),
            Some("--user-id <USER_ID>")
        );
        assert_eq!(
            error.to_string().lines().next(),
            Some(
                r"error: invalid value '' for '--user-id <USER_ID>': OpenPGP identity has no user ID"
            )
        );
    }

    /// `keys create` names the slot with its own flag, so the flag that
    /// names a key to act on is not accepted there.
    #[test]
    fn keys_create_takes_an_index_flag_of_its_own() {
        let parsed = GpgParser::try_parse_from([
            "gpg",
            "keys",
            "create",
            "--wallet-id",
            WALLET,
            "--at-index",
            "2",
            "--user-id",
            "Ada <ada@example.com>",
        ])
        .expect("the create flags should parse");
        let GpgCommand::Keys {
            command:
                KeysCommand::Create(CreateArgs {
                    wallet: WalletArgs { wallet_id },
                    at_index,
                    user_id,
                }),
        } = parsed.command
        else {
            panic!("expected a keys create command")
        };
        assert_eq!(wallet_id.map(|id| id.to_string()).as_deref(), Some(WALLET));
        assert_eq!(at_index, Some(2));
        assert_eq!(user_id.as_str(), "Ada <ada@example.com>");

        let Err(error) = GpgParser::try_parse_from([
            "gpg",
            "keys",
            "create",
            "--wallet-id",
            WALLET,
            "--key-index",
            "2",
            "--user-id",
            "Ada <ada@example.com>",
        ]) else {
            panic!("--key-index should not parse on keys create")
        };
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn a_target_without_a_wallet_names_every_way_to_supply_one() {
        let error = target_of(["gpg", "keys", "list"])
            .resolve(None)
            .expect_err("no wallet should be an error");
        let invalid = error
            .downcast_ref::<InvalidInput>()
            .expect("no wallet is invalid input");
        assert_eq!(
            invalid.0,
            "no wallet selected; pass --wallet-id, set TK_GPG_WALLET_ID, or run tk gpg use"
        );
    }
}
