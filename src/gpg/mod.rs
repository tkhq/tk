//! The `tk gpg` command family. Signing and export need no wallet read: the
//! registered entry carries the key, and its organization selects the
//! credential.

use std::borrow::Cow;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::wire::openpgp::entity::{UserId, armored_detached_signature, export_public_key};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use tokio::fs;
use uuid::Uuid;

use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;

use crate::auth::{self, AuthOptions, build_turnkey_client};
use crate::errors::{InvalidInput, Malformed, MissingResource};
use crate::outcome::Outcome;

use registry::{GpgKeyEntry, KeyName, Scope, SelectError, SigningKeyName};
use signer::TurnkeySigner;

mod agent;
mod keys;
pub mod registry;
pub mod shim;
mod signer;

#[derive(Debug, Subcommand)]
pub enum GpgCommand {
    /// Manage PGP keys held as wallet accounts.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Write an armored detached signature for a file.
    Sign(SignArgs),
    /// Serve registered PGP keys over a Unix socket.
    Agent(agent::Args),
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Create a PGP signing key for a user ID as wallet accounts and register it.
    ///
    /// A wallet never gets a second key for the same user ID; the existing
    /// one is registered instead.
    Create(CreateArgs),
    /// Register an existing PGP key from a wallet.
    Add(AddArgs),
    /// Forget a registered key.
    ///
    /// The wallet accounts are kept.
    Remove(RemoveArgs),
    /// List the registered keys.
    List(ListArgs),
    /// Print the armored public key block of a registered key.
    ///
    /// The self-certification is signed with the key, so a policy that
    /// requires approval blocks the export.
    Export(KeyArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Wallet to create the accounts in.
    #[arg(long)]
    wallet_id: Uuid,
    /// The PGP user ID, for example "Ada Lovelace <ada@example.com>".
    #[arg(long, value_parser = |value: &str| UserId::parse(value.to_owned()))]
    user_id: UserId,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Wallet holding the key.
    #[arg(long)]
    wallet_id: Uuid,
    /// Fingerprint or long key ID of the key.
    ///
    /// Required when the wallet holds more than one PGP key.
    #[arg(long)]
    key: Option<SigningKeyName>,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Fingerprint or long key ID of the key.
    #[arg(long)]
    key: SigningKeyName,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// List the PGP keys in this wallet instead of the registered keys.
    #[arg(long)]
    wallet_id: Option<Uuid>,
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    /// Fingerprint or long key ID of the key.
    #[arg(long)]
    key: Option<SigningKeyName>,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    key: KeyArgs,
    /// File to sign; with no file, tk reads stdin.
    #[arg(long)]
    file: Option<PathBuf>,
    /// Write the armored signature here instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
struct KeySummary {
    key_index: u32,
    fingerprint: String,
    user_id: String,
    created: u32,
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
pub struct KeyRegistered {
    organization_id: Uuid,
    wallet_id: Uuid,
    #[serde(flatten)]
    key: KeySummary,
}

impl Display for KeyRegistered {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "registered OpenPGP key {} (key index {}) for {}",
            self.key.fingerprint, self.key.key_index, self.key.user_id
        )
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct RegisteredKey {
    pub fingerprint: String,
    pub user_id: String,
    pub organization_id: Uuid,
    pub wallet_id: Uuid,
    pub wallet_account_id: String,
    pub created: u32,
}

impl From<GpgKeyEntry> for RegisteredKey {
    fn from(entry: GpgKeyEntry) -> Self {
        let fingerprint = entry.fingerprint().to_string();
        let GpgKeyEntry {
            organization_id,
            wallet_id,
            wallet_account_id,
            key,
        } = entry;
        Self {
            fingerprint,
            user_id: key.user_id.into_string(),
            organization_id,
            wallet_id,
            wallet_account_id,
            created: key.signing.created,
        }
    }
}

impl Display for RegisteredKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  {}  {}  {}",
            self.fingerprint, self.organization_id, self.wallet_id, self.user_id
        )
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct KeysRegistered {
    keys: Vec<RegisteredKey>,
}

impl Display for KeysRegistered {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_lines(f, &self.keys, "no OpenPGP keys registered")
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct KeysListed {
    wallet_id: Uuid,
    keys: Vec<KeySummary>,
}

impl Display for KeysListed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_lines(
            f,
            &self.keys,
            format_args!("no OpenPGP keys in wallet {}", self.wallet_id),
        )
    }
}

/// One item per line with no trailing newline, or `empty` for none. The
/// output boundary adds the final newline.
fn write_lines(f: &mut Formatter<'_>, items: &[impl Display], empty: impl Display) -> fmt::Result {
    let Some((last, rest)) = items.split_last() else {
        return write!(f, "{empty}");
    };
    for item in rest {
        writeln!(f, "{item}")?;
    }
    write!(f, "{last}")
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyExported {
    fingerprint: String,
    armored: String,
}

impl Display for PublicKeyExported {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // The armor ends in a newline and the output boundary adds one.
        f.write_str(self.armored.trim_end_matches('\n'))
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct SignatureCreated {
    fingerprint: String,
    armored: String,
    output: Option<PathBuf>,
}

impl Display for SignatureCreated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.output {
            Some(_) => Ok(()),
            None => f.write_str(self.armored.trim_end_matches('\n')),
        }
    }
}

fn selection_error(error: SelectError, unnamed_remedy: &str) -> anyhow::Error {
    let remedy: Cow<'_, str> = match &error {
        SelectError::Empty {
            scope: Scope::Registry,
        } => "create one with tk gpg keys create or register one with tk gpg keys add".into(),
        SelectError::Empty {
            scope: Scope::Wallet(_),
        } => "create one with tk gpg keys create".into(),
        SelectError::Unnamed { .. } => unnamed_remedy.into(),
        SelectError::NoMatch {
            scope: Scope::Registry,
            requested,
        } => format!("register it with tk gpg keys add --wallet-id <wallet> --key {requested}")
            .into(),
        SelectError::NoMatch {
            scope: Scope::Wallet(_),
            requested,
        } => return MissingResource::new("OpenPGP key", requested.to_string()).into(),
        SelectError::Ambiguous { .. } => "use a longer fingerprint".into(),
    };
    InvalidInput(format!("{error}; {remedy}")).into()
}

async fn open_wallet(
    options: &AuthOptions,
    wallet_id: Uuid,
) -> Result<(Uuid, TurnkeyClient<TurnkeyP256ApiKey>, keys::WalletKeys)> {
    let auth = auth::resolve(options).await?;
    let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
    let wallet = keys::read_wallet(&client, auth.org_id, wallet_id).await?;
    Ok((auth.org_id, client, wallet))
}

pub async fn run(command: GpgCommand, options: &AuthOptions) -> Result<Outcome> {
    match command {
        GpgCommand::Agent(args) => agent::run(args, options).await,
        GpgCommand::Keys { command } => run_keys(command, options).await,
        GpgCommand::Sign(SignArgs {
            key: KeyArgs { key },
            file,
            output,
        }) => {
            let data = match &file {
                Some(path) => fs::read(path)
                    .await
                    .with_context(|| format!("read {} to sign", path.display()))?,
                None => {
                    let mut bytes = Vec::new();
                    io::stdin()
                        .read_to_end(&mut bytes)
                        .context("read the payload to sign from stdin")?;
                    bytes
                }
            };
            let (entry, client) = select_registered(options, key).await?;
            let signer = TurnkeySigner::new(&client, entry.organization_id);
            let now = unix_now()?;
            let signature =
                armored_detached_signature(entry.key.signing, &data, &signer, now).await?;
            let armored = signature.into_string();
            if let Some(path) = &output {
                fs::write(path, &armored)
                    .await
                    .with_context(|| format!("write the signature to {}", path.display()))?;
            }
            Ok(Outcome::GpgSignatureCreated(SignatureCreated {
                fingerprint: entry.fingerprint().to_string(),
                armored,
                output,
            }))
        }
    }
}

async fn run_keys(command: KeysCommand, options: &AuthOptions) -> Result<Outcome> {
    match command {
        KeysCommand::List(ListArgs { wallet_id: None }) => {
            let table = auth::load_gpg_keys().await?;
            Ok(Outcome::GpgKeysRegistered(KeysRegistered {
                keys: table.into_entries().map(RegisteredKey::from).collect(),
            }))
        }
        KeysCommand::Remove(RemoveArgs { key }) => {
            let removed = auth::remove_gpg_key(key)
                .await?
                .map_err(|error| selection_error(error, "name one with a fingerprint"))?;
            Ok(Outcome::GpgKeyRemoved(removed.into()))
        }
        KeysCommand::List(ListArgs {
            wallet_id: Some(wallet_id),
        }) => {
            let (
                _,
                _,
                keys::WalletKeys {
                    keys: existing,
                    occupied: _,
                },
            ) = open_wallet(options, wallet_id).await?;
            Ok(Outcome::GpgKeysListed(KeysListed {
                wallet_id,
                keys: existing.into_iter().map(KeySummary::from).collect(),
            }))
        }
        KeysCommand::Create(CreateArgs { wallet_id, user_id }) => {
            let (
                organization_id,
                client,
                keys::WalletKeys {
                    keys: existing,
                    occupied,
                },
            ) = open_wallet(options, wallet_id).await?;
            let selected = registry::select(
                Scope::Wallet(wallet_id),
                existing,
                |key| &key.key,
                Some(KeyName::UserId(user_id.as_str().to_owned())),
            );
            let (key, outcome): (_, fn(KeyRegistered) -> Outcome) = match selected {
                Ok(key) => (key, Outcome::GpgKeyRegistered),
                Err(SelectError::Empty { .. } | SelectError::NoMatch { .. }) => {
                    let index = keys::next_free_index(&occupied);
                    let key = keys::create_key(&client, organization_id, wallet_id, index, user_id)
                        .await?;
                    (key, Outcome::GpgKeyCreated)
                }
                Err(error @ (SelectError::Unnamed { .. } | SelectError::Ambiguous { .. })) => {
                    return Err(selection_error(error, "name one with --key"));
                }
            };
            Ok(outcome(register(organization_id, wallet_id, key).await?))
        }
        KeysCommand::Add(AddArgs { wallet_id, key }) => {
            let (
                organization_id,
                _,
                keys::WalletKeys {
                    keys: existing,
                    occupied: _,
                },
            ) = open_wallet(options, wallet_id).await?;
            let key = registry::select(
                Scope::Wallet(wallet_id),
                existing,
                |key| &key.key,
                key.map(KeyName::from),
            )
            .map_err(|error| selection_error(error, "name one with --key"))?;
            Ok(Outcome::GpgKeyRegistered(
                register(organization_id, wallet_id, key).await?,
            ))
        }
        KeysCommand::Export(KeyArgs { key }) => {
            let (entry, client) = select_registered(options, key).await?;
            let signer = TurnkeySigner::new(&client, entry.organization_id);
            let armored = export_public_key(&entry.key, &signer).await?;
            Ok(Outcome::GpgPublicKeyExported(PublicKeyExported {
                fingerprint: entry.fingerprint().to_string(),
                armored,
            }))
        }
    }
}

async fn select_registered(
    options: &AuthOptions,
    key: Option<SigningKeyName>,
) -> Result<(GpgKeyEntry, TurnkeyClient<TurnkeyP256ApiKey>)> {
    auth::open_gpg_key(options, key.map(KeyName::from))
        .await?
        .map_err(|error| selection_error(error, "name one with --key"))
}

async fn register(
    organization_id: Uuid,
    wallet_id: Uuid,
    key: keys::GpgKey,
) -> Result<KeyRegistered> {
    let keys::GpgKey {
        index,
        account_id,
        key,
    } = key;
    let entry = GpgKeyEntry {
        organization_id,
        wallet_id,
        wallet_account_id: account_id,
        key,
    };
    let registered = KeyRegistered {
        organization_id: entry.organization_id,
        wallet_id: entry.wallet_id,
        key: KeySummary {
            key_index: index,
            fingerprint: entry.fingerprint().to_string(),
            user_id: entry.key.user_id.as_str().to_owned(),
            created: entry.key.signing.created,
        },
    };
    auth::register_gpg_key(entry).await?;
    Ok(registered)
}

/// Unix seconds as the `u32` `OpenPGP` creation time field, which overflows in
/// 2106 along with the format itself.
fn unix_now() -> Result<u32> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Malformed::new("the system clock reads a time before 1970", error))?;
    Ok(since.as_secs() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct GpgParser {
        #[command(subcommand)]
        command: GpgCommand,
    }

    const WALLET: &str = "9a1e2c4b-0000-4000-8000-000000000001";

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
        assert_eq!(
            error.to_string().lines().next(),
            Some(
                r"error: invalid value '' for '--user-id <USER_ID>': OpenPGP identity has no user ID"
            )
        );
    }

    #[test]
    fn a_key_shorter_than_a_long_key_id_is_rejected_during_parsing() {
        let Err(error) = GpgParser::try_parse_from(["gpg", "sign", "--key", "0123456789ABCDE"])
        else {
            panic!("a short key should not parse")
        };
        assert_eq!(
            error.to_string().lines().next(),
            Some(
                r"error: invalid value '0123456789ABCDE' for '--key <KEY>': expected a fingerprint or long key ID of 16 to 40 hex characters"
            )
        );
    }
}
