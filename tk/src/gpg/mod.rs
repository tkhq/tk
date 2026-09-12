//! The `tk gpg` command family. Signing and export need no wallet read: the
//! registered entry carries the key, and its organization selects the
//! credential.

use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use tokio::fs;
use turnkey_auth::openpgp::entity::{
    UserId, armor_signature, detached_signature, export_public_key,
};
use uuid::Uuid;

use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;

use crate::auth::{self, AuthOptions, build_turnkey_client};
use crate::errors::{InvalidInput, MissingResource};
use crate::outcome::Outcome;

use registry::{GpgKeyEntry, SigningKeyName};
use signer::TurnkeySigner;

pub mod keys;
pub mod registry;
pub mod shim;
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
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Create a signing account for a user ID and register the key.
    Create(CreateArgs),
    /// Register an existing key from a wallet so git and tk gpg sign can use it.
    Add(AddArgs),
    /// Forget a registered key. The wallet accounts are kept.
    Remove(RemoveArgs),
    /// List the registered keys, or the OpenPGP keys in one wallet.
    List(ListArgs),
    /// Print the armored public key block of a registered key. Signs the self certification with the key, so a policy that requires approval blocks it.
    Export(KeyArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Wallet to create the accounts in.
    #[arg(long)]
    wallet_id: Uuid,
    /// The OpenPGP user ID, for example "Ada Lovelace <ada@example.com>".
    #[arg(long, value_parser = |value: &str| UserId::parse(value.to_owned()))]
    user_id: UserId,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Wallet holding the key.
    #[arg(long)]
    wallet_id: Uuid,
    /// Fingerprint or long key ID of the key. Needed when the wallet holds
    /// more than one.
    #[arg(long)]
    key: Option<SigningKeyName>,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Fingerprint or long key ID of the registered key.
    key: SigningKeyName,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// List the OpenPGP keys in this wallet instead of the registered keys.
    #[arg(long)]
    wallet_id: Option<Uuid>,
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    /// Fingerprint or long key ID of a registered key.
    #[arg(long)]
    key: Option<SigningKeyName>,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    key: KeyArgs,
    /// File to sign. With no file, tk reads stdin.
    file: Option<PathBuf>,
    /// Write the armored signature here instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
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

/// The record of `keys create` and `keys add`; the outcome reason tells
/// them apart, and a create prefixes this text with "created and".
#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct KeyRegistered {
    pub organization_id: Uuid,
    pub wallet_id: Uuid,
    #[serde(flatten)]
    pub key: KeySummary,
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
    pub keys: Vec<RegisteredKey>,
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
    pub wallet_id: Uuid,
    pub keys: Vec<KeySummary>,
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
    pub fingerprint: String,
    pub armored: String,
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
    pub fingerprint: String,
    pub armored: String,
    pub output: Option<PathBuf>,
}

impl Display for SignatureCreated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.output {
            Some(_) => Ok(()),
            None => f.write_str(self.armored.trim_end_matches('\n')),
        }
    }
}

/// Adds the remediation; the entry point supplies `unnamed_remedy` because
/// the way to name one key among several differs between git and tk.
pub fn registry_selection_error(
    error: registry::SelectError,
    unnamed_remedy: &str,
) -> anyhow::Error {
    use registry::SelectError;
    match &error {
        SelectError::Empty => InvalidInput(format!(
            "{error}; create one with tk gpg keys create or register one with tk gpg keys add"
        ))
        .into(),
        SelectError::Unnamed { .. } => InvalidInput(format!("{error}; {unnamed_remedy}")).into(),
        SelectError::NotRegistered { requested } => InvalidInput(format!(
            "{error}; register it with tk gpg keys add --wallet-id <wallet> --key {requested}"
        ))
        .into(),
        SelectError::Ambiguous { .. } => {
            InvalidInput(format!("{error}; use a longer fingerprint")).into()
        }
    }
}

fn wallet_selection_error(error: keys::SelectError) -> anyhow::Error {
    match &error {
        keys::SelectError::NoKeys { .. } => {
            InvalidInput(format!("{error}; create one with tk gpg keys create")).into()
        }
        keys::SelectError::Ambiguous { .. } => {
            InvalidInput(format!("{error}; name one with --key")).into()
        }
        keys::SelectError::NoMatch { name, .. } => {
            MissingResource::new("OpenPGP key", name.to_string()).into()
        }
        keys::SelectError::SeveralMatch { .. } => InvalidInput(error.to_string()).into(),
    }
}

pub(super) async fn client_for_entry(
    options: &AuthOptions,
    entry: &GpgKeyEntry,
) -> Result<(TurnkeyClient<TurnkeyP256ApiKey>, String)> {
    let auth = auth::resolve_for_organization(options, entry.organization_id)
        .await
        .with_context(|| {
            format!(
                "select a credential for OpenPGP key {}",
                entry.fingerprint()
            )
        })?;
    Ok((
        build_turnkey_client(auth.stamper, &auth.api_base_url)?,
        auth.org_id,
    ))
}

pub async fn run(command: GpgCommand, options: &AuthOptions) -> Result<Outcome> {
    // Everything local that can fail, the registry read and the payload to
    // sign, happens before the first credential read.
    match command {
        GpgCommand::Keys {
            command: KeysCommand::List(ListArgs { wallet_id: None }),
        } => {
            let table = auth::load_gpg_keys(options).await?;
            Ok(Outcome::GpgKeysRegistered(KeysRegistered {
                keys: table.into_entries().map(RegisteredKey::from).collect(),
            }))
        }
        GpgCommand::Keys {
            command: KeysCommand::Remove(RemoveArgs { key }),
        } => {
            let removed = auth::remove_gpg_key(options, &key)
                .await?
                .map_err(|error| registry_selection_error(error, "name one with a fingerprint"))?;
            Ok(Outcome::GpgKeyRemoved(removed.into()))
        }
        GpgCommand::Keys {
            command:
                KeysCommand::List(ListArgs {
                    wallet_id: Some(wallet_id),
                }),
        } => {
            let auth = auth::resolve(options).await?;
            let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
            let existing = keys::read_wallet(&client, &auth.org_id, wallet_id)
                .await?
                .keys;
            Ok(Outcome::GpgKeysListed(KeysListed {
                wallet_id,
                keys: existing.into_iter().map(KeySummary::from).collect(),
            }))
        }
        GpgCommand::Keys {
            command: KeysCommand::Create(CreateArgs { wallet_id, user_id }),
        } => {
            let auth = auth::resolve(options).await?;
            let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
            let occupied = keys::read_wallet(&client, &auth.org_id, wallet_id)
                .await?
                .occupied;
            let index = keys::next_free_index(&occupied);
            let key = keys::create_key(&client, &auth.org_id, wallet_id, index, user_id).await?;
            let key = register(options, auth.organization_id, wallet_id, key).await?;
            Ok(Outcome::GpgKeyCreated(KeyRegistered {
                organization_id: auth.organization_id,
                wallet_id,
                key,
            }))
        }
        GpgCommand::Keys {
            command: KeysCommand::Add(AddArgs { wallet_id, key }),
        } => {
            let auth = auth::resolve(options).await?;
            let client = build_turnkey_client(auth.stamper, &auth.api_base_url)?;
            let existing = keys::read_wallet(&client, &auth.org_id, wallet_id)
                .await?
                .keys;
            let key =
                keys::select(existing, wallet_id, key.as_ref()).map_err(wallet_selection_error)?;
            let key = register(options, auth.organization_id, wallet_id, key).await?;
            Ok(Outcome::GpgKeyRegistered(KeyRegistered {
                organization_id: auth.organization_id,
                wallet_id,
                key,
            }))
        }
        GpgCommand::Keys {
            command: KeysCommand::Export(KeyArgs { key }),
        } => {
            let entry = select_registered(options, key.as_ref()).await?;
            let (client, org_id) = client_for_entry(options, &entry).await?;
            let signer = TurnkeySigner::new(&client, &org_id);
            let armored = export_public_key(&entry.key, &signer).await?;
            Ok(Outcome::GpgPublicKeyExported(PublicKeyExported {
                fingerprint: entry.fingerprint().to_string(),
                armored,
            }))
        }
        GpgCommand::Sign(SignArgs {
            key: KeyArgs { key },
            file,
            output,
        }) => {
            let data = match &file {
                Some(path) => fs::read(path)
                    .await
                    .with_context(|| format!("read {} to sign", path.display()))?,
                // Stdin has no async reader in this build of tokio.
                None => {
                    let mut bytes = Vec::new();
                    io::stdin()
                        .read_to_end(&mut bytes)
                        .context("read the payload to sign from stdin")?;
                    bytes
                }
            };
            let entry = select_registered(options, key.as_ref()).await?;
            let (client, org_id) = client_for_entry(options, &entry).await?;
            let signer = TurnkeySigner::new(&client, &org_id);
            // A detached signature is dated by the clock, unlike the self
            // signature in an export.
            let now = unix_now()?;
            let packet = detached_signature(entry.key.signing, &data, &signer, now).await?;
            let armored = armor_signature(&packet);
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

async fn select_registered(
    options: &AuthOptions,
    key: Option<&SigningKeyName>,
) -> Result<GpgKeyEntry> {
    auth::load_gpg_keys(options)
        .await?
        .select(key)
        .map_err(|error| registry_selection_error(error, "name one with --key"))
}

async fn register(
    options: &AuthOptions,
    organization_id: Uuid,
    wallet_id: Uuid,
    key: keys::GpgKey,
) -> Result<KeySummary> {
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
    let summary = KeySummary {
        key_index: index,
        fingerprint: entry.fingerprint().to_string(),
        user_id: entry.key.user_id.as_str().to_owned(),
        created: entry.key.signing.created,
    };
    auth::register_gpg_key(options, entry).await?;
    Ok(summary)
}

/// Unix seconds as the `u32` OpenPGP creation time field, which overflows in
/// 2106 along with the format itself.
fn unix_now() -> Result<u32> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InvalidInput("the system clock reads a time before 1970".into()))?;
    Ok(since.as_secs() as u32)
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

    #[test]
    fn a_key_shorter_than_a_long_key_id_is_rejected_during_parsing() {
        let Err(error) = GpgParser::try_parse_from(["gpg", "sign", "--key", "0123456789ABCDE"])
        else {
            panic!("a short key should not parse")
        };
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
        assert_eq!(
            error.to_string().lines().next(),
            Some(
                r"error: invalid value '0123456789ABCDE' for '--key <KEY>': expected a fingerprint or long key ID of at least 16 hex characters"
            )
        );
    }
}
