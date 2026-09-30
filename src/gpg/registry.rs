//! The table of `OpenPGP` keys tk can sign with, keyed by fingerprint. The
//! fingerprint is a function of the entry's point and creation time, so an
//! entry is checked against its own key when the table is read and cannot
//! name a key other than the one it describes.

use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    mem,
    path::Path,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::{InvalidInput, Malformed},
    wire::openpgp::{
        entity::{OpenPgpKey, SigningKey, UserId},
        key::{Fingerprint, parse_point_hex},
    },
};

const LONG_KEY_ID_CHARS: usize = 16;
const FINGERPRINT_CHARS: usize = 40;

/// A key as `user.signingkey` or `--key` names it: the hex tail of a
/// fingerprint, from a long key ID up to the whole fingerprint. `GnuPG`'s
/// grouping into fours and trailing "!" are normalized away.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SigningKeyName(String);

#[derive(Debug, thiserror::Error)]
#[error(
    "expected a fingerprint or long key ID of {LONG_KEY_ID_CHARS} to {FINGERPRINT_CHARS} hex characters"
)]
pub struct SigningKeyNameError;

impl FromStr for SigningKeyName {
    type Err = SigningKeyNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let value: String = value
            .strip_suffix('!')
            .unwrap_or(value)
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        ((LONG_KEY_ID_CHARS..=FINGERPRINT_CHARS).contains(&value.len())
            && value.chars().all(|c| c.is_ascii_hexdigit()))
        .then_some(Self(value))
        .ok_or(SigningKeyNameError)
    }
}

impl Display for SigningKeyName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl SigningKeyName {
    pub(in crate::gpg) fn as_str(&self) -> &str {
        &self.0
    }

    pub(in crate::gpg) fn matches_fingerprint(&self, fingerprint: &Fingerprint) -> bool {
        fingerprint.ends_with(&self.0)
    }
}

#[derive(Debug)]
pub enum KeyName {
    Suffix(SigningKeyName),
    UserId(String),
}

impl KeyName {
    fn matches(&self, key: &OpenPgpKey) -> bool {
        match self {
            Self::Suffix(name) => name.matches_fingerprint(&key.signing.fingerprint()),
            Self::UserId(user_id) => key.user_id.as_str() == user_id,
        }
    }
}

impl From<SigningKeyName> for KeyName {
    fn from(name: SigningKeyName) -> Self {
        Self::Suffix(name)
    }
}

impl From<String> for KeyName {
    fn from(value: String) -> Self {
        match value.parse() {
            Ok(name) => Self::Suffix(name),
            Err(SigningKeyNameError) => Self::UserId(value.trim().to_string()),
        }
    }
}

impl Display for KeyName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suffix(name) => name.fmt(f),
            Self::UserId(user_id) => f.write_str(user_id),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    Registry,
    Wallet(Uuid),
}

impl Display for Scope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry => f.write_str("the registry"),
            Self::Wallet(wallet_id) => write!(f, "wallet {wallet_id}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("{scope} holds no OpenPGP keys")]
    Empty { scope: Scope },
    #[error("{scope} holds {count} OpenPGP keys and none was named")]
    Unnamed { scope: Scope, count: usize },
    #[error("no OpenPGP key in {scope} matches signing key {requested}")]
    NoMatch { scope: Scope, requested: KeyName },
    #[error("signing key {requested} matches several OpenPGP keys in {scope}")]
    Ambiguous { scope: Scope, requested: KeyName },
}

pub fn select<T>(
    scope: Scope,
    keys: impl IntoIterator<Item = T>,
    key: impl Fn(&T) -> &OpenPgpKey,
    requested: Option<KeyName>,
) -> Result<T, SelectError> {
    select_split(scope, keys, key, requested).0
}

fn select_split<T>(
    scope: Scope,
    keys: impl IntoIterator<Item = T>,
    key: impl Fn(&T) -> &OpenPgpKey,
    requested: Option<KeyName>,
) -> (Result<T, SelectError>, Vec<T>) {
    crate::registry::select_split(
        keys,
        requested,
        |requested, item| requested.matches(key(item)),
        || SelectError::Empty { scope },
        |count| SelectError::Unnamed { scope, count },
        |requested| SelectError::NoMatch { scope, requested },
        |requested| SelectError::Ambiguous { scope, requested },
    )
}

pub struct GpgKeyEntry {
    pub organization_id: Uuid,
    pub wallet_id: Uuid,
    pub wallet_account_id: String,
    pub key: OpenPgpKey,
}

impl GpgKeyEntry {
    pub fn fingerprint(&self) -> Fingerprint {
        self.key.signing.fingerprint()
    }
}

/// The persisted shape of one entry, kept separate from [`GpgKeyEntry`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredGpgKey {
    organization_id: Uuid,
    wallet_id: Uuid,
    wallet_account_id: String,
    user_id: String,
    /// The uncompressed P-256 signing point, hex.
    public_key: String,
    /// Unix seconds.
    created: u32,
}

impl From<GpgKeyEntry> for StoredGpgKey {
    fn from(entry: GpgKeyEntry) -> Self {
        let GpgKeyEntry {
            organization_id,
            wallet_id,
            wallet_account_id,
            key:
                OpenPgpKey {
                    user_id,
                    signing: SigningKey { point, created },
                },
        } = entry;
        Self {
            organization_id,
            wallet_id,
            wallet_account_id,
            user_id: user_id.into_string(),
            public_key: hex::encode(point.as_bytes()),
            created,
        }
    }
}

pub struct GpgKeyTable(BTreeMap<Fingerprint, GpgKeyEntry>);

impl GpgKeyTable {
    pub fn from_stored(
        stored: BTreeMap<String, StoredGpgKey>,
        path: &Path,
    ) -> anyhow::Result<Self> {
        let mut table = BTreeMap::new();
        for (key, entry) in stored {
            let malformed = |reason: &str| {
                format!(
                    "invalid gpg_keys entry {key} in {}: {reason}",
                    path.display()
                )
            };
            let fingerprint: Fingerprint = key.parse().map_err(|error| {
                Malformed::new(malformed("the key is not a fingerprint"), error)
            })?;
            let StoredGpgKey {
                organization_id,
                wallet_id,
                wallet_account_id,
                user_id,
                public_key,
                created,
            } = entry;
            let point = parse_point_hex(&public_key).map_err(|error| {
                Malformed::new(
                    malformed("public_key is not an uncompressed P-256 point"),
                    error,
                )
            })?;
            let user_id = UserId::parse(user_id).map_err(|error| {
                Malformed::new(malformed("user_id is not an OpenPGP user ID"), error)
            })?;
            let entry = GpgKeyEntry {
                organization_id,
                wallet_id,
                wallet_account_id,
                key: OpenPgpKey {
                    user_id,
                    signing: SigningKey { point, created },
                },
            };
            if entry.fingerprint() != fingerprint {
                return Err(InvalidInput(malformed(
                    "public_key and created do not produce this fingerprint",
                ))
                .into());
            }
            if table.insert(fingerprint, entry).is_some() {
                return Err(
                    InvalidInput(malformed("duplicates the fingerprint of another entry")).into(),
                );
            }
        }
        Ok(Self(table))
    }

    pub fn into_stored(self) -> BTreeMap<String, StoredGpgKey> {
        self.0
            .into_iter()
            .map(|(fingerprint, entry)| (fingerprint.to_string(), entry.into()))
            .collect()
    }

    pub fn insert(&mut self, entry: GpgKeyEntry) {
        self.0.insert(entry.fingerprint(), entry);
    }

    pub fn into_entries(self) -> impl Iterator<Item = GpgKeyEntry> {
        self.0.into_values()
    }

    pub fn select(self, requested: Option<KeyName>) -> Result<GpgKeyEntry, SelectError> {
        select(
            Scope::Registry,
            self.0.into_values(),
            |entry| &entry.key,
            requested,
        )
    }

    pub fn remove(&mut self, name: SigningKeyName) -> Result<GpgKeyEntry, SelectError> {
        let (selected, rest) = select_split(
            Scope::Registry,
            mem::take(&mut self.0),
            |(_, entry): &(Fingerprint, GpgKeyEntry)| &entry.key,
            Some(name.into()),
        );
        self.0 = rest.into_iter().collect();
        selected.map(|(_, entry)| entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_with_groups_or_a_trailing_bang_is_the_same_name() {
        let full = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
        let grouped = full
            .as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        for requested in [
            format!("{full}!"),
            format!("{grouped}!"),
            grouped,
            full.to_ascii_lowercase(),
        ] {
            assert_eq!(
                requested.parse::<SigningKeyName>().ok(),
                Some(SigningKeyName(full.to_string())),
                "{requested:?} should normalize to the full fingerprint"
            );
        }
    }

    #[test]
    fn a_name_longer_than_a_fingerprint_is_a_user_id() {
        let long = "FEDCBA9876543210FEDCBA9876543210FEDCBA980";
        long.parse::<SigningKeyName>().unwrap_err();
        assert!(matches!(
            KeyName::from(long.to_string()),
            KeyName::UserId(user_id) if user_id == long
        ));
    }
}
