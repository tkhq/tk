//! The table of OpenPGP keys tk can sign with, keyed by fingerprint. The
//! fingerprint is a function of the entry's point and creation time, so an
//! entry is checked against its own key when the table is read and cannot
//! name a key other than the one it describes.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use turnkey_auth::openpgp::entity::{OpenPgpKey, SigningKey, UserId};
use turnkey_auth::openpgp::key::{fingerprint_hex, parse_point_hex};
use uuid::Uuid;

use crate::errors::InvalidInput;

/// An OpenPGP v4 fingerprint, which is also the table key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fingerprint([u8; 20]);

impl Fingerprint {
    /// GnuPG matches a long key ID or partial fingerprint as a hex suffix.
    fn ends_with(&self, suffix: &str) -> bool {
        self.to_string().ends_with(suffix)
    }
}

impl From<SigningKey> for Fingerprint {
    fn from(key: SigningKey) -> Self {
        Self(key.fingerprint())
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&fingerprint_hex(&self.0))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("expected a 40 character hex fingerprint")]
pub struct FingerprintError;

impl FromStr for Fingerprint {
    type Err = FingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(value).map_err(|_| FingerprintError)?;
        bytes.try_into().map(Self).map_err(|_| FingerprintError)
    }
}

const LONG_KEY_ID_CHARS: usize = 16;

/// A key as `user.signingkey` or `--key` names it: the hex tail of a
/// fingerprint, at least a long key ID. GnuPG's grouping into fours and
/// trailing "!" are normalized away.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SigningKeyName(String);

#[derive(Debug, thiserror::Error)]
#[error("expected a fingerprint or long key ID of at least {LONG_KEY_ID_CHARS} hex characters")]
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
        (value.len() >= LONG_KEY_ID_CHARS && value.chars().all(|c| c.is_ascii_hexdigit()))
            .then_some(Self(value))
            .ok_or(SigningKeyNameError)
    }
}

impl Display for SigningKeyName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone)]
pub struct GpgKeyEntry {
    pub organization_id: Uuid,
    pub wallet_id: Uuid,
    pub wallet_account_id: String,
    pub key: OpenPgpKey,
}

impl GpgKeyEntry {
    pub fn fingerprint(&self) -> Fingerprint {
        self.key.signing.into()
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

#[derive(Default)]
pub struct GpgKeyTable(BTreeMap<Fingerprint, GpgKeyEntry>);

/// States the fact alone; the entry point adds the remediation.
#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("no OpenPGP keys are registered")]
    Empty,
    #[error("{count} OpenPGP keys are registered and none was named")]
    Unnamed { count: usize },
    #[error("no registered OpenPGP key matches signing key {requested}")]
    NotRegistered { requested: String },
    #[error("signing key {requested} matches several registered OpenPGP keys")]
    Ambiguous { requested: String },
}

impl GpgKeyTable {
    /// Rejects an entry whose key does not produce its fingerprint; `path`
    /// names the file in the error.
    pub fn from_stored(
        stored: BTreeMap<String, StoredGpgKey>,
        path: &Path,
    ) -> Result<Self, InvalidInput> {
        let mut table = BTreeMap::new();
        for (key, entry) in stored {
            let malformed = |reason: &str| {
                InvalidInput(format!(
                    "invalid gpg_keys entry {key} in {}: {reason}",
                    path.display()
                ))
            };
            let fingerprint: Fingerprint = key
                .parse()
                .map_err(|_| malformed("the key is not a fingerprint"))?;
            let StoredGpgKey {
                organization_id,
                wallet_id,
                wallet_account_id,
                user_id,
                public_key,
                created,
            } = entry;
            let point = parse_point_hex(&public_key)
                .map_err(|_| malformed("public_key is not an uncompressed P-256 point"))?;
            let user_id = UserId::parse(user_id)
                .map_err(|_| malformed("user_id is not an OpenPGP user ID"))?;
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
                return Err(malformed(
                    "public_key and created do not produce this fingerprint",
                ));
            }
            table.insert(fingerprint, entry);
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

    pub fn select(mut self, name: Option<&SigningKeyName>) -> Result<GpgKeyEntry, SelectError> {
        match name {
            None => self.only(),
            Some(name) => self.remove(name),
        }
    }

    /// The entry git asked for with `-u`: `user.signingkey`, or the committer
    /// ident when that is unset. A hex value of at least a long key ID
    /// matches a fingerprint suffix; any other value must equal a user ID
    /// exactly. A value that names no entry fails rather than falling back;
    /// only a call with no `-u` at all takes the only entry.
    pub fn select_for_git(mut self, requested: Option<&str>) -> Result<GpgKeyEntry, SelectError> {
        let Some(requested) = requested else {
            return self.only();
        };
        // An empty table must say to create a key rather than that no key
        // matches, so it is answered before the value is compared.
        if self.0.is_empty() {
            return Err(SelectError::Empty);
        }
        let requested = requested.trim();
        let fingerprint = match requested.parse::<SigningKeyName>() {
            Ok(name) => self.find(requested, |fingerprint, _| fingerprint.ends_with(&name.0)),
            Err(SigningKeyNameError) => self.find(requested, |_, entry| {
                entry.key.user_id.as_str() == requested
            }),
        }?;
        Ok(self.take(fingerprint))
    }

    pub fn remove(&mut self, name: &SigningKeyName) -> Result<GpgKeyEntry, SelectError> {
        let fingerprint = self.find(&name.0, |fingerprint, _| fingerprint.ends_with(&name.0))?;
        Ok(self.take(fingerprint))
    }

    fn only(self) -> Result<GpgKeyEntry, SelectError> {
        let count = self.0.len();
        match count {
            0 => Err(SelectError::Empty),
            1 => Ok(self.0.into_values().next().expect("one entry")),
            _ => Err(SelectError::Unnamed { count }),
        }
    }

    fn find(
        &self,
        requested: &str,
        matches: impl Fn(&Fingerprint, &GpgKeyEntry) -> bool,
    ) -> Result<Fingerprint, SelectError> {
        let mut matching = self
            .0
            .iter()
            .filter(|(fingerprint, entry)| matches(fingerprint, entry))
            .map(|(fingerprint, _)| *fingerprint);
        let Some(fingerprint) = matching.next() else {
            return Err(SelectError::NotRegistered {
                requested: requested.to_string(),
            });
        };
        if matching.next().is_some() {
            return Err(SelectError::Ambiguous {
                requested: requested.to_string(),
            });
        }
        Ok(fingerprint)
    }

    fn take(&mut self, fingerprint: Fingerprint) -> GpgKeyEntry {
        self.0.remove(&fingerprint).expect("the key was just found")
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
}
