//! Registered SSH signing keys and request-side key names.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    fmt::{self, Display, Formatter},
    mem,
    path::Path,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::{InvalidInput, Malformed},
    registry::{select, select_split},
    wire::ssh::{Ed25519PublicKey, parse_public_key_line},
};

/// An opaque Turnkey private-key identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct PrivateKeyId(String);

impl PrivateKeyId {
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for PrivateKeyId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl FromStr for PrivateKeyId {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_string()))
    }
}

impl Display for PrivateKeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An OpenSSH SHA-256 public-key fingerprint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SshFingerprint(String);

#[derive(Debug, thiserror::Error)]
#[error("expected an SSH fingerprint beginning with SHA256:")]
pub struct SshFingerprintError;

impl FromStr for SshFingerprint {
    type Err = SshFingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let digest = value.strip_prefix("SHA256:").ok_or(SshFingerprintError)?;
        (!digest.is_empty()
            && digest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-')))
        .then(|| Self(value.to_string()))
        .ok_or(SshFingerprintError)
    }
}

impl Display for SshFingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A key name accepted from git or a terminal command.
#[derive(Clone, Debug)]
pub enum SshKeyName {
    Fingerprint(SshFingerprint),
    PublicKey(Ed25519PublicKey),
    PrivateKeyId(PrivateKeyId),
}

impl SshKeyName {
    fn matches(&self, entry: &SshKeyEntry) -> bool {
        match self {
            Self::Fingerprint(fingerprint) => &entry.fingerprint() == fingerprint,
            Self::PublicKey(public_key) => &entry.public_key == public_key,
            Self::PrivateKeyId(private_key_id) => &entry.private_key_id == private_key_id,
        }
    }
}

impl From<String> for SshKeyName {
    fn from(value: String) -> Self {
        if let Ok(fingerprint) = value.parse() {
            Self::Fingerprint(fingerprint)
        } else if let Ok(public_key) = parse_public_key_line(&value) {
            Self::PublicKey(public_key)
        } else {
            Self::PrivateKeyId(value.into())
        }
    }
}

impl FromStr for SshKeyName {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(value.to_string().into())
    }
}

impl Display for SshKeyName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fingerprint(fingerprint) => fingerprint.fmt(f),
            Self::PublicKey(public_key) => f.write_str(&public_key.line()),
            Self::PrivateKeyId(private_key_id) => private_key_id.fmt(f),
        }
    }
}

/// One registered SSH signing key.
#[derive(Clone)]
pub struct SshKeyEntry {
    pub organization_id: Uuid,
    pub private_key_id: PrivateKeyId,
    pub public_key: Ed25519PublicKey,
}

impl SshKeyEntry {
    pub fn fingerprint(&self) -> SshFingerprint {
        SshFingerprint(self.public_key.fingerprint())
    }
}

/// The persisted shape of one SSH key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSshKey {
    organization_id: Uuid,
    private_key_id: String,
    public_key: String,
}

impl From<SshKeyEntry> for StoredSshKey {
    fn from(entry: SshKeyEntry) -> Self {
        let SshKeyEntry {
            organization_id,
            private_key_id,
            public_key,
        } = entry;
        Self {
            organization_id,
            private_key_id: private_key_id.into_string(),
            public_key: public_key.line(),
        }
    }
}

/// A failed selection from the SSH key registry.
#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    #[error("the registry holds no SSH keys")]
    Empty,
    #[error("the registry holds {count} SSH keys and none was named")]
    Unnamed { count: usize },
    #[error("no registered SSH key matches {requested}")]
    NoMatch { requested: SshKeyName },
    #[error("{requested} matches several registered SSH keys")]
    Ambiguous { requested: SshKeyName },
}

/// The validated SSH key registry.
#[derive(Default)]
pub struct SshKeyTable(BTreeMap<SshFingerprint, SshKeyEntry>);

impl SshKeyTable {
    pub fn from_stored(
        stored: BTreeMap<String, StoredSshKey>,
        path: &Path,
    ) -> anyhow::Result<Self> {
        let mut table = BTreeMap::new();
        for (key, stored) in stored {
            let invalid = |reason: &str| {
                InvalidInput(format!(
                    "invalid ssh_keys entry {key} in {}: {reason}",
                    path.display()
                ))
            };
            let fingerprint: SshFingerprint = key.parse().map_err(|error| {
                Malformed::new(invalid("the key is not an SSH fingerprint").0, error)
            })?;
            let StoredSshKey {
                organization_id,
                private_key_id,
                public_key,
            } = stored;
            let public_key = parse_public_key_line(&public_key).map_err(|error| {
                Malformed::new(
                    invalid("public_key is not an ssh-ed25519 public key line").0,
                    error,
                )
            })?;
            let entry = SshKeyEntry {
                organization_id,
                private_key_id: private_key_id.into(),
                public_key,
            };
            if entry.fingerprint() != fingerprint {
                return Err(invalid("public_key does not produce this fingerprint").into());
            }
            table.insert(fingerprint, entry);
        }
        Ok(Self(table))
    }

    pub fn into_stored(self) -> BTreeMap<String, StoredSshKey> {
        self.0
            .into_iter()
            .map(|(fingerprint, entry)| (fingerprint.to_string(), entry.into()))
            .collect()
    }

    pub fn insert(&mut self, entry: SshKeyEntry) {
        self.0.insert(entry.fingerprint(), entry);
    }

    pub fn into_entries(self) -> impl Iterator<Item = SshKeyEntry> {
        self.0.into_values()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn retain_organization(&mut self, organization_id: Uuid) {
        self.0
            .retain(|_, entry| entry.organization_id == organization_id);
    }

    pub fn select(self, requested: Option<SshKeyName>) -> Result<SshKeyEntry, SelectError> {
        select(
            self.0.into_values(),
            requested,
            SshKeyName::matches,
            || SelectError::Empty,
            |count| SelectError::Unnamed { count },
            |requested| SelectError::NoMatch { requested },
            |requested| SelectError::Ambiguous { requested },
        )
    }

    pub fn select_ref(&self, requested: SshKeyName) -> Result<&SshKeyEntry, SelectError> {
        select(
            self.0.values(),
            Some(requested),
            |requested, entry| requested.matches(entry),
            || SelectError::Empty,
            |count| SelectError::Unnamed { count },
            |requested| SelectError::NoMatch { requested },
            |requested| SelectError::Ambiguous { requested },
        )
    }

    pub fn remove(&mut self, requested: SshKeyName) -> Result<SshKeyEntry, SelectError> {
        let (selected, rest) = select_split(
            mem::take(&mut self.0),
            Some(requested),
            |requested: &SshKeyName, (_, entry): &(SshFingerprint, SshKeyEntry)| {
                requested.matches(entry)
            },
            || SelectError::Empty,
            |count| SelectError::Unnamed { count },
            |requested| SelectError::NoMatch { requested },
            |requested| SelectError::Ambiguous { requested },
        );
        self.0 = rest.into_iter().collect();
        selected.map(|(_, entry)| entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORGANIZATION_ID: Uuid = Uuid::from_u128(0x3c0f1d5a_2222_4000_8000_0123456789ab);
    const REGISTRY_PATH: &str = "/tmp/tk.config.toml";

    fn entry(byte: u8, private_key_id: &str) -> SshKeyEntry {
        SshKeyEntry {
            organization_id: ORGANIZATION_ID,
            private_key_id: private_key_id.to_string().into(),
            public_key: Ed25519PublicKey::from_bytes([byte; 32]),
        }
    }

    fn stored(public_key: String) -> StoredSshKey {
        StoredSshKey {
            organization_id: ORGANIZATION_ID,
            private_key_id: "private-key-1".into(),
            public_key,
        }
    }

    fn error(result: anyhow::Result<SshKeyTable>) -> String {
        result
            .err()
            .expect("the registry should be rejected")
            .to_string()
    }

    #[test]
    fn key_names_distinguish_fingerprint_public_key_and_private_key_id() {
        let public_key = Ed25519PublicKey::from_bytes([7; 32]);

        assert!(matches!(
            SshKeyName::from(public_key.fingerprint()),
            SshKeyName::Fingerprint(fingerprint) if fingerprint.to_string() == public_key.fingerprint()
        ));
        assert!(matches!(
            SshKeyName::from(public_key.line()),
            SshKeyName::PublicKey(parsed) if parsed == public_key
        ));
        assert!(matches!(
            SshKeyName::from("private-key-1".to_string()),
            SshKeyName::PrivateKeyId(id) if id.to_string() == "private-key-1"
        ));
    }

    #[test]
    fn stored_entry_must_match_its_fingerprint() {
        let map_key = Ed25519PublicKey::from_bytes([1; 32]).fingerprint();
        let mut entries = BTreeMap::new();
        entries.insert(
            map_key.clone(),
            stored(Ed25519PublicKey::from_bytes([2; 32]).line()),
        );

        assert_eq!(
            error(SshKeyTable::from_stored(entries, Path::new(REGISTRY_PATH))),
            format!(
                "invalid ssh_keys entry {map_key} in {REGISTRY_PATH}: public_key does not produce this fingerprint"
            )
        );
    }

    #[test]
    fn stored_entry_must_be_an_ed25519_public_key_line() {
        let map_key = Ed25519PublicKey::from_bytes([1; 32]).fingerprint();
        let mut entries = BTreeMap::new();
        entries.insert(map_key.clone(), stored("ssh-rsa AAAA".into()));

        assert_eq!(
            error(SshKeyTable::from_stored(entries, Path::new(REGISTRY_PATH))),
            format!(
                "invalid ssh_keys entry {map_key} in {REGISTRY_PATH}: public_key is not an ssh-ed25519 public key line"
            )
        );
    }

    #[test]
    fn selection_covers_empty_unnamed_no_match_and_ambiguous() {
        assert!(matches!(
            SshKeyTable::default().select(None),
            Err(SelectError::Empty)
        ));

        let first = entry(1, "shared-private-key");
        let second = entry(2, "shared-private-key");
        let mut table = SshKeyTable::default();
        table.insert(first.clone());
        table.insert(second.clone());
        assert!(matches!(
            table.select(None),
            Err(SelectError::Unnamed { count: 2 })
        ));

        let mut table = SshKeyTable::default();
        table.insert(first.clone());
        table.insert(second.clone());
        assert!(matches!(
            table.select(Some(SshKeyName::PrivateKeyId("missing".to_string().into()))),
            Err(SelectError::NoMatch { .. })
        ));

        let mut table = SshKeyTable::default();
        table.insert(first);
        table.insert(second);
        assert!(matches!(
            table.select(Some(SshKeyName::PrivateKeyId(
                "shared-private-key".to_string().into()
            ))),
            Err(SelectError::Ambiguous { .. })
        ));
    }

    #[test]
    fn named_selection_accepts_every_supported_name() {
        let selected = entry(9, "private-key-9");
        for requested in [
            SshKeyName::Fingerprint(selected.fingerprint()),
            SshKeyName::PublicKey(selected.public_key),
            SshKeyName::PrivateKeyId(selected.private_key_id.clone()),
        ] {
            let mut table = SshKeyTable::default();
            table.insert(selected.clone());
            let actual = table
                .select(Some(requested))
                .expect("the registered key should match");
            assert_eq!(actual.public_key, selected.public_key);
            assert_eq!(actual.organization_id, selected.organization_id);
            assert_eq!(actual.private_key_id, selected.private_key_id);
        }
    }
}
