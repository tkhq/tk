//! Local parsing for `tk secret`. Everything here runs before credentials are
//! resolved.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    fs::File,
    io::{self, IsTerminal, Read},
    mem::take,
    path::Path,
};

use anyhow::{Context, Result};
use serde::Serialize;
use turnkey_client::generated::{SecretMetadata, immutable::models::v1::KeyValue};
use turnkey_enclave_encrypt::QuorumPublicKey;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{errors::InvalidInput, output::MissingRequiredInput};

const MAX_SECRET_BYTES: usize = 1024 * 1024;

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum SecretRef {
    Id(Uuid),
    Name(SecretName),
}

/// A non-blank secret name of at most 256 bytes.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub struct SecretName(String);

impl SecretName {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Err("secret name must not be blank".into());
        }
        if raw.len() > 256 {
            return Err("secret name must be at most 256 bytes".into());
        }
        Ok(Self(raw.to_owned()))
    }

    pub(crate) fn parse_new(raw: &str) -> Result<Self, String> {
        if Uuid::parse_str(raw).is_ok() {
            return Err("secret name must not be a UUID".into());
        }
        Self::parse(raw)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for SecretName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<SecretName> for String {
    fn from(name: SecretName) -> Self {
        name.0
    }
}

pub(crate) fn parse_key_value(raw: &str) -> Result<KeyValue, String> {
    match raw.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok(KeyValue {
            key: key.to_owned(),
            value: value.to_owned(),
        }),
        _ => Err("expected KEY=VALUE with a non-empty KEY".into()),
    }
}

/// Key/value pairs from a repeatable flag, in the order given, with each key present once.
#[cfg_attr(test, derive(Debug))]
pub struct UniqueKeyValues(Vec<KeyValue>);

impl UniqueKeyValues {
    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn parse(pairs: Vec<KeyValue>, flag: &str) -> Result<Self> {
        let mut seen = BTreeSet::new();
        for pair in &pairs {
            if !seen.insert(pair.key.as_str()) {
                return Err(InvalidInput(format!(
                    "{flag} key {} was given more than once",
                    pair.key
                ))
                .into());
            }
        }
        Ok(Self(pairs))
    }
}

impl From<UniqueKeyValues> for Vec<KeyValue> {
    fn from(pairs: UniqueKeyValues) -> Self {
        pairs.0
    }
}

impl From<UniqueKeyValues> for BTreeMap<String, String> {
    fn from(pairs: UniqueKeyValues) -> Self {
        pairs
            .0
            .into_iter()
            .map(|KeyValue { key, value }| (key, value))
            .collect()
    }
}

pub struct Selector {
    properties: UniqueKeyValues,
    name_prefix: Option<String>,
}

impl Selector {
    pub(crate) fn new(properties: UniqueKeyValues, name_prefix: Option<String>) -> Self {
        Self {
            properties,
            name_prefix,
        }
    }

    pub(crate) fn matches(&self, secret: &SecretMetadata) -> bool {
        let SecretMetadata {
            secret_id: _,
            name,
            static_properties,
            created_at_unix_ms: _,
        } = secret;
        let prefixed = self
            .name_prefix
            .as_deref()
            .is_none_or(|prefix| name.as_deref().is_some_and(|name| name.starts_with(prefix)));
        prefixed
            && self.properties.0.iter().all(|KeyValue { key, value }| {
                static_properties
                    .iter()
                    .any(|property| property.key == *key && property.value == *value)
            })
    }
}

pub(crate) fn read_value(
    from_file: Option<&Path>,
    non_interactive: bool,
) -> Result<Zeroizing<String>> {
    if let Some(path) = from_file {
        let mut bytes = Zeroizing::new(Vec::new());
        File::open(path)
            .with_context(|| format!("read secret value from {}", path.display()))?
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read secret value from {}", path.display()))?;
        return normalize(take(&mut *bytes));
    }
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut bytes = Zeroizing::new(Vec::new());
        stdin
            .lock()
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        return normalize(take(&mut *bytes));
    }
    if non_interactive {
        return Err(MissingRequiredInput::new("--from-file").into());
    }
    let mut value = Zeroizing::new(rpassword::prompt_password("Secret value: ")?);
    normalize(take(&mut *value).into_bytes())
}

fn normalize(bytes: Vec<u8>) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(bytes);
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(InvalidInput("secret value exceeds the 1 MiB limit".into()).into());
    }
    let mut value = match String::from_utf8(take(&mut *bytes)) {
        Ok(value) => Zeroizing::new(value),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            return Err(InvalidInput("secret value is not valid UTF-8".into()).into());
        }
    };
    if value.ends_with("\r\n") {
        let len = value.len();
        value.truncate(len - 2);
    } else if value.ends_with('\n') {
        let len = value.len();
        value.truncate(len - 1);
    }
    if value.is_empty() {
        return Err(InvalidInput("secret value is empty".into()).into());
    }
    Ok(value)
}

const TURNKEY_DEV_SIGNER_QUORUM_PUBLIC_KEY: &str = "046101205064b86e23b9619dad4a887a3cb31ac4cb2cb8256556fdf315c7d42d9cece7bbc7b5ebc70a34b2faa4d1f0dffad0c2706b08f0065e0cb0534140b66564048cf9ed5f579298cc1571823a3222b82d80c529c551f6070fbe712ae1a9e8d1a23b7006e306d27190358dfcd9c44624918a00f23c920a33cb14f5b026eafc865d";

pub(crate) fn quorum_for(api_base_url: &str) -> Result<QuorumPublicKey> {
    match api_base_url.trim_end_matches('/') {
        "https://api.turnkey.com" => Ok(QuorumPublicKey::production_signer()),
        "https://api.preprod.turnkey.engineering" => Ok(QuorumPublicKey::preprod_signer()),
        "https://api.dev.turnkey.engineering" => {
            QuorumPublicKey::from_string(TURNKEY_DEV_SIGNER_QUORUM_PUBLIC_KEY)
                .context("dev signer quorum key constant is malformed")
        }
        _ => Err(InvalidInput(format!(
            "no trusted enclave quorum key is known for API base URL {api_base_url}"
        ))
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_name_must_be_a_non_blank_non_uuid_label() {
        assert_eq!(
            SecretName::parse_new("api-token").unwrap(),
            SecretName("api-token".into())
        );
        assert_eq!(
            SecretName::parse_new(" ").unwrap_err(),
            "secret name must not be blank"
        );
        assert_eq!(
            SecretName::parse_new(&"x".repeat(257)).unwrap_err(),
            "secret name must be at most 256 bytes"
        );
        assert_eq!(
            SecretName::parse_new(&Uuid::new_v4().to_string()).unwrap_err(),
            "secret name must not be a UUID"
        );
    }

    #[test]
    fn key_value_splits_at_the_first_equals_sign() {
        assert_eq!(
            parse_key_value("env=prod=eu").unwrap(),
            KeyValue {
                key: "env".into(),
                value: "prod=eu".into()
            }
        );
        assert_eq!(
            parse_key_value("env=").unwrap(),
            KeyValue {
                key: "env".into(),
                value: String::new()
            }
        );
        assert_eq!(
            parse_key_value("=x").unwrap_err(),
            "expected KEY=VALUE with a non-empty KEY"
        );
        assert_eq!(
            parse_key_value("env").unwrap_err(),
            "expected KEY=VALUE with a non-empty KEY"
        );
    }

    #[test]
    fn selector_prefix_never_matches_an_unnamed_secret() {
        let unnamed = SecretMetadata {
            secret_id: Uuid::new_v4().to_string(),
            name: None,
            static_properties: Vec::new(),
            created_at_unix_ms: 0,
        };
        assert!(Selector::new(UniqueKeyValues::empty(), None).matches(&unnamed));
        assert!(!Selector::new(UniqueKeyValues::empty(), Some("svc/".into())).matches(&unnamed));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let pairs = vec![
            KeyValue {
                key: "a".into(),
                value: "1".into(),
            },
            KeyValue {
                key: "a".into(),
                value: "2".into(),
            },
        ];
        let error = UniqueKeyValues::parse(pairs, "--property").unwrap_err();
        assert_eq!(
            error.to_string(),
            "--property key a was given more than once"
        );
    }

    #[test]
    fn values_are_utf8_with_one_trailing_newline_stripped() {
        assert_eq!(&*normalize(b"hunter2\n".to_vec()).unwrap(), "hunter2");
        assert_eq!(&*normalize(b"hunter2\r\n".to_vec()).unwrap(), "hunter2");
        assert_eq!(&*normalize(b"a\n\n".to_vec()).unwrap(), "a\n");
        assert_eq!(&*normalize(b"multi\nline".to_vec()).unwrap(), "multi\nline");
        assert_eq!(
            normalize(b"\n".to_vec()).unwrap_err().to_string(),
            "secret value is empty"
        );
        assert_eq!(
            normalize(vec![0xff, 0xfe]).unwrap_err().to_string(),
            "secret value is not valid UTF-8"
        );
        let huge = vec![b'a'; MAX_SECRET_BYTES + 1];
        assert_eq!(
            normalize(huge).unwrap_err().to_string(),
            "secret value exceeds the 1 MiB limit"
        );
    }

    #[test]
    fn quorum_key_follows_the_api_base_url() {
        assert_eq!(
            quorum_for("https://api.turnkey.com").unwrap(),
            QuorumPublicKey::production_signer()
        );
        assert_eq!(
            quorum_for("https://api.turnkey.com/").unwrap(),
            QuorumPublicKey::production_signer()
        );
        assert_eq!(
            quorum_for("https://api.preprod.turnkey.engineering").unwrap(),
            QuorumPublicKey::preprod_signer()
        );
        assert_eq!(
            quorum_for("https://api.dev.turnkey.engineering").unwrap(),
            QuorumPublicKey::from_string(TURNKEY_DEV_SIGNER_QUORUM_PUBLIC_KEY).unwrap()
        );
        assert_eq!(
            quorum_for("http://localhost:8080").unwrap_err().to_string(),
            "no trusted enclave quorum key is known for API base URL http://localhost:8080"
        );
    }
}
