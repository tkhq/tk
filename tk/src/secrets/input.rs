//! Local parsing for `tk secret`. Everything here runs before credentials are
//! resolved.

use anyhow::{Context, Result};
use std::io::{IsTerminal, Read};
use std::path::Path;
use turnkey_client::generated::immutable::models::v1::KeyValue;
use turnkey_enclave_encrypt::QuorumPublicKey;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::errors::InvalidInput;
use crate::output::MissingRequiredInput;

pub(crate) const MAX_SECRET_BYTES: usize = 1024 * 1024;

/// A secret reference, either by ID or by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretRef {
    Id(Uuid),
    Name(String),
}

/// Parses a non-blank name of at most 256 bytes.
pub(crate) fn parse_label(raw: &str) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Err("secret name must not be blank".into());
    }
    if raw.len() > 256 {
        return Err("secret name must be at most 256 bytes".into());
    }
    Ok(raw.to_owned())
}

/// Parses a new secret's name, which must not be a UUID.
pub(crate) fn parse_name(raw: &str) -> Result<String, String> {
    if Uuid::parse_str(raw).is_ok() {
        return Err("secret name must not be a UUID".into());
    }
    parse_label(raw)
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

/// Rejects duplicate keys in repeatable flags.
pub(crate) fn unique_key_values(pairs: Vec<KeyValue>, flag: &str) -> Result<Vec<KeyValue>> {
    let mut seen = std::collections::BTreeSet::new();
    for pair in &pairs {
        if !seen.insert(pair.key.as_str()) {
            return Err(
                InvalidInput(format!("{flag} key {} was given more than once", pair.key)).into(),
            );
        }
    }
    Ok(pairs)
}

/// Reads from a file, stdin, or a hidden prompt.
pub(crate) fn read_value(
    from_file: Option<&Path>,
    non_interactive: bool,
) -> Result<Zeroizing<String>> {
    if let Some(path) = from_file {
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(path)?
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        return normalize(std::mem::take(&mut *bytes));
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut bytes = Zeroizing::new(Vec::new());
        stdin
            .lock()
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        return normalize(std::mem::take(&mut *bytes));
    }
    if non_interactive {
        return Err(MissingRequiredInput::new("--from-file").into());
    }
    let value = Zeroizing::new(rpassword::prompt_password("Secret value: ")?);
    normalize(value.as_bytes().to_vec())
}

/// Normalizes a non-empty UTF-8 value up to 1 MiB.
pub(crate) fn normalize(bytes: Vec<u8>) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(bytes);
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(InvalidInput("secret value exceeds the 1 MiB limit".into()).into());
    }
    let mut value = match String::from_utf8(std::mem::take(&mut *bytes)) {
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

/// Turnkey's development signer quorum public key.
const TURNKEY_DEV_SIGNER_QUORUM_PUBLIC_KEY: &str = "046101205064b86e23b9619dad4a887a3cb31ac4cb2cb8256556fdf315c7d42d9cece7bbc7b5ebc70a34b2faa4d1f0dffad0c2706b08f0065e0cb0534140b66564048cf9ed5f579298cc1571823a3222b82d80c529c551f6070fbe712ae1a9e8d1a23b7006e306d27190358dfcd9c44624918a00f23c920a33cb14f5b026eafc865d";

/// Returns the trusted quorum key for an API base URL.
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
    use turnkey_client::generated::immutable::models::v1::KeyValue;

    #[test]
    fn import_name_must_be_a_non_blank_non_uuid_label() {
        assert_eq!(parse_name("api-token").unwrap(), "api-token");
        assert_eq!(
            parse_name(" ").unwrap_err(),
            "secret name must not be blank"
        );
        assert_eq!(
            parse_name(&"x".repeat(257)).unwrap_err(),
            "secret name must be at most 256 bytes"
        );
        assert_eq!(
            parse_name(&Uuid::new_v4().to_string()).unwrap_err(),
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
        let error = unique_key_values(pairs, "--property").unwrap_err();
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
