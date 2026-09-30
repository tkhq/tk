//! A compressed P256 public key as the CLI accepts and prints it.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::external::data::v1::ApiKey;

use crate::errors::InvalidInput;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(try_from = "String")]
pub(crate) struct CompressedPublicKey(String);

impl CompressedPublicKey {
    pub(crate) fn matches(&self, key: &ApiKey) -> bool {
        key.credential
            .as_ref()
            .is_some_and(|credential| credential.public_key.eq_ignore_ascii_case(&self.0))
    }
}

impl FromStr for CompressedPublicKey {
    type Err = InvalidInput;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let key = text.trim().to_ascii_lowercase();
        let valid = key.len() == 66
            && (key.starts_with("02") || key.starts_with("03"))
            && key.chars().all(|c| c.is_ascii_hexdigit());
        if valid {
            Ok(Self(key))
        } else {
            Err(InvalidInput(
                "must be a compressed P256 public key: 66 hex characters starting with 02 or 03"
                    .into(),
            ))
        }
    }
}

impl TryFrom<String> for CompressedPublicKey {
    type Error = InvalidInput;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<&TurnkeyP256ApiKey> for CompressedPublicKey {
    fn from(key: &TurnkeyP256ApiKey) -> Self {
        Self(hex::encode(key.compressed_public_key()))
    }
}

impl Display for CompressedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "02ABCDEFabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123";

    #[test]
    fn normalizes_to_trimmed_lowercase_hex() {
        let key: CompressedPublicKey = format!(" {KEY}\n").parse().unwrap();
        assert_eq!(key.to_string(), KEY.to_ascii_lowercase());
    }

    #[test]
    fn rejects_wrong_length_prefix_and_non_hex() {
        for bad in [
            &KEY[..64],
            &format!("04{}", &KEY[2..]),
            &format!("0g{}", &KEY[2..]),
            "",
        ] {
            let InvalidInput(message) = bad.parse::<CompressedPublicKey>().unwrap_err();
            assert_eq!(
                message,
                "must be a compressed P256 public key: 66 hex characters starting with 02 or 03"
            );
        }
    }

    #[test]
    fn serializes_as_the_hex_string_and_rejects_malformed_json() {
        let key: CompressedPublicKey = KEY.parse().unwrap();
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!(r#""{}""#, KEY.to_ascii_lowercase()));
        assert_eq!(
            serde_json::from_str::<CompressedPublicKey>(&json).unwrap(),
            key
        );
        let error = serde_json::from_str::<CompressedPublicKey>(r#""02ab""#).unwrap_err();
        assert_eq!(
            error.to_string(),
            "must be a compressed P256 public key: 66 hex characters starting with 02 or 03"
        );
    }
}
