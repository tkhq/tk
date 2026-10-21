//! Stamps Turnkey API requests with a profile's credential.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::json;
use turnkey_api_key_stamper::{
    API_KEY_STAMP_HEADER_NAME, SIGNATURE_SCHEME_P256, Stamp, StampHeader, StamperError,
    TurnkeyP256ApiKey,
};

use crate::{sessions::public_key::CompressedPublicKey, yubikey::YubiKeyCredential};

pub enum Stamper {
    File(TurnkeyP256ApiKey),
    YubiKey(YubiKeyCredential),
}

impl Stamper {
    pub(crate) fn public_key(&self) -> CompressedPublicKey {
        match self {
            Self::File(key) => CompressedPublicKey::from(key),
            Self::YubiKey(credential) => credential.public_key.clone(),
        }
    }
}

impl From<TurnkeyP256ApiKey> for Stamper {
    fn from(key: TurnkeyP256ApiKey) -> Self {
        Self::File(key)
    }
}

impl Stamp for Stamper {
    fn stamp(&self, body: &[u8]) -> Result<StampHeader, StamperError> {
        let credential = match self {
            Self::File(key) => return key.stamp(body),
            Self::YubiKey(credential) => credential,
        };
        // `Stamp` can only report a string-carrying `StamperError`, so the
        // rendered chain is the most this error can keep.
        let signature = credential
            .sign(body)
            .map_err(|error| StamperError::InvalidPrivateKeyBytes(format!("{error:#}")))?;
        let stamp = json!({
            "publicKey": credential.public_key,
            "scheme": SIGNATURE_SCHEME_P256,
            "signature": hex::encode(signature),
        });
        Ok(StampHeader {
            name: API_KEY_STAMP_HEADER_NAME.to_owned(),
            value: BASE64_URL_SAFE_NO_PAD.encode(stamp.to_string()),
        })
    }
}
