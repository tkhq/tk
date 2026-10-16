//! Turnkey API keys that never leave a YubiKey's PIV application.

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{errors::InvalidInput, sessions::public_key::CompressedPublicKey};

#[cfg(feature = "yubikey")]
mod device;

#[cfg(not(feature = "yubikey"))]
mod device {
    use anyhow::Result;

    use super::{PivSlot, YubiKeyCredential, YubiKeySerial};

    #[derive(Debug, thiserror::Error)]
    #[error("this tk build has no YubiKey support; install a build with the yubikey feature")]
    struct YubiKeyUnsupported;

    pub(super) fn discover(_: Option<YubiKeySerial>, _: PivSlot) -> Result<YubiKeyCredential> {
        Err(YubiKeyUnsupported.into())
    }

    pub(super) fn sign(_: &YubiKeyCredential, _: &[u8]) -> Result<Vec<u8>> {
        Err(YubiKeyUnsupported.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct YubiKeySerial(u32);

impl FromStr for YubiKeySerial {
    type Err = InvalidInput;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse().map(Self).map_err(|error| {
            InvalidInput(format!("YubiKey serial must be a decimal number: {error}"))
        })
    }
}

impl Display for YubiKeySerial {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct PivSlot(u8);

impl FromStr for PivSlot {
    type Err = InvalidInput;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match u8::from_str_radix(text, 16) {
            Ok(slot @ (0x9a | 0x9c | 0x9d | 0x9e | 0x82..=0x95)) if text.len() == 2 => {
                Ok(Self(slot))
            }
            _ => Err(InvalidInput(format!(
                "PIV slot {text} cannot hold a signing key; use 9a, 9c, 9d, 9e, or a retired slot 82 through 95"
            ))),
        }
    }
}

impl TryFrom<String> for PivSlot {
    type Error = InvalidInput;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<PivSlot> for String {
    fn from(slot: PivSlot) -> Self {
        slot.to_string()
    }
}

impl Display for PivSlot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct YubiKeyCredential {
    pub(crate) serial: YubiKeySerial,
    pub(crate) slot: PivSlot,
    pub(crate) public_key: CompressedPublicKey,
}

#[derive(Debug, thiserror::Error)]
#[error("slot {slot} on YubiKey {serial} now holds {actual}, not the profile's key {expected}")]
pub(crate) struct YubiKeyKeyChanged {
    serial: YubiKeySerial,
    slot: PivSlot,
    expected: CompressedPublicKey,
    actual: CompressedPublicKey,
}

impl YubiKeyCredential {
    pub(crate) fn discover(serial: Option<YubiKeySerial>, slot: PivSlot) -> Result<Self> {
        device::discover(serial, slot)
    }

    pub(crate) fn confirm(&self) -> Result<()> {
        let current = Self::discover(Some(self.serial), self.slot)?;
        if current.public_key != self.public_key {
            return Err(YubiKeyKeyChanged {
                serial: self.serial,
                slot: self.slot,
                expected: self.public_key.clone(),
                actual: current.public_key,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        device::sign(self, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_parse_only_signing_capable_piv_slots() {
        for slot in ["9a", "9c", "9d", "9e", "82", "8f", "95"] {
            assert_eq!(slot.parse::<PivSlot>().unwrap().to_string(), slot);
        }
        for slot in ["9b", "f9", "81", "96", "9A9", "a", "", "0x9a", "+9a"] {
            assert!(slot.parse::<PivSlot>().is_err(), "{slot} parsed");
        }
    }

    #[test]
    fn a_credential_round_trips_through_its_persisted_shape() {
        let text = r#"
serial = 12345678
slot = "9a"
public_key = "02abcdefabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
"#;
        let credential: YubiKeyCredential = toml::from_str(text).unwrap();
        assert_eq!(
            credential,
            YubiKeyCredential {
                serial: YubiKeySerial(12_345_678),
                slot: PivSlot(0x9a),
                public_key: "02abcdefabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
                    .parse()
                    .unwrap(),
            }
        );
        assert_eq!(toml::to_string(&credential).unwrap().trim(), text.trim());
    }
}
