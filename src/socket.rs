use std::{
    fmt::{self, Display, Formatter},
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SocketMode(u32);

#[derive(Debug, Error)]
#[error("socket mode must be an octal value from 000 through 777")]
pub struct SocketModeError;

impl SocketMode {
    pub fn permissions(self) -> Permissions {
        Permissions::from_mode(self.0)
    }
}

impl FromStr for SocketMode {
    type Err = SocketModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        u32::from_str_radix(value, 8)
            .ok()
            .filter(|mode| *mode <= 0o777)
            .map(Self)
            .ok_or(SocketModeError)
    }
}

impl Display for SocketMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:03o}", self.0)
    }
}

impl Serialize for SocketMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SocketMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}
