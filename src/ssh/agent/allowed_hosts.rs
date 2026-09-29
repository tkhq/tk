//! Parsing the allowed-hosts file into host keys and reported hostnames.

use std::path::Path;

use anyhow::{Context, Result};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, PublicKey};
use tokio::fs;

use crate::errors::{InvalidInput, Malformed};

pub(super) struct AllowedHosts {
    pub(super) names: Vec<String>,
    pub(super) keys: Vec<KeyData>,
}

pub(super) async fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))
}

pub(super) fn parse(path: &Path, contents: &str) -> Result<AllowedHosts> {
    let mut names = Vec::new();
    let mut keys = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let location = || format!("{}:{}", path.display(), index + 1);
        let reject = |problem: &str| InvalidInput(format!("{}: {problem}", location()));
        if line.starts_with('@') {
            return Err(reject("marker entries such as @revoked and @cert-authority are not supported; list plain host keys").into());
        }
        let mut fields = line.split_whitespace();
        let (Some(name), Some(_algorithm), Some(_body)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(
                reject("expected known_hosts fields: hostnames, key type, base64 key").into(),
            );
        };
        if name.starts_with('|') {
            return Err(reject("hashed hostnames are not supported").into());
        }
        let key = PublicKey::from_openssh(line[name.len()..].trim_start())
            .map_err(|error| Malformed::new(format!("{}: invalid host key", location()), error))?;
        if !matches!(
            key.algorithm(),
            Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
        ) {
            return Err(reject(&format!(
                "unsupported host key algorithm {}; use ed25519, ecdsa, or rsa",
                key.algorithm()
            ))
            .into());
        }
        if let KeyData::Rsa(rsa) = key.key_data() {
            // ssh-key's RSA verifier refuses a modulus over 4096 bits or shorter than 256 bytes,
            // so no session-bind signature from such a host key can ever verify.
            let Some(modulus) = rsa.n.as_positive_bytes() else {
                return Err(reject("RSA host key modulus is not positive").into());
            };
            let bits = modulus.len() * 8
                - modulus
                    .first()
                    .map_or(0, |byte| byte.leading_zeros() as usize);
            if bits > 4096 {
                return Err(reject("RSA host keys over 4096 bits are not supported").into());
            }
            if modulus.len() < 256 {
                return Err(reject("RSA host keys under 2048 bits are not supported").into());
            }
        }

        names.push(name.to_string());
        keys.push(key.into());
    }

    if keys.is_empty() {
        return Err(InvalidInput(format!("{} names no host keys", path.display())).into());
    }

    names.sort();
    names.dedup();
    Ok(AllowedHosts { names, keys })
}
