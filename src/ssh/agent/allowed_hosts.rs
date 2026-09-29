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

pub(super) async fn load(path: &Path) -> Result<AllowedHosts> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut names = Vec::new();
    let mut keys = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let location = format!("{}:{}", path.display(), index + 1);
        let reject = |problem: &str| InvalidInput(format!("{location}: {problem}"));
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
            return Err(reject(
                "hashed hostnames are not supported; regenerate the file with ssh-keyscan",
            )
            .into());
        }
        let key = PublicKey::from_openssh(line[name.len()..].trim_start())
            .map_err(|error| Malformed::new(format!("{location}: invalid host key"), error))?;
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
        names.push(name.to_string());
        keys.push(key.into());
    }
    if keys.is_empty() {
        return Err(InvalidInput(format!(
            "{} names no host keys; add entries with ssh-keyscan HOST",
            path.display()
        ))
        .into());
    }
    names.sort();
    names.dedup();
    Ok(AllowedHosts { names, keys })
}
