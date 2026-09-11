use crate::{
    auth::{KeyCurve, StoredApiKey, secure_create},
    operations::OperationOutput,
};
use anyhow::{Context, Result};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// New credential JSON path. Existing files are never overwritten.
    #[arg(long)]
    output: PathBuf,
}

impl GenerateArgs {
    pub async fn run(self) -> Result<OperationOutput> {
        let key = TurnkeyP256ApiKey::generate();
        let public_key = hex::encode(key.compressed_public_key());
        let mut stored = StoredApiKey {
            public_key: public_key.clone(),
            private_key: hex::encode(key.private_key()),
            curve: KeyCurve::P256,
        };
        let encoded = serde_json::to_vec(&stored);
        stored.private_key.zeroize();
        let encoded = Zeroizing::new(encoded?);
        secure_create(&self.output, &encoded)
            .await
            .with_context(|| format!("create {}", self.output.display()))?;
        Ok(OperationOutput::result(
            "api-key.generate",
            json!({"publicKey": public_key, "curve": "p256", "path": self.output}),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[tokio::test]
    async fn generated_credentials_are_valid_private_and_not_in_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        let output = GenerateArgs {
            output: path.clone(),
        }
        .run()
        .await
        .unwrap();
        let stored: StoredApiKey = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key)).unwrap();
        let result = serde_json::to_value(output).unwrap();
        assert_eq!(result["data"]["publicKey"], stored.public_key);
        assert!(!result.to_string().contains(&stored.private_key));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn existing_destination_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        fs::write(&path, b"existing").unwrap();
        assert!(
            GenerateArgs {
                output: path.clone()
            }
            .run()
            .await
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(GenerateArgs { output: path }.run().await.is_err());
        assert!(!target.exists());
    }
}
