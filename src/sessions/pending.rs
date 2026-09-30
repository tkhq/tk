//! A generated credential awaiting registration, remembered per profile.

use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};
use tokio::fs;

use super::public_key::CompressedPublicKey;
use crate::{
    auth::secure_create,
    errors::{InvalidInput, Malformed},
};

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingSession {
    pub(crate) version: u32,
    pub(crate) public_key: CompressedPublicKey,
    pub(crate) key_file: PathBuf,
}

impl PendingSession {
    fn dir(state: &Path) -> PathBuf {
        state.join("sessions/pending")
    }

    fn path(state: &Path, profile: &str) -> PathBuf {
        Self::dir(state).join(format!("{profile}.json"))
    }

    pub(crate) async fn load(state: &Path, profile: &str) -> Result<Option<Self>> {
        let path = Self::path(state, profile);
        let bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let pending: Self = from_slice(&bytes).map_err(|error| {
            Malformed::new(
                format!(
                    "pending session state {} is malformed; delete it to start over",
                    path.display()
                ),
                error,
            )
        })?;
        if pending.version != 1 {
            return Err(InvalidInput(format!(
                "pending session state {} has unsupported version {}",
                path.display(),
                pending.version
            ))
            .into());
        }
        Ok(Some(pending))
    }

    pub(crate) async fn create(&self, state: &Path, profile: &str) -> Result<()> {
        let dir = Self::dir(state);
        fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create {}", dir.display()))?;
        let path = Self::path(state, profile);
        secure_create(&path, &to_vec(self)?)
            .await
            .with_context(|| format!("write pending session state {}", path.display()))
    }

    pub(crate) async fn remove(state: &Path, profile: &str) -> Result<()> {
        let path = Self::path(state, profile);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::auth::SecureCreateError;

    fn sample() -> PendingSession {
        PendingSession {
            version: 1,
            public_key: "02abcdefabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
                .parse()
                .unwrap(),
            key_file: PathBuf::from("/keys/02ab.json"),
        }
    }

    #[tokio::test]
    async fn round_trips_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let pending = sample();
        pending.create(dir.path(), "agent").await.unwrap();
        let loaded = PendingSession::load(dir.path(), "agent").await.unwrap();
        assert_eq!(loaded, Some(pending));
        PendingSession::remove(dir.path(), "agent").await.unwrap();
        assert_eq!(
            PendingSession::load(dir.path(), "agent").await.unwrap(),
            None
        );
        PendingSession::remove(dir.path(), "agent").await.unwrap();
    }

    #[tokio::test]
    async fn second_request_for_the_same_profile_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        sample().create(dir.path(), "agent").await.unwrap();
        let error = sample().create(dir.path(), "agent").await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<SecureCreateError>(),
            Some(SecureCreateError::Exists)
        ));
    }

    #[tokio::test]
    async fn malformed_state_is_reported_as_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = PendingSession::path(dir.path(), "agent");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{").unwrap();
        let error = PendingSession::load(dir.path(), "agent").await.unwrap_err();
        let malformed = error
            .downcast_ref::<Malformed>()
            .expect("a Malformed error");
        assert_eq!(
            malformed.to_string(),
            format!(
                "pending session state {} is malformed; delete it to start over",
                path.display()
            )
        );
    }
}
