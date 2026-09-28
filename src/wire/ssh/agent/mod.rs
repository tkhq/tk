//! Foreground SSH agent serving identities from a caller-provided keyring.

use std::io::{self, ErrorKind};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::fs;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Ed25519PublicKey;
use super::protocol;
use crate::socket::SocketMode;

/// One identity advertised by the SSH agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentity {
    /// The public key used to identify signing requests.
    pub public_key: Ed25519PublicKey,
    /// The comment shown by SSH identity-listing tools.
    pub comment: String,
}

/// A keyring signing failure.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// No keyring entry matches the requested public key.
    #[error("no registered key has this public key blob")]
    UnknownKey,
    /// The selected signer failed.
    #[error(transparent)]
    Signer(#[from] anyhow::Error),
}

/// A future returned by a [`Keyring`] signing operation.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<[u8; 64], SignError>> + Send + 'a>>;

/// Supplies the identities and signing operations served by an SSH agent.
pub trait Keyring: Send + Sync {
    /// Returns the identities advertised by the agent.
    fn identities(&self) -> Vec<AgentIdentity>;

    /// Signs data with the requested public key.
    fn sign<'a>(&'a self, public_key: &'a Ed25519PublicKey, data: &'a [u8]) -> SignFuture<'a>;
}

/// Runs a foreground SSH agent bound to the provided Unix socket path.
pub async fn run(socket: PathBuf, mode: SocketMode, keyring: Arc<dyn Keyring>) -> Result<()> {
    remove_stale_socket(&socket).await?;

    let result = async {
        let listener = UnixListener::bind(&socket)
            .with_context(|| format!("failed to bind SSH agent socket at {}", socket.display()))?;
        fs::set_permissions(&socket, mode.permissions())
            .await
            .with_context(|| {
                format!("failed to restrict SSH agent socket at {}", socket.display())
            })?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
        let mut terminate =
            signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, _) = accept_result.context("failed to accept SSH agent connection")?;
                    let keyring = Arc::clone(&keyring);
                    connections.spawn(async move { handle_connection(stream, keyring).await });
                }
                _ = interrupt.recv() => break,
                _ = terminate.recv() => break,
                Some(join_result) = connections.join_next() => {
                    match join_result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) if is_connection_error_kind(error.kind()) => {}
                        Ok(Err(error)) => {
                            return Err(error).context("failed to serve SSH agent connection");
                        }
                        Err(error) => {
                            return Err(error).context("ssh-agent connection task failed");
                        }
                    }
                }
            }
        }

        connections.abort_all();
        while let Some(join_result) = connections.join_next().await {
            if let Err(error) = join_result
                && error.is_panic()
            {
                return Err(error).context("ssh-agent connection task panicked");
            }
        }

        Ok(())
    }
    .await;

    let _ = fs::remove_file(&socket).await;
    result
}

async fn handle_connection(mut stream: UnixStream, keyring: Arc<dyn Keyring>) -> io::Result<()> {
    loop {
        let frame = match protocol::read_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                let failure = protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[]);
                let _ = protocol::write_frame(&mut stream, &failure).await;
                return Ok(());
            }
            Err(error) if is_connection_error_kind(error.kind()) => return Ok(()),
            Err(error) => return Err(error),
        };

        let response = match frame.get(4).copied() {
            Some(protocol::SSH_AGENTC_REQUEST_IDENTITIES) => {
                protocol::encode_request_identities_response(&keyring.identities())
            }
            Some(protocol::SSH_AGENTC_SIGN_REQUEST) => {
                sign_response(&frame, keyring.as_ref()).await
            }
            Some(_) | None => protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[]),
        };

        if let Err(error) = protocol::write_frame(&mut stream, &response).await {
            if is_connection_error_kind(error.kind()) {
                return Ok(());
            }
            return Err(error);
        }
    }
}

async fn sign_response(frame: &[u8], keyring: &dyn Keyring) -> Vec<u8> {
    let request = match protocol::parse_sign_request_frame(frame) {
        Ok(request) => request,
        Err(error) => {
            debug!(?error, "rejected malformed SSH agent sign request");
            return protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[]);
        }
    };
    let public_key = match Ed25519PublicKey::from_blob(&request.public_key_blob) {
        Ok(public_key) => public_key,
        Err(error) => {
            debug!(
                ?error,
                "SSH agent sign request named an unsupported key blob"
            );
            return protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[]);
        }
    };

    match keyring.sign(&public_key, &request.data).await {
        Ok(signature) => protocol::encode_sign_response(&signature),
        Err(SignError::UnknownKey) => {
            debug!(fingerprint = %public_key.fingerprint(), "SSH agent sign request named an unknown key");
            protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[])
        }
        Err(SignError::Signer(error)) => {
            warn!(?error, fingerprint = %public_key.fingerprint(), "SSH agent signer failed");
            protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[])
        }
    }
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).await.with_context(|| {
                format!(
                    "failed to remove stale SSH agent socket at {}",
                    path.display()
                )
            })?;
        }
        Ok(_) => {
            return Err(anyhow!(
                "refusing to remove non-socket path at {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    Ok(())
}

fn is_connection_error_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
            | ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
    )
}

#[cfg(test)]
mod tests;
