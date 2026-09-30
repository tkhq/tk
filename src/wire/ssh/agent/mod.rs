//! Foreground SSH agent serving identities from a caller-provided keyring.

pub mod destination;

use std::{
    io::{self, ErrorKind},
    os::unix::{fs::FileTypeExt, net::UnixListener as StdUnixListener},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use destination::{DestinationPolicy, Destinations};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::{
    fs,
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
    task::JoinSet,
};
use tracing::{debug, warn};

use super::{Ed25519PublicKey, protocol};
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
pub async fn run(
    socket: PathBuf,
    mode: SocketMode,
    keyring: Arc<dyn Keyring>,
    policy: Arc<DestinationPolicy>,
) -> Result<()> {
    remove_stale_socket(&socket).await?;

    let result = async {
        let bind_context = || format!("failed to bind SSH agent socket at {}", socket.display());
        let listener = (|| -> io::Result<Socket> {
            let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            listener.set_nonblocking(true)?;
            listener.bind(&SockAddr::unix(&socket)?)?;
            Ok(listener)
        })()
        .with_context(bind_context)?;
        std::fs::set_permissions(&socket, mode.permissions()).with_context(|| {
            format!("failed to restrict SSH agent socket at {}", socket.display())
        })?;
        let listener = (|| -> io::Result<UnixListener> {
            listener.listen(128)?;
            UnixListener::from_std(StdUnixListener::from(listener))
        })()
        .with_context(bind_context)?;
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
                    let policy = Arc::clone(&policy);
                    connections.spawn(async move { handle_connection(stream, keyring, policy).await });
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

async fn handle_connection(
    mut stream: UnixStream,
    keyring: Arc<dyn Keyring>,
    policy: Arc<DestinationPolicy>,
) -> io::Result<()> {
    let mut destinations = Destinations::default();

    loop {
        let frame = match protocol::read_frame(&mut stream).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                let _ = protocol::write_frame(&mut stream, &failure_frame()).await;
                return Ok(());
            }
            Err(error) if is_connection_error_kind(error.kind()) => return Ok(()),
            Err(error) => return Err(error),
        };

        let response = match protocol::parse_agent_frame(&frame) {
            Ok((protocol::SSH_AGENTC_REQUEST_IDENTITIES, _)) => {
                let identities = if policy.lists_identities(&destinations) {
                    keyring.identities()
                } else {
                    Vec::new()
                };
                protocol::encode_request_identities_response(&identities)
            }
            Ok((protocol::SSH_AGENTC_SIGN_REQUEST, payload)) => {
                sign_response(payload, keyring.as_ref(), &policy, &destinations).await
            }
            Ok((protocol::SSH_AGENTC_EXTENSION, payload))
                if matches!(policy.as_ref(), DestinationPolicy::Restricted { .. }) =>
            {
                bind_response(payload, &mut destinations)
            }
            Ok(_) | Err(_) => failure_frame(),
        };

        if let Err(error) = protocol::write_frame(&mut stream, &response).await {
            if is_connection_error_kind(error.kind()) {
                return Ok(());
            }
            return Err(error);
        }
    }
}

fn bind_response(payload: &[u8], destinations: &mut Destinations) -> Vec<u8> {
    let Some(contents) = protocol::parse_extension(payload) else {
        return failure_frame();
    };

    match destinations.bind(contents) {
        Ok(()) => protocol::encode_agent_frame(protocol::SSH_AGENT_SUCCESS, &[]),
        Err(error) => {
            debug!(?error, "refused an SSH agent session-bind");
            // RFC 9987 section 5.8: a supported extension signals failure with
            // SSH_AGENT_EXTENSION_FAILURE, keeping SSH_AGENT_FAILURE for unsupported ones.
            protocol::encode_agent_frame(protocol::SSH_AGENT_EXTENSION_FAILURE, &[])
        }
    }
}

async fn sign_response(
    payload: &[u8],
    keyring: &dyn Keyring,
    policy: &DestinationPolicy,
    destinations: &Destinations,
) -> Vec<u8> {
    let request = match protocol::parse_sign_request(payload) {
        Ok(request) => request,
        Err(error) => {
            debug!(?error, "rejected malformed SSH agent sign request");
            return failure_frame();
        }
    };
    let public_key = match Ed25519PublicKey::from_blob(request.public_key_blob) {
        Ok(public_key) => public_key,
        Err(error) => {
            debug!(
                ?error,
                "SSH agent sign request named an unsupported key blob"
            );
            return failure_frame();
        }
    };
    let authorized = match policy.evaluate(request, destinations) {
        Ok(authorized) => authorized,
        Err(refusal) => {
            debug!(fingerprint = %public_key.fingerprint(), %refusal, "refused an SSH agent sign request");
            return failure_frame();
        }
    };

    match keyring.sign(&public_key, authorized.bytes()).await {
        Ok(signature) => protocol::encode_sign_response(&signature),
        Err(SignError::UnknownKey) => {
            debug!(fingerprint = %public_key.fingerprint(), "SSH agent sign request named an unknown key");
            failure_frame()
        }
        Err(SignError::Signer(error)) => {
            warn!(?error, fingerprint = %public_key.fingerprint(), "SSH agent signer failed");
            failure_frame()
        }
    }
}

fn failure_frame() -> Vec<u8> {
    protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[])
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
