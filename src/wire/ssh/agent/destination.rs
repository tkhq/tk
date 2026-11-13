//! Destination constraints limiting which servers an agent signs for.

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use signature::Verifier;
use ssh_key::{Fingerprint, HashAlg, PublicKey, Signature, public::KeyData};

use super::super::protocol::{
    AgentSignRequest, SessionBind, SignedData, classify_signed_data, parse_session_bind,
};

pub enum DestinationPolicy {
    Unrestricted,
    Restricted {
        hosts: Vec<Fingerprint>,
        namespaces: Vec<String>,
    },
}

struct Destination {
    host_key: KeyData,
    session_id: Vec<u8>,
}

struct AuthenticationBind {
    destination: Destination,
    contents: Vec<u8>,
}

#[derive(Default)]
pub(super) struct BoundSessions {
    forwarding: Vec<Destination>,
    authentication: Option<Box<AuthenticationBind>>,
}

pub(super) enum Destinations {
    Bound(BoundSessions),
    FailedBind,
}

impl Default for Destinations {
    fn default() -> Self {
        Self::Bound(BoundSessions::default())
    }
}

// OpenSSH's AGENT_MAX_SESSION_IDS caps the session binds one connection records.
const MAX_SESSION_BINDS: usize = 16;

pub(super) struct AuthorizedData<'a>(&'a [u8]);

impl<'a> AuthorizedData<'a> {
    pub(super) fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl Destinations {
    pub(super) fn bind(&mut self, contents: &[u8], hosts: Option<&[Fingerprint]>) -> Result<()> {
        // OpenSSH's process_ext_session_bind marks a bind attempted before parsing it, and
        // identity_permitted refuses destination-constrained keys after a failed attempt,
        // because ssh forwards the agent even when its forwarding bind fails.
        let Self::Bound(sessions) = self else {
            return Err(anyhow!("an earlier session-bind failed on this connection"));
        };

        let recorded =
            parse_session_bind(contents).and_then(|bind| sessions.bind(bind, contents, hosts));
        if recorded.is_err() {
            *self = Self::FailedBind;
        }
        recorded
    }

    pub(super) fn authentication_bind(&self, session_id: &[u8]) -> Result<&[u8]> {
        let Self::Bound(sessions) = self else {
            return Err(anyhow!("a session-bind failed on this connection"));
        };
        if let Some(hop) = sessions.forwarding.first() {
            return Err(anyhow!(
                "the session-bind for host key {} is a forwarding hop",
                hop.host_key.fingerprint(HashAlg::Sha256)
            ));
        }
        sessions
            .authentication
            .as_ref()
            .filter(|bind| bind.destination.session_id == session_id)
            .map(|bind| bind.contents.as_slice())
            .ok_or_else(|| {
                anyhow!(
                    "no session-bind@openssh.com matches the login; typed userauth needs an OpenSSH 8.9+ client"
                )
            })
    }
}

impl BoundSessions {
    fn bind(
        &mut self,
        bind: SessionBind<'_>,
        contents: &[u8],
        hosts: Option<&[Fingerprint]>,
    ) -> Result<()> {
        let SessionBind {
            host_key_blob,
            session_id,
            signature_blob,
            is_forwarding,
        } = bind;

        let fingerprint = Fingerprint::Sha256(Sha256::digest(host_key_blob).into());
        if let Some(hosts) = hosts
            && !hosts.contains(&fingerprint)
        {
            return Err(anyhow!(
                "host key {fingerprint} is not in the allowed hosts file"
            ));
        }
        let host_key =
            PublicKey::from_bytes(host_key_blob).context("decode the session-bind host key")?;
        let signature =
            Signature::try_from(signature_blob).context("decode the session-bind signature")?;
        host_key
            .key_data()
            .verify(session_id, &signature)
            .with_context(|| {
                format!(
                    "verify the session-bind signature for host key {}",
                    host_key.fingerprint(HashAlg::Sha256)
                )
            })?;

        if self
            .forwarding
            .iter()
            .chain(self.authentication.as_deref().map(|bind| &bind.destination))
            .any(|destination| destination.session_id == session_id)
        {
            return Err(anyhow!("the session is already bound on this connection"));
        }
        // OpenSSH's process_ext_session_bind refuses any bind after one made for authentication.
        if let Some(authentication) = &self.authentication {
            return Err(anyhow!(
                "the connection is already bound for authentication to host key {}",
                authentication
                    .destination
                    .host_key
                    .fingerprint(HashAlg::Sha256)
            ));
        }
        if self.forwarding.len() >= MAX_SESSION_BINDS {
            return Err(anyhow!(
                "this connection already holds {MAX_SESSION_BINDS} session binds"
            ));
        }

        let bound = Destination {
            host_key: host_key.into(),
            session_id: session_id.to_vec(),
        };
        if is_forwarding {
            self.forwarding.push(bound);
        } else {
            self.authentication = Some(Box::new(AuthenticationBind {
                destination: bound,
                contents: contents.to_vec(),
            }));
        }
        Ok(())
    }
}

impl DestinationPolicy {
    pub(super) fn lists_identities(&self, destinations: &Destinations) -> bool {
        // OpenSSH's identity_permitted hides destination-constrained keys from a connection
        // whose session-bind failed or that reaches the agent through a forwarding hop.
        match (self, destinations) {
            (Self::Unrestricted, _) => true,
            (Self::Restricted { .. }, Destinations::Bound(sessions)) => {
                sessions.forwarding.is_empty()
            }
            (Self::Restricted { .. }, Destinations::FailedBind) => false,
        }
    }

    pub(super) fn evaluate<'a>(
        &self,
        request: AgentSignRequest<'a>,
        destinations: &Destinations,
    ) -> Result<AuthorizedData<'a>> {
        let AgentSignRequest {
            public_key_blob: requested_key_blob,
            data,
        } = request;
        let Self::Restricted { namespaces, .. } = self else {
            return Ok(AuthorizedData(data));
        };
        let Destinations::Bound(sessions) = destinations else {
            return Err(anyhow!("a session-bind failed on this connection"));
        };

        match classify_signed_data(data) {
            SignedData::Userauth {
                session_id,
                public_key_blob,
                server_host_key_blob,
            } => {
                if public_key_blob != requested_key_blob {
                    return Err(anyhow!(
                        "the signed userauth blob names a different public key"
                    ));
                }
                if let Some(hop) = sessions.forwarding.first() {
                    return Err(anyhow!(
                        "the session-bind for host key {} is a forwarding hop",
                        hop.host_key.fingerprint(HashAlg::Sha256)
                    ));
                }

                let destination = sessions
                    .authentication
                    .as_deref()
                    .map(|bind| &bind.destination)
                    .filter(|destination| destination.session_id == session_id)
                    .ok_or_else(|| anyhow!("no verified session-bind matches the signed data"))?;
                if let Some(blob) = server_host_key_blob {
                    let signed_host_key = PublicKey::from_bytes(blob)
                        .context("decode the hostbound userauth server host key")?;
                    if *signed_host_key.key_data() != destination.host_key {
                        return Err(anyhow!(
                            "the hostbound userauth names host key {}, not the bound host key {}",
                            signed_host_key.fingerprint(HashAlg::Sha256),
                            destination.host_key.fingerprint(HashAlg::Sha256)
                        ));
                    }
                }
                Ok(AuthorizedData(data))
            }
            SignedData::SshSig { namespace } => {
                if let Some(bound) = sessions.forwarding.first().or(sessions
                    .authentication
                    .as_deref()
                    .map(|bind| &bind.destination))
                {
                    return Err(anyhow!(
                        "SSHSIG is refused on a connection bound to host key {}",
                        bound.host_key.fingerprint(HashAlg::Sha256)
                    ));
                }

                if namespaces.iter().any(|allowed| allowed == namespace) {
                    Ok(AuthorizedData(data))
                } else {
                    Err(anyhow!("SSHSIG namespace {namespace:?} is not allowed"))
                }
            }
            SignedData::Unrecognized => Err(anyhow!(
                "the signed data is neither SSH userauth nor SSHSIG"
            )),
        }
    }
}
