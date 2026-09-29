//! Destination constraints limiting which servers an agent signs for.

use anyhow::{Result, anyhow};
use signature::Verifier;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, PublicKey, Signature};

use super::super::Ed25519PublicKey;
use super::super::protocol::{SessionBind, SignedData, classify_signed_data};

/// The destinations an agent signs for.
pub enum DestinationPolicy {
    /// Sign any request, as an agent without constraints does.
    Unrestricted,
    /// Sign only for bound allowed hosts and listed `SSHSIG` namespaces.
    Restricted {
        /// The host keys the agent may sign userauth requests for.
        hosts: Vec<KeyData>,
        /// The `SSHSIG` namespaces the agent may sign payloads in.
        namespaces: Vec<String>,
    },
}

pub(super) enum SessionBinding {
    Authentication {
        host_key: KeyData,
        session_id: Vec<u8>,
    },
    Forwarding {
        host_key: KeyData,
    },
}

const FAILED_BIND: &str = "an earlier session-bind on this connection failed to verify";

#[derive(Default)]
pub(super) enum Destinations {
    #[default]
    Unbound,
    Bound(SessionBinding),
    Refused,
}

impl Destinations {
    pub(super) fn bind(&mut self, verified: Result<SessionBinding>) -> Result<()> {
        match (&*self, verified) {
            (Self::Refused, _) => Err(anyhow!(FAILED_BIND)),
            (_, Err(error)) => {
                *self = Self::Refused;
                Err(error)
            }
            (Self::Bound(_), Ok(_)) => Err(anyhow!("this connection already has a session-bind")),
            (Self::Unbound, Ok(binding)) => {
                *self = Self::Bound(binding);
                Ok(())
            }
        }
    }
}

pub(super) struct AuthorizedSign<'a> {
    public_key: Ed25519PublicKey,
    data: &'a [u8],
}

impl<'a> AuthorizedSign<'a> {
    pub(super) fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub(super) fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl DestinationPolicy {
    pub(super) fn authorize<'a>(
        &self,
        public_key: Ed25519PublicKey,
        data: &'a [u8],
        destinations: &Destinations,
    ) -> Result<AuthorizedSign<'a>> {
        let authorized = AuthorizedSign { public_key, data };
        match self {
            Self::Unrestricted => Ok(authorized),
            Self::Restricted { hosts, namespaces } => {
                let binding = match destinations {
                    Destinations::Refused => return Err(anyhow!(FAILED_BIND)),
                    Destinations::Bound(SessionBinding::Forwarding { host_key }) => {
                        return Err(anyhow!(
                            "the session-bind for host key {} is a forwarding hop",
                            host_key.fingerprint(HashAlg::Sha256)
                        ));
                    }
                    Destinations::Unbound => None,
                    Destinations::Bound(SessionBinding::Authentication {
                        host_key,
                        session_id,
                    }) => Some((host_key, session_id)),
                };
                match classify_signed_data(data) {
                    SignedData::Userauth {
                        session_id,
                        public_key_blob,
                        host_key_blob,
                    } => {
                        if Ed25519PublicKey::from_blob(public_key_blob).ok() != Some(public_key) {
                            return Err(anyhow!(
                                "the signed userauth blob names a different public key"
                            ));
                        }
                        let host_key = match binding {
                            Some((host_key, bound_session_id))
                                if bound_session_id == session_id =>
                            {
                                host_key
                            }
                            _ => {
                                return Err(anyhow!(
                                    "no verified session-bind matches the signed data"
                                ));
                            }
                        };
                        if !hosts.contains(host_key) {
                            return Err(anyhow!(
                                "host key {} is not in the allowed hosts file",
                                host_key.fingerprint(HashAlg::Sha256)
                            ));
                        }
                        if let Some(host_key_blob) = host_key_blob
                            && !PublicKey::from_bytes(host_key_blob)
                                .is_ok_and(|signed| signed.key_data() == host_key)
                        {
                            return Err(anyhow!(
                                "the signed userauth names a server host key other than the bound host key {}",
                                host_key.fingerprint(HashAlg::Sha256)
                            ));
                        }
                        Ok(authorized)
                    }
                    SignedData::SshSig { namespace } => {
                        if namespaces.iter().any(|allowed| allowed == namespace) {
                            Ok(authorized)
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
    }
}

pub(super) fn verify_session_bind(bind: SessionBind<'_>) -> Result<SessionBinding> {
    let SessionBind {
        host_key_blob,
        session_id,
        signature_blob,
        is_forwarding,
    } = bind;
    let host_key = PublicKey::from_bytes(host_key_blob)?;
    let signature = Signature::try_from(signature_blob)?;
    host_key.key_data().verify(session_id, &signature)?;
    let host_key = host_key.into();
    Ok(if is_forwarding {
        SessionBinding::Forwarding { host_key }
    } else {
        SessionBinding::Authentication {
            host_key,
            session_id: session_id.to_vec(),
        }
    })
}
