//! SSH agent protocol helpers.
//!
//! Reference docs:
//! - <https://www.rfc-editor.org/rfc/rfc9987>
//! - <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent>

use std::io::{self, Error, ErrorKind};

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

use super::{SSHSIG_PREAMBLE, agent::AgentIdentity, read_ssh_bytes};

const SSH_ED25519_ALGORITHM: &str = "ssh-ed25519";
const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const USERAUTH_PUBLICKEY: &[u8] = b"publickey";
const USERAUTH_PUBLICKEY_HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_AGENT_FRAME_SIZE: usize = 1 << 20;
// OpenSSH's AGENT_MAX_SID_LEN; process_ext_session_bind refuses longer session IDs.
const MAX_SESSION_ID_LEN: usize = 128;

/// Generic SSH agent failure response message code.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub(super) const SSH_AGENT_SUCCESS: u8 = 6;
/// SSH agent request code for listing available identities.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// SSH agent response code for returning identities.
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// SSH agent request code for signing data with a key.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// SSH agent response code for returning a signature.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub(super) const SSH_AGENTC_EXTENSION: u8 = 27;
pub(super) const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

#[cfg_attr(test, derive(Debug))]
pub(super) struct AgentSignRequest<'a> {
    pub public_key_blob: &'a [u8],
    pub data: &'a [u8],
}

pub(super) struct SessionBind<'a> {
    pub host_key_blob: &'a [u8],
    pub session_id: &'a [u8],
    pub signature_blob: &'a [u8],
    pub is_forwarding: bool,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub(super) enum SignedData<'a> {
    Userauth {
        session_id: &'a [u8],
        public_key_blob: &'a [u8],
        server_host_key_blob: Option<&'a [u8]>,
    },
    SshSig {
        namespace: &'a str,
    },
    Unrecognized,
}

/// Encodes an SSH agent packet with the given message type and payload.
pub fn encode_agent_frame(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 1 + payload.len());
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(message_type);
    frame.extend_from_slice(payload);
    frame
}

/// Reads one SSH agent frame from a Unix stream with a bounded size.
///
/// The length prefix is awaited without a deadline, because between requests it
/// is the idle wait for the next one. Once a length is known the rest of the
/// frame must arrive within `CONNECTION_IO_TIMEOUT`. Callers that must not
/// block indefinitely impose their own deadline on the whole read.
pub async fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut length_bytes = [0u8; 4];
    match stream.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_AGENT_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "SSH agent frame exceeds maximum size",
        ));
    }

    let mut frame = vec![0u8; 4 + length];
    frame[..4].copy_from_slice(&length_bytes);
    read_exact_with_deadline(stream, &mut frame[4..]).await?;
    Ok(Some(frame))
}

/// Writes one SSH agent frame to a Unix stream with a timeout.
pub(crate) async fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> io::Result<()> {
    match timeout(CONNECTION_IO_TIMEOUT, stream.write_all(frame)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::from(ErrorKind::TimedOut)),
    }
}

/// Encodes an `SSH_AGENT_IDENTITIES_ANSWER` packet for all available identities.
pub fn encode_request_identities_response(identities: &[AgentIdentity]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for identity in identities {
        payload = encode_string(&identity.public_key.blob(), payload);
        payload = encode_string(identity.comment.as_bytes(), payload);
    }
    encode_agent_frame(SSH_AGENT_IDENTITIES_ANSWER, &payload)
}

pub(super) fn parse_sign_request(payload: &[u8]) -> Result<AgentSignRequest<'_>> {
    let mut cursor = payload;
    let public_key_blob = read_ssh_bytes(&mut cursor)?;
    let data = read_ssh_bytes(&mut cursor)?;
    read_u32(&mut cursor)?;

    if !cursor.is_empty() {
        return Err(anyhow!("unexpected trailing SSH agent sign request data"));
    }

    Ok(AgentSignRequest {
        public_key_blob,
        data,
    })
}

pub(super) fn parse_extension(payload: &[u8]) -> Option<&[u8]> {
    let mut cursor = payload;
    let name = read_ssh_bytes(&mut cursor).ok()?;
    (name == SESSION_BIND_EXTENSION).then_some(cursor)
}

pub(super) fn parse_session_bind(contents: &[u8]) -> Result<SessionBind<'_>> {
    let mut cursor = contents;
    let host_key_blob = read_ssh_bytes(&mut cursor)?;
    let session_id = read_ssh_bytes(&mut cursor)?;
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(anyhow!(
            "session-bind session ID is longer than {MAX_SESSION_ID_LEN} bytes"
        ));
    }
    let signature_blob = read_ssh_bytes(&mut cursor)?;
    let Some((&flag, rest)) = cursor.split_first() else {
        return Err(anyhow!("truncated SSH agent boolean"));
    };
    if !rest.is_empty() {
        return Err(anyhow!("unexpected trailing SSH agent session-bind data"));
    }

    Ok(SessionBind {
        host_key_blob,
        session_id,
        signature_blob,
        // RFC 4251 section 5: any nonzero byte is true.
        is_forwarding: flag != 0,
    })
}

pub(super) fn classify_signed_data(data: &[u8]) -> SignedData<'_> {
    if let Some(userauth) = parse_userauth(data) {
        return userauth;
    }
    if let Some(namespace) = parse_sshsig_namespace(data) {
        return SignedData::SshSig { namespace };
    }
    SignedData::Unrecognized
}

fn parse_userauth(data: &[u8]) -> Option<SignedData<'_>> {
    let mut cursor = data;
    let session_id = read_ssh_bytes(&mut cursor).ok()?;
    let (message_type, mut cursor) = cursor.split_first()?;
    if *message_type != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    read_ssh_bytes(&mut cursor).ok()?;
    if read_ssh_bytes(&mut cursor).ok()? != b"ssh-connection".as_slice() {
        return None;
    }

    let method = read_ssh_bytes(&mut cursor).ok()?;
    let is_hostbound = match method {
        USERAUTH_PUBLICKEY => false,
        USERAUTH_PUBLICKEY_HOSTBOUND => true,
        _ => return None,
    };

    let (has_signature, mut cursor) = cursor.split_first()?;
    // RFC 4252 section 7 includes TRUE here in the data covered by the signature.
    if *has_signature == 0 {
        return None;
    }
    read_ssh_bytes(&mut cursor).ok()?;
    let public_key_blob = read_ssh_bytes(&mut cursor).ok()?;
    // OpenSSH PROTOCOL section 3.1: the hostbound method appends the server
    // host key blob after the user's public key blob.
    let server_host_key_blob = if is_hostbound {
        Some(read_ssh_bytes(&mut cursor).ok()?)
    } else {
        None
    };

    if !cursor.is_empty() {
        return None;
    }

    Some(SignedData::Userauth {
        session_id,
        public_key_blob,
        server_host_key_blob,
    })
}

fn parse_sshsig_namespace(data: &[u8]) -> Option<&str> {
    let mut cursor = data.strip_prefix(SSHSIG_PREAMBLE)?;
    let namespace = read_ssh_bytes(&mut cursor).ok()?;
    for _ in 0..3 {
        read_ssh_bytes(&mut cursor).ok()?;
    }
    if !cursor.is_empty() {
        return None;
    }
    str::from_utf8(namespace).ok()
}

/// Encodes a `SSH_AGENT_SIGN_RESPONSE` packet for a 64-byte Ed25519 signature.
pub fn encode_sign_response(signature: &[u8; 64]) -> Vec<u8> {
    let mut signature_blob = Vec::new();
    signature_blob = encode_string(SSH_ED25519_ALGORITHM.as_bytes(), signature_blob);
    signature_blob = encode_string(signature, signature_blob);

    let mut payload = Vec::new();
    payload = encode_string(&signature_blob, payload);
    encode_agent_frame(SSH_AGENT_SIGN_RESPONSE, &payload)
}

async fn read_exact_with_deadline(stream: &mut UnixStream, buf: &mut [u8]) -> io::Result<()> {
    match timeout(CONNECTION_IO_TIMEOUT, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(Error::from(ErrorKind::TimedOut)),
    }
}

fn encode_string(bytes: &[u8], mut output: Vec<u8>) -> Vec<u8> {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

pub(super) fn parse_agent_frame(frame: &[u8]) -> Result<(u8, &[u8])> {
    let Some((length, payload)) = frame.split_first_chunk::<4>() else {
        return Err(anyhow!("truncated SSH agent frame length"));
    };
    let length = u32::from_be_bytes(*length) as usize;
    if payload.len() < length {
        return Err(anyhow!("truncated SSH agent frame payload"));
    }
    if payload.len() != length {
        return Err(anyhow!("unexpected trailing bytes in SSH agent frame"));
    }
    let Some((kind, body)) = payload.split_first() else {
        return Err(anyhow!("truncated SSH agent frame payload"));
    };

    Ok((*kind, body))
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32> {
    let Some((value, rest)) = cursor.split_first_chunk::<4>() else {
        return Err(anyhow!("truncated SSH agent unsigned 32-bit integer"));
    };
    *cursor = rest;
    Ok(u32::from_be_bytes(*value))
}
