//! Tests for the SSH agent protocol and keyring-backed server.

use std::collections::BTreeMap;
use std::io::{self, Error, ErrorKind};
use std::path::Path;
use std::sync::Arc;

use crate::wire::ssh::Ed25519PublicKey;
use crate::wire::ssh::agent::{self, AgentIdentity, Keyring, SignError, SignFuture};
use crate::wire::ssh::protocol;
use anyhow::anyhow;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Duration, sleep};

fn encode_string(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn encode_frame(message_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(message_type);
    frame.extend_from_slice(payload);
    frame
}

fn identity(byte: u8, comment: &str) -> AgentIdentity {
    AgentIdentity {
        public_key: Ed25519PublicKey::from_bytes([byte; 32]),
        comment: comment.to_string(),
    }
}

fn expected_identities_frame(identities: &[AgentIdentity]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for identity in identities {
        encode_string(&identity.public_key.blob(), &mut payload);
        encode_string(identity.comment.as_bytes(), &mut payload);
    }
    encode_frame(protocol::SSH_AGENT_IDENTITIES_ANSWER, &payload)
}

fn sign_request_frame(public_key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_string(public_key_blob, &mut payload);
    encode_string(data, &mut payload);
    payload.extend_from_slice(&0x0000_0004u32.to_be_bytes());
    encode_frame(protocol::SSH_AGENTC_SIGN_REQUEST, &payload)
}

fn expected_sign_response(signature: &[u8]) -> Vec<u8> {
    let mut signature_blob = Vec::new();
    encode_string(b"ssh-ed25519", &mut signature_blob);
    encode_string(signature, &mut signature_blob);

    let mut payload = Vec::new();
    encode_string(&signature_blob, &mut payload);
    encode_frame(protocol::SSH_AGENT_SIGN_RESPONSE, &payload)
}

#[test]
fn identities_response_encodes_zero_one_and_three_keys() {
    for identities in [
        Vec::new(),
        vec![identity(0x11, "one")],
        vec![
            identity(0x11, "one"),
            identity(0x22, "two"),
            identity(0x33, "three"),
        ],
    ] {
        assert_eq!(
            protocol::encode_request_identities_response(&identities),
            expected_identities_frame(&identities)
        );
    }
}

#[test]
fn parse_sign_request_frame_extracts_key_blob_and_payload() {
    let key = Ed25519PublicKey::from_bytes([0x11; 32]);
    let frame = sign_request_frame(&key.blob(), b"ssh-agent-challenge");

    let request = protocol::parse_sign_request_frame(&frame).expect("sign request should parse");

    assert_eq!(request.public_key_blob, key.blob());
    assert_eq!(request.data, b"ssh-agent-challenge");
}

#[test]
fn sign_response_matches_expected_frame() {
    let signature = [0x22; 64];

    assert_eq!(
        protocol::encode_sign_response(&signature),
        expected_sign_response(&signature)
    );
}

#[test]
fn sign_request_parser_rejects_malformed_or_unsupported_frames() {
    let key = Ed25519PublicKey::from_bytes([0x11; 32]);
    let frame = sign_request_frame(&key.blob(), b"challenge");
    let truncated = &frame[..frame.len() - 1];

    let truncated_error = protocol::parse_sign_request_frame(truncated)
        .expect_err("truncated frame should be rejected");
    assert_eq!(
        truncated_error.to_string(),
        "truncated SSH agent frame payload"
    );

    let unsupported = encode_frame(99, &[]);
    let unsupported_error = protocol::parse_sign_request_frame(&unsupported)
        .expect_err("unsupported frame should be rejected");
    assert_eq!(
        unsupported_error.to_string(),
        "unsupported SSH agent message type: 99"
    );
}

struct StubKeyring {
    identities: Vec<AgentIdentity>,
    signatures: BTreeMap<Ed25519PublicKey, [u8; 64]>,
    refused: Ed25519PublicKey,
}

impl Keyring for StubKeyring {
    fn identities(&self) -> Vec<AgentIdentity> {
        self.identities.clone()
    }

    fn sign<'a>(&'a self, public_key: &'a Ed25519PublicKey, _data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            if *public_key == self.refused {
                return Err(SignError::Signer(anyhow!("the signer refused")));
            }
            self.signatures
                .get(public_key)
                .copied()
                .ok_or(SignError::UnknownKey)
        })
    }
}

async fn connect(socket: &Path) -> io::Result<UnixStream> {
    for _ in 0..1_000 {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::NotFound => tokio::task::yield_now().await,
            Err(error) => return Err(error),
        }
    }
    Err(Error::new(
        ErrorKind::NotFound,
        "test agent did not bind its socket",
    ))
}

async fn exchange(socket: &Path, request: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = connect(socket).await?;
    request_on(&mut stream, request).await
}

async fn request_on(stream: &mut UnixStream, request: &[u8]) -> io::Result<Vec<u8>> {
    stream.write_all(request).await?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let mut response = length.to_vec();
    let mut body = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).await?;
    response.extend_from_slice(&body);
    Ok(response)
}

#[tokio::test]
async fn server_lists_and_signs_with_multiple_stub_identities() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let socket = directory.path().join("agent.sock");
    let identities = vec![
        identity(0x11, "turnkey:first"),
        identity(0x22, "turnkey:second"),
        identity(0x55, "turnkey:refused"),
    ];
    let second_signature = [0x77; 64];
    let keyring: Arc<dyn Keyring> = Arc::new(StubKeyring {
        signatures: BTreeMap::from([
            (identities[0].public_key, [0x66; 64]),
            (identities[1].public_key, second_signature),
        ]),
        identities: identities.clone(),
        refused: identities[2].public_key,
    });
    let server_socket = socket.clone();
    let server =
        tokio::spawn(
            async move { agent::run(server_socket, "600".parse().unwrap(), keyring).await },
        );

    let identities_request =
        protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    assert_eq!(
        exchange(&socket, &identities_request)
            .await
            .expect("identities response should read"),
        expected_identities_frame(&identities)
    );

    let sign_second = sign_request_frame(&identities[1].public_key.blob(), b"ssh-agent-challenge");
    assert_eq!(
        exchange(&socket, &sign_second)
            .await
            .expect("sign response should read"),
        expected_sign_response(&second_signature)
    );

    let unknown = sign_request_frame(
        &Ed25519PublicKey::from_bytes([0x33; 32]).blob(),
        b"ssh-agent-challenge",
    );
    let failure = protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[]);
    assert_eq!(
        exchange(&socket, &unknown)
            .await
            .expect("unknown-key response should read"),
        failure
    );

    let refused = sign_request_frame(&identities[2].public_key.blob(), b"ssh-agent-challenge");
    assert_eq!(
        exchange(&socket, &refused)
            .await
            .expect("refused-signer response should read"),
        failure
    );

    let mut rsa_blob = Vec::new();
    encode_string(b"ssh-rsa", &mut rsa_blob);
    encode_string(&[0x44; 32], &mut rsa_blob);
    let rsa = sign_request_frame(&rsa_blob, b"ssh-agent-challenge");
    assert_eq!(
        exchange(&socket, &rsa)
            .await
            .expect("unsupported-key response should read"),
        failure
    );

    let malformed = encode_frame(protocol::SSH_AGENTC_SIGN_REQUEST, &[0, 0, 0, 4, 1, 2]);
    assert_eq!(
        exchange(&socket, &malformed)
            .await
            .expect("malformed-request response should read"),
        failure
    );

    server.abort();
    let join_error = server
        .await
        .expect_err("aborted server should report cancellation");
    assert!(join_error.is_cancelled());
}

#[tokio::test]
async fn a_connection_idle_between_requests_still_gets_a_signature() {
    let directory = TempDir::new().expect("temporary directory should be created");
    let socket = directory.path().join("agent.sock");
    let identities = vec![identity(0x11, "turnkey:first")];
    let signature = [0x66; 64];
    let keyring: Arc<dyn Keyring> = Arc::new(StubKeyring {
        signatures: BTreeMap::from([(identities[0].public_key, signature)]),
        identities: identities.clone(),
        refused: Ed25519PublicKey::from_bytes([0xff; 32]),
    });
    let server_socket = socket.clone();
    let server =
        tokio::spawn(
            async move { agent::run(server_socket, "600".parse().unwrap(), keyring).await },
        );

    let mut stream = connect(&socket).await.expect("agent socket should accept");
    let identities_request =
        protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    assert_eq!(
        request_on(&mut stream, &identities_request)
            .await
            .expect("identities response should read"),
        expected_identities_frame(&identities)
    );

    // OpenSSH waits a server round trip before signing; that idle gap must not
    // close the connection.
    sleep(Duration::from_millis(750)).await;

    let sign = sign_request_frame(&identities[0].public_key.blob(), b"ssh-agent-challenge");
    assert_eq!(
        request_on(&mut stream, &sign)
            .await
            .expect("sign response should read after an idle gap"),
        expected_sign_response(&signature)
    );

    server.abort();
    let join_error = server
        .await
        .expect_err("aborted server should report cancellation");
    assert!(join_error.is_cancelled());
}
