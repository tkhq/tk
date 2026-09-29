//! Tests for the SSH agent protocol and keyring-backed server.

use std::collections::BTreeMap;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::wire::ssh::agent::destination::DestinationPolicy;
use crate::wire::ssh::agent::{self, AgentIdentity, Keyring, SignError, SignFuture};
use crate::wire::ssh::protocol;
use crate::wire::ssh::{Ed25519PublicKey, build_signed_data};
use anyhow::{Result, anyhow};
use rand_core::OsRng;
use signature::Signer;
use ssh_key::{Algorithm, PrivateKey, Signature};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
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

    let (message_type, payload) =
        protocol::parse_agent_frame(&frame).expect("sign request frame should split");
    assert_eq!(message_type, protocol::SSH_AGENTC_SIGN_REQUEST);
    let request = protocol::parse_sign_request(payload).expect("sign request should parse");

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
fn sign_request_parser_rejects_malformed_frames_and_payloads() {
    let key = Ed25519PublicKey::from_bytes([0x11; 32]);
    let frame = sign_request_frame(&key.blob(), b"challenge");
    let truncated = &frame[..frame.len() - 1];

    let truncated_error =
        protocol::parse_agent_frame(truncated).expect_err("truncated frame should be rejected");
    assert_eq!(
        truncated_error.to_string(),
        "truncated SSH agent frame payload"
    );

    let malformed_error = protocol::parse_sign_request(&[0, 0, 0, 4, 1, 2])
        .expect_err("malformed payload should be rejected");
    assert_eq!(malformed_error.to_string(), "truncated SSH string body");
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
    let server = tokio::spawn(async move {
        agent::run(
            server_socket,
            "600".parse().unwrap(),
            keyring,
            Arc::new(DestinationPolicy::Unrestricted),
        )
        .await
    });

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
    let server = tokio::spawn(async move {
        agent::run(
            server_socket,
            "600".parse().unwrap(),
            keyring,
            Arc::new(DestinationPolicy::Unrestricted),
        )
        .await
    });

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

fn host_keypair() -> (PrivateKey, Vec<u8>) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .expect("an Ed25519 host key should generate");
    let blob = key
        .public_key()
        .to_bytes()
        .expect("the host public key should encode");
    (key, blob)
}

fn bind_signature(key: &PrivateKey, session_id: &[u8]) -> Vec<u8> {
    let signature: Signature = key
        .try_sign(session_id)
        .expect("the host key should sign the session id");
    let mut blob = Vec::new();
    encode_string(signature.algorithm().to_string().as_bytes(), &mut blob);
    encode_string(signature.as_bytes(), &mut blob);
    blob
}

fn session_bind_frame(
    host_key_blob: &[u8],
    session_id: &[u8],
    signature_blob: &[u8],
    is_forwarding: bool,
) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_string(b"session-bind@openssh.com", &mut payload);
    encode_string(host_key_blob, &mut payload);
    encode_string(session_id, &mut payload);
    encode_string(signature_blob, &mut payload);
    payload.push(u8::from(is_forwarding));
    encode_frame(protocol::SSH_AGENTC_EXTENSION, &payload)
}

fn userauth_data(
    session_id: &[u8],
    public_key_blob: &[u8],
    has_signature: bool,
    host_key_blob: Option<&[u8]>,
) -> Vec<u8> {
    let mut data = Vec::new();
    encode_string(session_id, &mut data);
    data.push(50);
    encode_string(b"user", &mut data);
    encode_string(b"ssh-connection", &mut data);
    let method: &[u8] = match host_key_blob {
        Some(_) => b"publickey-hostbound-v00@openssh.com",
        None => b"publickey",
    };
    encode_string(method, &mut data);
    data.push(u8::from(has_signature));
    encode_string(b"ssh-ed25519", &mut data);
    encode_string(public_key_blob, &mut data);
    if let Some(host_key_blob) = host_key_blob {
        encode_string(host_key_blob, &mut data);
    }
    data
}

const SESSION_ID: [u8; 32] = [0xaa; 32];

fn success_frame() -> Vec<u8> {
    encode_frame(protocol::SSH_AGENT_SUCCESS, &[])
}

fn failure_frame() -> Vec<u8> {
    encode_frame(protocol::SSH_AGENT_FAILURE, &[])
}

fn userauth_sign_frame(served: &AgentIdentity, host_key_blob: Option<&[u8]>) -> Vec<u8> {
    sign_request_frame(
        &served.public_key.blob(),
        &userauth_data(&SESSION_ID, &served.public_key.blob(), true, host_key_blob),
    )
}

struct RestrictedAgent {
    _directory: TempDir,
    socket: PathBuf,
    served: AgentIdentity,
    server: JoinHandle<Result<()>>,
    host_key: PrivateKey,
    host_blob: Vec<u8>,
}

impl RestrictedAgent {
    fn start(namespaces: &[&str]) -> Self {
        let (host_key, host_blob) = host_keypair();
        let policy = Arc::new(DestinationPolicy::Restricted {
            hosts: vec![host_key.public_key().key_data().clone()],
            namespaces: namespaces.iter().map(ToString::to_string).collect(),
        });
        let directory = TempDir::new().expect("temporary directory should be created");
        let socket = directory.path().join("agent.sock");
        let served = identity(0x11, "turnkey:served");
        let keyring: Arc<dyn Keyring> = Arc::new(StubKeyring {
            signatures: BTreeMap::from([(served.public_key, [0x66; 64])]),
            identities: vec![served.clone()],
            refused: Ed25519PublicKey::from_bytes([0xff; 32]),
        });
        let server_socket = socket.clone();
        let server = tokio::spawn(async move {
            agent::run(server_socket, "600".parse().unwrap(), keyring, policy).await
        });
        Self {
            _directory: directory,
            socket,
            served,
            server,
            host_key,
            host_blob,
        }
    }

    fn host_bind_frame(&self, is_forwarding: bool) -> Vec<u8> {
        session_bind_frame(
            &self.host_blob,
            &SESSION_ID,
            &bind_signature(&self.host_key, &SESSION_ID),
            is_forwarding,
        )
    }

    async fn bound_stream(&self) -> UnixStream {
        let mut stream = connect(&self.socket)
            .await
            .expect("agent socket should accept");
        assert_eq!(
            request_on(&mut stream, &self.host_bind_frame(false))
                .await
                .expect("bind should answer"),
            success_frame()
        );
        stream
    }
}

impl Drop for RestrictedAgent {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn a_bound_connection_to_an_allowed_host_signs_userauth_for_its_own_session_only() {
    let agent = RestrictedAgent::start(&["git"]);
    let failure = failure_frame();

    let mut stream = agent.bound_stream().await;
    let sign = userauth_sign_frame(&agent.served, None);
    assert_eq!(
        request_on(&mut stream, &sign)
            .await
            .expect("sign should answer"),
        expected_sign_response(&[0x66; 64])
    );
    let mismatched = sign_request_frame(
        &agent.served.public_key.blob(),
        &userauth_data(&[0xbb; 32], &agent.served.public_key.blob(), true, None),
    );
    assert_eq!(
        request_on(&mut stream, &mismatched)
            .await
            .expect("mismatched-session sign should answer"),
        failure
    );
    let foreign_key = sign_request_frame(
        &agent.served.public_key.blob(),
        &userauth_data(
            &SESSION_ID,
            &Ed25519PublicKey::from_bytes([0x22; 32]).blob(),
            true,
            None,
        ),
    );
    assert_eq!(
        request_on(&mut stream, &foreign_key)
            .await
            .expect("foreign-key sign should answer"),
        failure
    );
}

#[tokio::test]
async fn a_bound_connection_to_an_allowed_host_signs_hostbound_userauth_naming_the_bound_host_key()
{
    let agent = RestrictedAgent::start(&[]);

    let mut stream = agent.bound_stream().await;
    assert_eq!(
        request_on(
            &mut stream,
            &userauth_sign_frame(&agent.served, Some(&agent.host_blob))
        )
        .await
        .expect("hostbound sign should answer"),
        expected_sign_response(&[0x66; 64])
    );
}

#[tokio::test]
async fn hostbound_userauth_naming_a_host_key_other_than_the_bound_one_is_refused() {
    let agent = RestrictedAgent::start(&[]);
    let (_, other_blob) = host_keypair();

    let mut stream = agent.bound_stream().await;
    assert_eq!(
        request_on(
            &mut stream,
            &userauth_sign_frame(&agent.served, Some(&other_blob))
        )
        .await
        .expect("hostbound sign should answer"),
        failure_frame()
    );
}

#[tokio::test]
async fn a_verified_bind_to_a_host_outside_the_allowed_hosts_refuses_userauth() {
    let agent = RestrictedAgent::start(&["git"]);
    let (other_key, other_blob) = host_keypair();

    let mut stream = connect(&agent.socket)
        .await
        .expect("agent socket should accept");
    let bind = session_bind_frame(
        &other_blob,
        &SESSION_ID,
        &bind_signature(&other_key, &SESSION_ID),
        false,
    );
    assert_eq!(
        request_on(&mut stream, &bind)
            .await
            .expect("bind should answer"),
        success_frame()
    );
    let sign = userauth_sign_frame(&agent.served, None);
    assert_eq!(
        request_on(&mut stream, &sign)
            .await
            .expect("sign should answer"),
        failure_frame()
    );
}

#[tokio::test]
async fn an_unbound_connection_signs_only_sshsig_in_an_allowed_namespace() {
    let agent = RestrictedAgent::start(&["git"]);
    let failure = failure_frame();

    let unbound_userauth = userauth_sign_frame(&agent.served, None);
    assert_eq!(
        exchange(&agent.socket, &unbound_userauth)
            .await
            .expect("unbound sign should answer"),
        failure
    );
    let raw = sign_request_frame(&agent.served.public_key.blob(), b"ssh-agent-challenge");
    assert_eq!(
        exchange(&agent.socket, &raw)
            .await
            .expect("raw sign should answer"),
        failure
    );
    let git = sign_request_frame(
        &agent.served.public_key.blob(),
        &build_signed_data("git", b"payload"),
    );
    assert_eq!(
        exchange(&agent.socket, &git)
            .await
            .expect("git sign should answer"),
        expected_sign_response(&[0x66; 64])
    );
    let file = sign_request_frame(
        &agent.served.public_key.blob(),
        &build_signed_data("file", b"payload"),
    );
    assert_eq!(
        exchange(&agent.socket, &file)
            .await
            .expect("file sign should answer"),
        failure
    );
}

#[tokio::test]
async fn a_forged_host_signature_bind_refuses_every_later_bind_and_restricted_sign() {
    let agent = RestrictedAgent::start(&["git"]);
    let failure = failure_frame();

    let mut forged_signature = bind_signature(&agent.host_key, &SESSION_ID);
    let last = forged_signature.len() - 1;
    forged_signature[last] ^= 0x01;
    let mut stream = connect(&agent.socket)
        .await
        .expect("agent socket should accept");
    let forged = session_bind_frame(&agent.host_blob, &SESSION_ID, &forged_signature, false);
    assert_eq!(
        request_on(&mut stream, &forged)
            .await
            .expect("forged bind should answer"),
        failure
    );
    assert_eq!(
        request_on(&mut stream, &agent.host_bind_frame(false))
            .await
            .expect("valid bind should answer"),
        failure
    );
    assert_eq!(
        request_on(&mut stream, &userauth_sign_frame(&agent.served, None))
            .await
            .expect("sign should answer"),
        failure
    );
    let git = sign_request_frame(
        &agent.served.public_key.blob(),
        &build_signed_data("git", b"payload"),
    );
    assert_eq!(
        request_on(&mut stream, &git)
            .await
            .expect("git sign should answer"),
        failure
    );
}

#[tokio::test]
async fn a_bind_signed_over_another_session_id_is_refused() {
    let agent = RestrictedAgent::start(&[]);

    let mut stream = connect(&agent.socket)
        .await
        .expect("agent socket should accept");
    let resigned = session_bind_frame(
        &agent.host_blob,
        &SESSION_ID,
        &bind_signature(&agent.host_key, &[0xbb; 32]),
        false,
    );
    assert_eq!(
        request_on(&mut stream, &resigned)
            .await
            .expect("mismatched bind should answer"),
        failure_frame()
    );
}

#[tokio::test]
async fn a_forwarding_bind_verifies_but_never_authorizes_signing() {
    let agent = RestrictedAgent::start(&[]);

    let mut stream = connect(&agent.socket)
        .await
        .expect("agent socket should accept");
    assert_eq!(
        request_on(&mut stream, &agent.host_bind_frame(true))
            .await
            .expect("forwarding bind should answer"),
        success_frame()
    );
    assert_eq!(
        request_on(&mut stream, &userauth_sign_frame(&agent.served, None))
            .await
            .expect("sign should answer"),
        failure_frame()
    );
}

#[tokio::test]
async fn a_bind_after_a_forwarding_bind_is_refused_and_the_connection_signs_nothing() {
    let agent = RestrictedAgent::start(&["git"]);
    let (hop_key, hop_blob) = host_keypair();
    let failure = failure_frame();

    let mut stream = connect(&agent.socket)
        .await
        .expect("agent socket should accept");
    let forwarding = session_bind_frame(
        &hop_blob,
        &[0xbb; 32],
        &bind_signature(&hop_key, &[0xbb; 32]),
        true,
    );
    assert_eq!(
        request_on(&mut stream, &forwarding)
            .await
            .expect("forwarding bind should answer"),
        success_frame()
    );
    assert_eq!(
        request_on(&mut stream, &agent.host_bind_frame(false))
            .await
            .expect("second bind should answer"),
        failure
    );
    assert_eq!(
        request_on(&mut stream, &userauth_sign_frame(&agent.served, None))
            .await
            .expect("userauth sign should answer"),
        failure
    );
    let git = sign_request_frame(
        &agent.served.public_key.blob(),
        &build_signed_data("git", b"payload"),
    );
    assert_eq!(
        request_on(&mut stream, &git)
            .await
            .expect("git sign should answer"),
        failure
    );
}

#[tokio::test]
async fn malformed_or_foreign_extension_frames_are_refused() {
    let agent = RestrictedAgent::start(&[]);
    let failure = failure_frame();

    let complete = agent.host_bind_frame(false);
    let truncated = encode_frame(
        protocol::SSH_AGENTC_EXTENSION,
        &complete[5..complete.len() - 1],
    );

    let mut trailing_payload = complete[5..].to_vec();
    trailing_payload.push(0x00);
    let trailing = encode_frame(protocol::SSH_AGENTC_EXTENSION, &trailing_payload);

    let mut foreign_payload = Vec::new();
    encode_string(b"unknown@example.com", &mut foreign_payload);
    let foreign = encode_frame(protocol::SSH_AGENTC_EXTENSION, &foreign_payload);

    for frame in [&truncated, &trailing, &foreign] {
        assert_eq!(
            exchange(&agent.socket, frame)
                .await
                .expect("extension should answer"),
            failure
        );
    }
}

#[tokio::test]
async fn a_second_bind_for_an_already_bound_session_is_refused() {
    let agent = RestrictedAgent::start(&[]);
    let (other_key, other_blob) = host_keypair();

    let mut stream = agent.bound_stream().await;
    let rebind = session_bind_frame(
        &other_blob,
        &SESSION_ID,
        &bind_signature(&other_key, &SESSION_ID),
        false,
    );
    assert_eq!(
        request_on(&mut stream, &rebind)
            .await
            .expect("second bind should answer"),
        failure_frame()
    );
    let sign = userauth_sign_frame(&agent.served, None);
    assert_eq!(
        request_on(&mut stream, &sign)
            .await
            .expect("sign should answer"),
        expected_sign_response(&[0x66; 64])
    );
}

#[test]
fn signed_data_classification_recognizes_userauth_and_sshsig_only() {
    let key = Ed25519PublicKey::from_bytes([0x11; 32]);

    assert_eq!(
        protocol::classify_signed_data(&userauth_data(&SESSION_ID, &key.blob(), true, None)),
        protocol::SignedData::Userauth {
            session_id: &SESSION_ID,
            public_key_blob: &key.blob(),
            host_key_blob: None,
        }
    );
    assert_eq!(
        protocol::classify_signed_data(&userauth_data(
            &SESSION_ID,
            &key.blob(),
            true,
            Some(b"host-key")
        )),
        protocol::SignedData::Userauth {
            session_id: &SESSION_ID,
            public_key_blob: &key.blob(),
            host_key_blob: Some(b"host-key"),
        }
    );
    assert_eq!(
        protocol::classify_signed_data(&build_signed_data("git", b"payload")),
        protocol::SignedData::SshSig { namespace: "git" }
    );
    for unrecognized in [
        &b"ssh-agent-challenge"[..],
        &b""[..],
        &b"SSHSIG"[..],
        &userauth_data(&SESSION_ID, &key.blob(), true, None)[..8],
        &userauth_data(&SESSION_ID, &key.blob(), false, None),
    ] {
        assert_eq!(
            protocol::classify_signed_data(unrecognized),
            protocol::SignedData::Unrecognized
        );
    }
}
