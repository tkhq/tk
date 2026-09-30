//! Tests for the SSH agent protocol and keyring-backed server.

use std::{
    collections::BTreeMap,
    io::{self, Error, ErrorKind},
    path::{Path, PathBuf},
    slice,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use rand_core::OsRng;
use signature::Signer;
use ssh_key::{Algorithm, PrivateKey, Signature};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    task::JoinHandle,
    time::{Duration, sleep},
};

use crate::wire::ssh::{
    Ed25519PublicKey,
    agent::{self, AgentIdentity, Keyring, SignError, SignFuture, destination::DestinationPolicy},
    build_signed_data, protocol,
};

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

fn spawn_agent(
    socket: PathBuf,
    keyring: Arc<dyn Keyring>,
    policy: DestinationPolicy,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        agent::run(socket, "600".parse().unwrap(), keyring, Arc::new(policy)).await
    })
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

struct UnrestrictedAgent {
    _directory: TempDir,
    socket: PathBuf,
    server: JoinHandle<Result<()>>,
}

impl UnrestrictedAgent {
    fn start(keyring: StubKeyring) -> Self {
        let directory = TempDir::new().expect("temporary directory should be created");
        let socket = directory.path().join("agent.sock");
        let server = spawn_agent(
            socket.clone(),
            Arc::new(keyring),
            DestinationPolicy::Unrestricted,
        );
        Self {
            _directory: directory,
            socket,
            server,
        }
    }
}

#[tokio::test]
async fn server_lists_and_signs_with_multiple_stub_identities() {
    let identities = vec![
        identity(0x11, "turnkey:first"),
        identity(0x22, "turnkey:second"),
        identity(0x55, "turnkey:refused"),
    ];
    let second_signature = [0x77; 64];
    let UnrestrictedAgent {
        _directory,
        socket,
        server,
    } = UnrestrictedAgent::start(StubKeyring {
        signatures: BTreeMap::from([
            (identities[0].public_key, [0x66; 64]),
            (identities[1].public_key, second_signature),
        ]),
        identities: identities.clone(),
        refused: identities[2].public_key,
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
    let identities = vec![identity(0x11, "turnkey:first")];
    let signature = [0x66; 64];
    let UnrestrictedAgent {
        _directory,
        socket,
        server,
    } = UnrestrictedAgent::start(StubKeyring {
        signatures: BTreeMap::from([(identities[0].public_key, signature)]),
        identities: identities.clone(),
        refused: Ed25519PublicKey::from_bytes([0xff; 32]),
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

#[tokio::test]
async fn unsupported_and_malformed_requests_are_refused_with_exact_codes() {
    let identities = vec![identity(0x11, "turnkey:first")];
    let UnrestrictedAgent {
        _directory,
        socket,
        server,
    } = UnrestrictedAgent::start(StubKeyring {
        signatures: BTreeMap::new(),
        identities: identities.clone(),
        refused: Ed25519PublicKey::from_bytes([0xff; 32]),
    });

    let identities_request =
        protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);

    let legacy_and_reserved = [0, 1, 2, 3, 4, 7, 8, 9, 10, 24]
        .into_iter()
        .chain(240..=255)
        .map(|message_type| encode_frame(message_type, &[]));
    let host = host_key();
    let unsupported = legacy_and_reserved.chain([
        extension_frame(b"query"),
        bind_frame(&host, false),
        bind_frame(&host, true),
        vec![0, 0, 0, 0],
    ]);

    let mut stream = connect(&socket).await.expect("agent socket should accept");
    for request in unsupported {
        assert_eq!(answer(&mut stream, &request).await, failure_frame());
        assert_eq!(
            answer(&mut stream, &identities_request).await,
            expected_identities_frame(&identities)
        );
    }

    let mut largest = encode_frame(0, &vec![0; (1 << 20) - 1]);
    assert_eq!(answer(&mut stream, &largest).await, failure_frame());
    largest[..4].copy_from_slice(&((1u32 << 20) + 1).to_be_bytes());
    assert_eq!(answer(&mut stream, &largest[..4]).await, failure_frame());
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .await
        .expect("the agent should close the connection after an oversized frame");
    assert_eq!(rest, Vec::<u8>::new());

    server.abort();
}

fn host_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("an Ed25519 host key should generate")
}

fn host_blob(key: &PrivateKey) -> Vec<u8> {
    key.public_key()
        .to_bytes()
        .expect("the host public key should encode")
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

fn bind_frame(key: &PrivateKey, is_forwarding: bool) -> Vec<u8> {
    bind_session_frame(key, &SESSION_ID, is_forwarding)
}

fn bind_session_frame(key: &PrivateKey, session_id: &[u8], is_forwarding: bool) -> Vec<u8> {
    session_bind_frame(
        &host_blob(key),
        session_id,
        &bind_signature(key, session_id),
        is_forwarding,
    )
}

fn forged_bind_frame(key: &PrivateKey, session_id: &[u8], is_forwarding: bool) -> Vec<u8> {
    let mut signature = bind_signature(key, session_id);
    let last = signature.len() - 1;
    signature[last] ^= 0x01;
    session_bind_frame(&host_blob(key), session_id, &signature, is_forwarding)
}

fn userauth_data(
    session_id: &[u8],
    public_key_blob: &[u8],
    has_signature: bool,
    server_host_key_blob: Option<&[u8]>,
) -> Vec<u8> {
    let mut data = Vec::new();
    encode_string(session_id, &mut data);
    data.push(50);
    encode_string(b"user", &mut data);
    encode_string(b"ssh-connection", &mut data);
    let method: &[u8] = match server_host_key_blob {
        Some(_) => b"publickey-hostbound-v00@openssh.com",
        None => b"publickey",
    };
    encode_string(method, &mut data);
    data.push(u8::from(has_signature));
    encode_string(b"ssh-ed25519", &mut data);
    encode_string(public_key_blob, &mut data);
    if let Some(blob) = server_host_key_blob {
        encode_string(blob, &mut data);
    }
    data
}

const SESSION_ID: [u8; 32] = [0xaa; 32];
const SIGNATURE: [u8; 64] = [0x66; 64];

fn success_frame() -> Vec<u8> {
    encode_frame(protocol::SSH_AGENT_SUCCESS, &[])
}

fn failure_frame() -> Vec<u8> {
    encode_frame(protocol::SSH_AGENT_FAILURE, &[])
}

fn extension_failure_frame() -> Vec<u8> {
    encode_frame(protocol::SSH_AGENT_EXTENSION_FAILURE, &[])
}

fn extension_frame(name: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_string(name, &mut payload);
    encode_frame(protocol::SSH_AGENTC_EXTENSION, &payload)
}

async fn answer(stream: &mut UnixStream, request: &[u8]) -> Vec<u8> {
    request_on(stream, request)
        .await
        .expect("the agent should answer on the connection")
}

async fn answer_fresh(socket: &Path, request: &[u8]) -> Vec<u8> {
    exchange(socket, request)
        .await
        .expect("the agent should answer on a fresh connection")
}

struct RestrictedAgent {
    _directory: TempDir,
    socket: PathBuf,
    served: AgentIdentity,
    allowed_host: PrivateKey,
    server: JoinHandle<Result<()>>,
}

impl RestrictedAgent {
    fn start(namespaces: &[&str]) -> Self {
        let directory = TempDir::new().expect("temporary directory should be created");
        let socket = directory.path().join("agent.sock");
        let served = identity(0x11, "turnkey:served");
        let allowed_host = host_key();
        let policy = DestinationPolicy::Restricted {
            hosts: vec![allowed_host.public_key().key_data().clone()],
            namespaces: namespaces.iter().map(ToString::to_string).collect(),
        };
        let keyring: Arc<dyn Keyring> = Arc::new(StubKeyring {
            signatures: BTreeMap::from([(served.public_key, SIGNATURE)]),
            identities: vec![served.clone()],
            refused: Ed25519PublicKey::from_bytes([0xff; 32]),
        });
        let server = spawn_agent(socket.clone(), keyring, policy);

        Self {
            _directory: directory,
            socket,
            served,
            allowed_host,
            server,
        }
    }

    async fn connect(&self) -> UnixStream {
        connect(&self.socket)
            .await
            .expect("agent socket should accept")
    }

    async fn bound_connection(&self) -> UnixStream {
        let mut stream = self.connect().await;
        assert_eq!(
            answer(&mut stream, &bind_frame(&self.allowed_host, false)).await,
            success_frame()
        );
        stream
    }

    fn sign_frame(&self, data: &[u8]) -> Vec<u8> {
        sign_request_frame(&self.served.public_key.blob(), data)
    }

    fn userauth_sign_frame(&self) -> Vec<u8> {
        let blob = self.served.public_key.blob();
        self.sign_frame(&userauth_data(&SESSION_ID, &blob, true, None))
    }
}

impl Drop for RestrictedAgent {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn a_restricted_agent_refuses_userauth_that_does_not_match_a_bound_session() {
    let agent = RestrictedAgent::start(&[]);
    let served_blob = agent.served.public_key.blob();

    let mut stream = agent.bound_connection().await;
    let mismatched = agent.sign_frame(&userauth_data(&[0xbb; 32], &served_blob, true, None));
    assert_eq!(answer(&mut stream, &mismatched).await, failure_frame());
    let foreign_key = agent.sign_frame(&userauth_data(
        &SESSION_ID,
        &Ed25519PublicKey::from_bytes([0x22; 32]).blob(),
        true,
        None,
    ));
    assert_eq!(answer(&mut stream, &foreign_key).await, failure_frame());

    assert_eq!(
        answer_fresh(&agent.socket, &agent.userauth_sign_frame()).await,
        failure_frame()
    );
    assert_eq!(
        answer_fresh(&agent.socket, &agent.sign_frame(b"ssh-agent-challenge")).await,
        failure_frame()
    );
}

#[tokio::test]
async fn a_forged_or_forwarding_session_bind_never_authorizes_signing() {
    let agent = RestrictedAgent::start(&[]);
    let host = &agent.allowed_host;
    let sign = agent.userauth_sign_frame();

    let forged = forged_bind_frame(host, &SESSION_ID, false);
    let mut stream = agent.connect().await;
    assert_eq!(
        answer(&mut stream, &forged).await,
        extension_failure_frame()
    );
    assert_eq!(answer(&mut stream, &sign).await, failure_frame());

    let resigned = session_bind_frame(
        &host_blob(host),
        &SESSION_ID,
        &bind_signature(host, &[0xbb; 32]),
        false,
    );
    let mut stream = agent.connect().await;
    assert_eq!(
        answer(&mut stream, &resigned).await,
        extension_failure_frame()
    );

    let mut stream = agent.connect().await;
    assert_eq!(
        answer(&mut stream, &bind_frame(host, true)).await,
        success_frame()
    );
    assert_eq!(answer(&mut stream, &sign).await, failure_frame());
}

#[tokio::test]
async fn a_hostbound_userauth_is_signed_only_for_the_bound_host_key() {
    let agent = RestrictedAgent::start(&[]);
    let served_blob = agent.served.public_key.blob();
    let hostbound = |server_host_key_blob: &[u8]| {
        agent.sign_frame(&userauth_data(
            &SESSION_ID,
            &served_blob,
            true,
            Some(server_host_key_blob),
        ))
    };

    let mut stream = agent.bound_connection().await;
    assert_eq!(
        answer(&mut stream, &hostbound(&host_blob(&agent.allowed_host))).await,
        expected_sign_response(&SIGNATURE)
    );
    assert_eq!(
        answer(&mut stream, &hostbound(&host_blob(&host_key()))).await,
        failure_frame()
    );
    assert_eq!(
        answer(&mut stream, &hostbound(&[0x00; 8])).await,
        failure_frame()
    );
}

#[tokio::test]
async fn a_forwarding_hop_anywhere_on_the_connection_refuses_userauth() {
    let agent = RestrictedAgent::start(&[]);
    let forwarding_hop = bind_session_frame(&host_key(), &[0xbb; 32], true);

    let mut stream = agent.connect().await;
    assert_eq!(answer(&mut stream, &forwarding_hop).await, success_frame());
    assert_eq!(
        answer(&mut stream, &bind_frame(&agent.allowed_host, false)).await,
        success_frame()
    );
    assert_eq!(
        answer(&mut stream, &agent.userauth_sign_frame()).await,
        failure_frame()
    );
}

#[tokio::test]
async fn malformed_session_binds_fail_and_unsupported_extensions_are_refused() {
    let agent = RestrictedAgent::start(&[]);

    let complete = bind_frame(&agent.allowed_host, false);
    let truncated = encode_frame(
        protocol::SSH_AGENTC_EXTENSION,
        &complete[5..complete.len() - 1],
    );

    let mut trailing_payload = complete[5..].to_vec();
    trailing_payload.push(0x00);
    let trailing = encode_frame(protocol::SSH_AGENTC_EXTENSION, &trailing_payload);

    for frame in [&truncated, &trailing] {
        assert_eq!(
            answer_fresh(&agent.socket, frame).await,
            extension_failure_frame()
        );
    }

    let nameless = encode_frame(protocol::SSH_AGENTC_EXTENSION, &[0, 0]);
    for frame in [
        extension_frame(b"unknown@example.com"),
        extension_frame(b"query"),
        nameless,
    ] {
        assert_eq!(answer_fresh(&agent.socket, &frame).await, failure_frame());
    }
}

#[tokio::test]
async fn a_failed_session_bind_taints_the_connection_for_userauth_and_sshsig() {
    let agent = RestrictedAgent::start(&["git"]);
    let host = &agent.allowed_host;
    let git = agent.sign_frame(&build_signed_data("git", b"payload"));

    let bad_signature = forged_bind_frame(host, &[0xbb; 32], true);
    let undecodable_host_key = session_bind_frame(
        &[0x00; 8],
        &[0xbb; 32],
        &bind_signature(host, &[0xbb; 32]),
        true,
    );

    for failing_forwarding_bind in [bad_signature, undecodable_host_key] {
        let mut stream = agent.connect().await;
        assert_eq!(
            answer(&mut stream, &failing_forwarding_bind).await,
            extension_failure_frame()
        );
        assert_eq!(answer(&mut stream, &git).await, failure_frame());

        assert_eq!(
            answer(&mut stream, &bind_frame(host, false)).await,
            extension_failure_frame()
        );
        assert_eq!(
            answer(&mut stream, &agent.userauth_sign_frame()).await,
            failure_frame()
        );
    }

    let mut stream = agent.bound_connection().await;
    assert_eq!(
        answer(&mut stream, &agent.userauth_sign_frame()).await,
        expected_sign_response(&SIGNATURE)
    );
    assert_eq!(
        answer_fresh(&agent.socket, &git).await,
        expected_sign_response(&SIGNATURE)
    );
}

#[tokio::test]
async fn a_refused_rebind_of_an_already_bound_session_taints_the_connection() {
    let agent = RestrictedAgent::start(&[]);

    let mut stream = agent.bound_connection().await;
    let relayed_rebind = bind_frame(&host_key(), false);
    assert_eq!(
        answer(&mut stream, &relayed_rebind).await,
        extension_failure_frame()
    );
    assert_eq!(
        answer(&mut stream, &agent.userauth_sign_frame()).await,
        failure_frame()
    );
}

#[tokio::test]
async fn a_connection_refuses_session_binds_past_the_openssh_limit() {
    let agent = RestrictedAgent::start(&[]);
    let bind = |session_id: [u8; 32]| bind_session_frame(&agent.allowed_host, &session_id, true);

    let mut stream = agent.connect().await;
    for index in 0..16 {
        assert_eq!(
            answer(&mut stream, &bind([index; 32])).await,
            success_frame()
        );
    }
    assert_eq!(
        answer(&mut stream, &bind([16; 32])).await,
        extension_failure_frame()
    );
}

#[tokio::test]
async fn a_session_bind_longer_than_the_openssh_limit_fails_and_taints_the_connection() {
    let agent = RestrictedAgent::start(&[]);
    let host = &agent.allowed_host;
    let blob = agent.served.public_key.blob();
    let userauth =
        |session_id: &[u8]| agent.sign_frame(&userauth_data(session_id, &blob, true, None));

    let mut stream = agent.connect().await;
    let too_long = [0xbb; 129];
    assert_eq!(
        answer(&mut stream, &bind_session_frame(host, &too_long, false)).await,
        extension_failure_frame()
    );
    assert_eq!(
        answer(&mut stream, &userauth(&too_long)).await,
        failure_frame()
    );

    let mut stream = agent.connect().await;
    let longest = [0xbb; 128];
    assert_eq!(
        answer(&mut stream, &bind_session_frame(host, &longest, false)).await,
        success_frame()
    );
    assert_eq!(
        answer(&mut stream, &userauth(&longest)).await,
        expected_sign_response(&SIGNATURE)
    );
}

#[tokio::test]
async fn a_bind_after_an_authentication_bind_is_refused_and_taints_the_connection() {
    let agent = RestrictedAgent::start(&[]);

    for is_forwarding in [false, true] {
        let mut stream = agent.bound_connection().await;
        let later = bind_session_frame(&host_key(), &[0xbb; 32], is_forwarding);
        assert_eq!(answer(&mut stream, &later).await, extension_failure_frame());
        assert_eq!(
            answer(&mut stream, &agent.userauth_sign_frame()).await,
            failure_frame()
        );
    }
}

#[tokio::test]
async fn forwarding_binds_followed_by_one_authentication_bind_are_accepted() {
    let agent = RestrictedAgent::start(&[]);

    let mut stream = agent.connect().await;
    for session_id in [[0xbb; 32], [0xcc; 32]] {
        assert_eq!(
            answer(
                &mut stream,
                &bind_session_frame(&host_key(), &session_id, true)
            )
            .await,
            success_frame()
        );
    }
    assert_eq!(
        answer(&mut stream, &bind_frame(&agent.allowed_host, false)).await,
        success_frame()
    );
    assert_eq!(
        answer(
            &mut stream,
            &bind_session_frame(&host_key(), &[0xdd; 32], true)
        )
        .await,
        extension_failure_frame()
    );
}

#[tokio::test]
async fn a_restricted_agent_lists_identities_only_without_a_forwarding_hop_or_failed_bind() {
    let agent = RestrictedAgent::start(&[]);
    let host = &agent.allowed_host;
    let identities_request =
        protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    let all = expected_identities_frame(slice::from_ref(&agent.served));
    let none = expected_identities_frame(&[]);

    let mut stream = agent.connect().await;
    assert_eq!(answer(&mut stream, &identities_request).await, all);

    let mut stream = agent.bound_connection().await;
    assert_eq!(answer(&mut stream, &identities_request).await, all);

    let mut stream = agent.connect().await;
    assert_eq!(
        answer(&mut stream, &bind_frame(host, true)).await,
        success_frame()
    );
    assert_eq!(answer(&mut stream, &identities_request).await, none);

    let forged = forged_bind_frame(host, &SESSION_ID, false);
    let mut stream = agent.connect().await;
    assert_eq!(
        answer(&mut stream, &forged).await,
        extension_failure_frame()
    );
    assert_eq!(answer(&mut stream, &identities_request).await, none);
}

#[tokio::test]
async fn an_sshsig_is_refused_on_a_connection_with_session_binds() {
    let agent = RestrictedAgent::start(&["git"]);
    let git = agent.sign_frame(&build_signed_data("git", b"payload"));

    for is_forwarding in [true, false] {
        let mut stream = agent.connect().await;
        assert_eq!(
            answer(&mut stream, &bind_frame(&agent.allowed_host, is_forwarding)).await,
            success_frame()
        );
        assert_eq!(answer(&mut stream, &git).await, failure_frame());
    }
}

#[test]
fn signed_data_classification_recognizes_userauth_and_sshsig_only() {
    let key = Ed25519PublicKey::from_bytes([0x11; 32]);

    let server_host_key = Ed25519PublicKey::from_bytes([0x22; 32]).blob();

    assert_eq!(
        protocol::classify_signed_data(&userauth_data(&SESSION_ID, &key.blob(), true, None)),
        protocol::SignedData::Userauth {
            session_id: &SESSION_ID,
            public_key_blob: &key.blob(),
            server_host_key_blob: None,
        }
    );
    assert_eq!(
        protocol::classify_signed_data(&userauth_data(
            &SESSION_ID,
            &key.blob(),
            true,
            Some(&server_host_key)
        )),
        protocol::SignedData::Userauth {
            session_id: &SESSION_ID,
            public_key_blob: &key.blob(),
            server_host_key_blob: Some(&server_host_key),
        }
    );

    let hostbound = userauth_data(&SESSION_ID, &key.blob(), true, Some(&server_host_key));
    let mut publickey_with_host_key = userauth_data(&SESSION_ID, &key.blob(), true, None);
    encode_string(&server_host_key, &mut publickey_with_host_key);
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
        &userauth_data(&SESSION_ID, &key.blob(), false, Some(&server_host_key)),
        &hostbound[..hostbound.len() - 1],
        &hostbound[..hostbound.len() - server_host_key.len() - 4],
        &publickey_with_host_key,
    ] {
        assert_eq!(
            protocol::classify_signed_data(unrecognized),
            protocol::SignedData::Unrecognized
        );
    }
}
