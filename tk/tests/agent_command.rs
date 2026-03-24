use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::tempdir;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::ssh;
use turnkey_auth::ssh::protocol;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TURNKEY_TEST_PUBLIC_KEY: [u8; 32] = [0x66; 32];
const TURNKEY_TEST_SIGNATURE: [u8; 64] = [0x22; 64];
const TURNKEY_TEST_V: &str = "00";
const CLIENT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(600);
const HELD_CONNECTION_DURATION: Duration = Duration::from_millis(800);
const OVERSIZED_FRAME_LENGTH: usize = 1 << 20;

#[tokio::test]
async fn ssh_agent_start_reports_running_status() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let pid_file_path = temp.path().join("auth.sock.pid");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let output = Command::new(env!("CARGO_BIN_EXE_tk"))
        .arg("ssh-agent")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--pid-file")
        .arg(&pid_file_path)
        .env("TURNKEY_ORGANIZATION_ID", "org-id")
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(api_key.compressed_public_key()),
        )
        .env(
            "TURNKEY_API_PRIVATE_KEY",
            hex::encode(api_key.private_key()),
        )
        .env("TURNKEY_PRIVATE_KEY_ID", "pk-id")
        .env("TURNKEY_API_BASE_URL", server.uri())
        .output()
        .await
        .expect("tk ssh-agent start should run");
    assert!(
        output.status.success(),
        "start should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    wait_for_path(&socket_path).await;
    wait_for_path(&pid_file_path).await;

    let status = Command::new(env!("CARGO_BIN_EXE_tk"))
        .arg("ssh-agent")
        .arg("status")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--pid-file")
        .arg(&pid_file_path)
        .output()
        .await
        .expect("tk ssh-agent status should run");
    assert!(
        status.status.success(),
        "status should succeed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("running"),
        "status stdout should mention running: {}",
        String::from_utf8_lossy(&status.stdout)
    );

    let stop = Command::new(env!("CARGO_BIN_EXE_tk"))
        .arg("ssh-agent")
        .arg("stop")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--pid-file")
        .arg(&pid_file_path)
        .output()
        .await
        .expect("tk ssh-agent stop should run");
    assert!(
        stop.status.success(),
        "stop should succeed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
}

#[tokio::test]
async fn ssh_agent_start_uses_default_socket_path_when_socket_is_omitted() {
    let temp = tempdir().expect("temp dir should exist");
    let home = temp.path();
    let socket_path = default_socket_path(home);
    let pid_file_path = socket_path.with_extension("sock.pid");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let output = run_agent_command_with_home(&["start"], home, &server, &api_key).await;
    assert!(
        output.status.success(),
        "start should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    wait_for_path(&socket_path).await;
    wait_for_path(&pid_file_path).await;

    let status = run_agent_command_with_home(&["status"], home, &server, &api_key).await;
    assert!(
        status.status.success(),
        "status should succeed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        String::from_utf8_lossy(&status.stdout).contains(socket_path.to_string_lossy().as_ref()),
        "status stdout should include default socket path: {}",
        String::from_utf8_lossy(&status.stdout)
    );

    let stop = run_agent_command_with_home(&["stop"], home, &server, &api_key).await;
    assert!(
        stop.status.success(),
        "stop should succeed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
}

#[tokio::test]
async fn ssh_agent_start_rejects_duplicate_process() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let pid_file_path = temp.path().join("auth.sock.pid");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child =
        spawn_tk_ssh_agent_with_pid_file(&socket_path, &pid_file_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let output = run_agent_command(
        &[
            "start",
            "--socket",
            socket_path.to_str().unwrap(),
            "--pid-file",
            pid_file_path.to_str().unwrap(),
        ],
        &server,
        &api_key,
    )
    .await;
    assert!(!output.status.success(), "duplicate start should fail");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already running"),
        "duplicate start stderr should mention already running: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn ssh_agent_stop_terminates_background_process() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let pid_file_path = temp.path().join("auth.sock.pid");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child =
        spawn_tk_ssh_agent_with_pid_file(&socket_path, &pid_file_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let stop = run_agent_command(
        &[
            "stop",
            "--socket",
            socket_path.to_str().unwrap(),
            "--pid-file",
            pid_file_path.to_str().unwrap(),
        ],
        &server,
        &api_key,
    )
    .await;
    assert!(
        stop.status.success(),
        "stop should succeed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    child.wait_for_exit().await;
    assert!(
        !fs::try_exists(&socket_path)
            .await
            .expect("socket path should be readable"),
        "socket should be removed after stop"
    );
    assert!(
        !fs::try_exists(&pid_file_path)
            .await
            .expect("pid file path should be readable"),
        "pid file should be removed after stop"
    );

    let status = run_agent_command(
        &[
            "status",
            "--socket",
            socket_path.to_str().unwrap(),
            "--pid-file",
            pid_file_path.to_str().unwrap(),
        ],
        &server,
        &api_key,
    )
    .await;
    assert!(!status.status.success(), "status should fail after stop");
}

#[tokio::test]
async fn ssh_agent_start_recovers_from_stale_pid_file() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let pid_file_path = temp.path().join("auth.sock.pid");

    fs::write(&pid_file_path, "999999\n")
        .await
        .expect("stale pid file should be writable");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child =
        spawn_tk_ssh_agent_with_pid_file(&socket_path, &pid_file_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;
    assert_ne!(child.pid(), 999999);
}

#[tokio::test]
async fn ssh_agent_start_does_not_report_ready_from_stale_socket() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let pid_file_path = temp.path().join("auth.sock.pid");

    let stale_listener =
        tokio::net::UnixListener::bind(&socket_path).expect("stale socket should bind");
    drop(stale_listener);

    let output = Command::new(env!("CARGO_BIN_EXE_tk"))
        .arg("ssh-agent")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--pid-file")
        .arg(&pid_file_path)
        .env("HOME", temp.path())
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL")
        .output()
        .await
        .expect("tk ssh-agent start should run");

    assert!(
        !output.status.success(),
        "start should fail without agent configuration"
    );
    assert!(
        !fs::try_exists(&pid_file_path)
            .await
            .expect("pid file path should be readable"),
        "pid file should be removed after failed start"
    );
}

#[tokio::test]
async fn ssh_agent_stop_does_not_kill_unowned_live_pid() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let pid_file_path = temp.path().join("auth.sock.pid");

    let mut unrelated = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("sleep should spawn");
    let unrelated_pid = unrelated.id().expect("sleep pid should be available");

    fs::write(&pid_file_path, format!("{unrelated_pid}\n"))
        .await
        .expect("stale pid file should be writable");

    let server = MockServer::start().await;
    let api_key = TurnkeyP256ApiKey::generate();
    let stop = run_agent_command(
        &[
            "stop",
            "--socket",
            socket_path.to_str().unwrap(),
            "--pid-file",
            pid_file_path.to_str().unwrap(),
        ],
        &server,
        &api_key,
    )
    .await;

    assert!(
        stop.status.success(),
        "stop should treat unowned pid state as stale: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(
        String::from_utf8_lossy(&stop.stdout).contains("not running"),
        "stop stdout should report stale state: {}",
        String::from_utf8_lossy(&stop.stdout)
    );
    assert!(
        unrelated
            .try_wait()
            .expect("sleep status should be readable")
            .is_none(),
        "stop should not signal an unrelated live pid"
    );

    unrelated.start_kill().expect("sleep should be killable");
    let _ = unrelated.wait().await.expect("sleep should exit");
}

#[tokio::test]
async fn ssh_agent_lists_identity_and_signs_for_configured_key() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let public_key_blob = public_key_blob(&TURNKEY_TEST_PUBLIC_KEY);

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;
    mount_sign_raw_payload_mock(&server, &TURNKEY_TEST_SIGNATURE).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child = spawn_tk_ssh_agent(&socket_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let identities = exchange_frame(
        &socket_path,
        &protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]),
    )
    .await;
    assert_eq!(identities[4], protocol::SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(
        identities,
        protocol::encode_request_identities_response(&public_key_blob).unwrap()
    );

    let challenge = b"ssh-agent-challenge";
    let sign_response =
        exchange_frame(&socket_path, &sign_request(&public_key_blob, challenge)).await;
    assert_eq!(sign_response[4], protocol::SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(
        sign_response,
        protocol::encode_sign_response(&TURNKEY_TEST_SIGNATURE).unwrap()
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert_eq!(requests.len(), 2);
    let sign_request_body: serde_json::Value = requests[1]
        .body_json()
        .expect("sign request body should be valid JSON");
    assert_eq!(
        sign_request_body["parameters"]["payload"],
        hex::encode(challenge)
    );
    assert_eq!(
        sign_request_body["parameters"]["encoding"],
        "PAYLOAD_ENCODING_HEXADECIMAL"
    );
    assert_eq!(
        sign_request_body["parameters"]["hashFunction"],
        "HASH_FUNCTION_NOT_APPLICABLE"
    );
}

#[tokio::test]
async fn ssh_agent_rejects_other_keys_and_unsupported_messages() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let other_public_key_blob = public_key_blob(&[0x11; 32]);

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child = spawn_tk_ssh_agent(&socket_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let sign_failure = exchange_frame(
        &socket_path,
        &sign_request(&other_public_key_blob, b"ssh-agent-challenge"),
    )
    .await;
    assert_eq!(
        sign_failure,
        protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[])
    );

    let unsupported = exchange_frame(&socket_path, &protocol::encode_agent_frame(99, &[])).await;
    assert_eq!(
        unsupported,
        protocol::encode_agent_frame(protocol::SSH_AGENT_FAILURE, &[])
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn ssh_agent_contains_malformed_clients_and_keeps_serving() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let public_key_blob = public_key_blob(&TURNKEY_TEST_PUBLIC_KEY);

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child = spawn_tk_ssh_agent(&socket_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    send_partial_frame_then_disconnect(&socket_path).await;
    sleep(Duration::from_millis(150)).await;
    child
        .assert_running("ssh-agent should survive malformed clients")
        .await;

    let identities = exchange_frame(
        &socket_path,
        &protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]),
    )
    .await;
    assert_eq!(
        identities,
        protocol::encode_request_identities_response(&public_key_blob).unwrap()
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn ssh_agent_rejects_oversized_frames_and_keeps_serving() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let public_key_blob = public_key_blob(&TURNKEY_TEST_PUBLIC_KEY);

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child = spawn_tk_ssh_agent(&socket_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let oversized_socket_path = socket_path.clone();
    let oversized_client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&oversized_socket_path)
            .await
            .expect("ssh-agent socket should accept");
        stream
            .write_all(&((OVERSIZED_FRAME_LENGTH as u32).to_be_bytes()))
            .await
            .expect("oversized frame header should write");
        sleep(HELD_CONNECTION_DURATION).await;
    });

    sleep(Duration::from_millis(300)).await;

    let identities = recv_frame_result(
        spawn_frame_request(
            socket_path.clone(),
            protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]),
        ),
        CLIENT_RESPONSE_TIMEOUT,
    )
    .await;
    assert_eq!(
        identities,
        protocol::encode_request_identities_response(&public_key_blob).unwrap()
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert_eq!(requests.len(), 1);

    oversized_client
        .await
        .expect("oversized client thread should finish");
}

#[tokio::test]
async fn ssh_agent_times_out_stalled_clients_and_keeps_serving() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");
    let public_key_blob = public_key_blob(&TURNKEY_TEST_PUBLIC_KEY);

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child = spawn_tk_ssh_agent(&socket_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let stalled_socket_path = socket_path.clone();
    let stalled_client = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&stalled_socket_path)
            .await
            .expect("ssh-agent socket should accept");
        stream
            .write_all(&[0, 0, 0, 8, protocol::SSH_AGENTC_SIGN_REQUEST, 0, 0])
            .await
            .expect("partial frame should write");
        sleep(HELD_CONNECTION_DURATION).await;
    });

    sleep(Duration::from_millis(300)).await;

    let identities = recv_frame_result(
        spawn_frame_request(
            socket_path.clone(),
            protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]),
        ),
        CLIENT_RESPONSE_TIMEOUT,
    )
    .await;
    assert_eq!(
        identities,
        protocol::encode_request_identities_response(&public_key_blob).unwrap()
    );

    let requests = server
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert_eq!(requests.len(), 1);

    stalled_client
        .await
        .expect("stalled client thread should finish");
}

#[tokio::test]
async fn ssh_agent_exits_on_sigterm_and_removes_socket() {
    let temp = tempdir().expect("temp dir should exist");
    let socket_path = temp.path().join("auth.sock");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(TURNKEY_TEST_PUBLIC_KEY)).await;

    let api_key = TurnkeyP256ApiKey::generate();
    let mut child = spawn_tk_ssh_agent(&socket_path, &server, &api_key).await;
    wait_for_socket(&socket_path, &mut child).await;

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.pid().to_string())
        .status()
        .await
        .expect("kill should run");
    assert!(status.success());

    child.wait_for_exit().await;
    assert!(
        !fs::try_exists(&socket_path)
            .await
            .expect("socket path should be readable"),
        "socket should be removed on shutdown"
    );
}

fn public_key_blob(public_key: &[u8]) -> Vec<u8> {
    let public_key_line =
        ssh::encode_public_key_line(public_key, None).expect("public key line should encode");
    ssh::parse_public_key_line(&public_key_line)
        .expect("public key should parse")
        .public_key_blob
}

fn sign_request(public_key_blob: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_ssh_string(public_key_blob, &mut payload);
    encode_ssh_string(challenge, &mut payload);
    payload.extend_from_slice(&0u32.to_be_bytes());
    protocol::encode_agent_frame(protocol::SSH_AGENTC_SIGN_REQUEST, &payload)
}

fn encode_ssh_string(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

async fn spawn_tk_ssh_agent(
    socket_path: &Path,
    server: &MockServer,
    api_key: &TurnkeyP256ApiKey,
) -> ChildGuard {
    let pid_file_path = socket_path.with_extension("sock.pid");
    spawn_tk_ssh_agent_with_pid_file(socket_path, &pid_file_path, server, api_key).await
}

async fn spawn_tk_ssh_agent_with_pid_file(
    socket_path: &Path,
    pid_file_path: &Path,
    server: &MockServer,
    api_key: &TurnkeyP256ApiKey,
) -> ChildGuard {
    let output = Command::new(env!("CARGO_BIN_EXE_tk"))
        .arg("ssh-agent")
        .arg("start")
        .arg("--socket")
        .arg(socket_path)
        .arg("--pid-file")
        .arg(pid_file_path)
        .env("TURNKEY_ORGANIZATION_ID", "org-id")
        .env(
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(api_key.compressed_public_key()),
        )
        .env(
            "TURNKEY_API_PRIVATE_KEY",
            hex::encode(api_key.private_key()),
        )
        .env("TURNKEY_PRIVATE_KEY_ID", "pk-id")
        .env("TURNKEY_API_BASE_URL", server.uri())
        .output()
        .await
        .expect("tk ssh-agent start should run");

    assert!(
        output.status.success(),
        "tk ssh-agent start should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    ChildGuard {
        pid: read_pid_file(pid_file_path).await,
    }
}

async fn wait_for_socket(socket_path: &Path, child: &mut ChildGuard) {
    for _ in 0..100 {
        if fs::try_exists(socket_path)
            .await
            .expect("socket path should be readable")
        {
            return;
        }

        if !child.is_running().await {
            panic!(
                "tk ssh-agent exited before binding socket: pid {} is not running",
                child.pid()
            );
        }

        sleep(Duration::from_millis(20)).await;
    }

    panic!(
        "timed out waiting for ssh-agent socket at {}",
        socket_path.display()
    );
}

async fn exchange_frame(socket_path: &Path, frame: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("ssh-agent socket should accept");
    stream.write_all(frame).await.expect("frame should write");

    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .expect("frame length should be readable");
    let length = u32::from_be_bytes(length) as usize;
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .await
        .expect("frame body should be readable");

    let mut response = (length as u32).to_be_bytes().to_vec();
    response.extend_from_slice(&body);
    response
}

fn spawn_frame_request(socket_path: PathBuf, frame: Vec<u8>) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move { exchange_frame(&socket_path, &frame).await })
}

async fn recv_frame_result(handle: JoinHandle<Vec<u8>>, timeout_duration: Duration) -> Vec<u8> {
    timeout(timeout_duration, handle)
        .await
        .expect("frame request should complete before timeout")
        .expect("frame request task should complete")
}

async fn send_partial_frame_then_disconnect(socket_path: &Path) {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("ssh-agent socket should accept");
    stream
        .write_all(&[0, 0, 0, 8, protocol::SSH_AGENTC_SIGN_REQUEST, 0, 0])
        .await
        .expect("partial frame should write");
}

async fn mount_get_private_key_mock(server: &MockServer, public_key: &str) {
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_private_key"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "privateKey": {
                "privateKeyId": "pk-id",
                "publicKey": public_key,
                "privateKeyName": "ssh agent signer",
                "curve": "CURVE_ED25519",
                "addresses": [],
                "privateKeyTags": [],
                "createdAt": null,
                "updatedAt": null,
                "exported": false,
                "imported": false
            }
        })))
        .mount(server)
        .await;
}

async fn mount_sign_raw_payload_mock(server: &MockServer, signature: &[u8]) {
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "activity": {
                "id": "activity-id",
                "organizationId": "org-id",
                "fingerprint": "fingerprint",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                "result": {
                    "signRawPayloadResult": {
                        "r": hex::encode(&signature[..32]),
                        "s": hex::encode(&signature[32..]),
                        "v": TURNKEY_TEST_V
                    }
                }
            }
        })))
        .mount(server)
        .await;
}

struct ChildGuard {
    pid: u32,
}

impl ChildGuard {
    async fn assert_running(&mut self, context: &str) {
        if !self.is_running().await {
            panic!("{context}: pid {} is not running", self.pid);
        }
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    async fn is_running(&self) -> bool {
        Command::new("kill")
            .arg("-0")
            .arg(self.pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("kill -0 should run")
            .success()
    }

    async fn wait_for_exit(&mut self) {
        for _ in 0..100 {
            if !self.is_running().await {
                return;
            }

            sleep(Duration::from_millis(20)).await;
        }

        panic!("timed out waiting for ssh-agent to exit");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::kill(self.pid as i32, libc::SIGTERM) };
    }
}

async fn wait_for_path(path: &Path) {
    for _ in 0..100 {
        if fs::try_exists(path).await.expect("path should be readable") {
            return;
        }

        sleep(Duration::from_millis(20)).await;
    }

    panic!("timed out waiting for path {}", path.display());
}

async fn read_pid_file(path: &Path) -> u32 {
    fs::read_to_string(path)
        .await
        .unwrap_or_else(|error| panic!("failed to read pid file {}: {error}", path.display()))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("failed to parse pid file {}: {error}", path.display()))
}

async fn run_agent_command(
    args: &[&str],
    server: &MockServer,
    api_key: &TurnkeyP256ApiKey,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    command.arg("ssh-agent");
    command.args(args);
    command.env("TURNKEY_ORGANIZATION_ID", "org-id");
    command.env(
        "TURNKEY_API_PUBLIC_KEY",
        hex::encode(api_key.compressed_public_key()),
    );
    command.env(
        "TURNKEY_API_PRIVATE_KEY",
        hex::encode(api_key.private_key()),
    );
    command.env("TURNKEY_PRIVATE_KEY_ID", "pk-id");
    command.env("TURNKEY_API_BASE_URL", server.uri());
    command
        .output()
        .await
        .expect("tk ssh-agent command should run")
}

async fn run_agent_command_with_home(
    args: &[&str],
    home: &Path,
    server: &MockServer,
    api_key: &TurnkeyP256ApiKey,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    command.arg("ssh-agent");
    command.args(args);
    command.env("HOME", home);
    command.env("TURNKEY_ORGANIZATION_ID", "org-id");
    command.env(
        "TURNKEY_API_PUBLIC_KEY",
        hex::encode(api_key.compressed_public_key()),
    );
    command.env(
        "TURNKEY_API_PRIVATE_KEY",
        hex::encode(api_key.private_key()),
    );
    command.env("TURNKEY_PRIVATE_KEY_ID", "pk-id");
    command.env("TURNKEY_API_BASE_URL", server.uri());
    command
        .output()
        .await
        .expect("tk ssh-agent command should run")
}

fn default_socket_path(home: &Path) -> PathBuf {
    home.join(".config")
        .join("turnkey")
        .join("tk")
        .join("ssh-agent.sock")
}
