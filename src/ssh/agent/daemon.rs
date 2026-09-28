use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::Arc;
use std::time::Duration;

use crate::wire::ssh::Ed25519PublicKey;
use crate::wire::ssh::agent::{self, AgentIdentity, Keyring, SignError, SignFuture};
use crate::wire::ssh::protocol;
use anyhow::{Context, Error, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClient;

use super::lock::{AgentLock, is_lock_held_by_other, resolve_lock_file};
use super::{
    AgentNotRunning, AgentPathArgs, AgentRunning, AgentStopped, InternalRunArgs, StartArgs,
};
use crate::auth::{self, AuthOptions, build_turnkey_client};
use crate::errors::InvalidInput;
use crate::outcome::{MachineOnly, Outcome};
use crate::socket::SocketMode;
use crate::ssh::registry::{SelectError, SshKeyEntry, SshKeyName};
use crate::ssh::selection_error;
use crate::ssh::signer::{BACKOFF, TurnkeySigner};

const START_TIMEOUT: Duration = Duration::from_secs(4);
const STOP_TIMEOUT: Duration = Duration::from_secs(4);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

type OrganizationClient = Arc<TurnkeyClient<TurnkeyP256ApiKey>>;

struct RegistryKeyring {
    entries: BTreeMap<Ed25519PublicKey, (SshKeyEntry, OrganizationClient)>,
    backoff: Duration,
}

impl Keyring for RegistryKeyring {
    fn identities(&self) -> Vec<AgentIdentity> {
        self.entries
            .values()
            .map(|(entry, _)| AgentIdentity {
                public_key: entry.public_key,
                comment: format!("turnkey:{}", entry.private_key_id),
            })
            .collect()
    }

    fn sign<'a>(&'a self, public_key: &'a Ed25519PublicKey, data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            let (entry, client) = self.entries.get(public_key).ok_or(SignError::UnknownKey)?;
            TurnkeySigner::new(
                client,
                entry.organization_id,
                &entry.private_key_id,
                self.backoff,
            )
            .sign_raw_payload(data)
            .await
            .map_err(SignError::Signer)
        })
    }
}

#[derive(Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
struct AgentMetadata {
    pid: u32,
    // Absent in pid files written by daemons that predate socket_mode.
    socket_mode: Option<SocketMode>,
    keys: Vec<String>,
}

struct AgentPaths {
    socket: PathBuf,
    pid_file: PathBuf,
    lock_file: PathBuf,
}

impl AgentPaths {
    fn resolve(socket: Option<PathBuf>, pid_file: Option<PathBuf>) -> Result<Self> {
        let socket = socket.map_or_else(default_socket_path, Ok)?;
        let pid_file = pid_file.map_or_else(default_pid_path, Ok)?;
        let lock_file = resolve_lock_file(&pid_file);
        Ok(Self {
            socket,
            pid_file,
            lock_file,
        })
    }
}

pub async fn start(args: StartArgs, options: &AuthOptions) -> Result<Outcome> {
    let AgentPaths {
        socket,
        pid_file,
        lock_file,
    } = AgentPaths::resolve(args.socket, args.pid_file)?;
    let requested = args.key;

    let mut command = Command::new(env::current_exe()?);
    command.arg("ssh").arg("agent").arg("internal-run");
    for argument in forwarded_auth_arguments(options) {
        command.arg(argument);
    }
    command.arg("--socket").arg(&socket);
    command.arg("--pid-file").arg(&pid_file);
    command
        .arg("--socket-mode")
        .arg(args.socket_mode.to_string());
    for requested in &requested {
        command.arg("--key").arg(requested.to_string());
    }
    let mut registry = auth::LoadedRegistry::load().await?;
    select_keys(options, requested, &mut registry)?;

    create_parent_dir(&socket).await?;
    create_parent_dir(&pid_file).await?;
    create_parent_dir(&lock_file).await?;

    if path_exists(&socket).await? {
        if probe_agent_socket(&socket).await.is_ok() || is_lock_held_by_other(lock_file).await? {
            return Err(anyhow!(
                "ssh-agent is already running on {}",
                socket.display()
            ));
        }
        remove_socket_if_present(&socket).await?;
    }
    remove_stale_pid_file(&pid_file).await?;

    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn background ssh-agent")?;

    let child_pid = child
        .id()
        .context("background ssh-agent pid was not available")?;

    match wait_for_startup(&socket, &mut child).await {
        Ok(()) => {
            let AgentMetadata {
                pid,
                socket_mode,
                keys,
            } = require_metadata(&pid_file).await?;
            Ok(Outcome::AgentStarted(AgentRunning {
                pid,
                socket: socket.display().to_string(),
                socket_mode,
                keys,
            }))
        }
        Err(error) => {
            remove_pid_file_owned_by(&pid_file, child_pid).await;
            let _ = child.start_kill();
            Err(error)
        }
    }
}

pub async fn stop(args: AgentPathArgs) -> Result<Outcome> {
    let AgentPaths {
        socket,
        pid_file,
        lock_file,
    } = AgentPaths::resolve(args.socket, args.pid_file)?;

    // Holding the lock across cleanup keeps a racing start from having the pid
    // file and socket it just created removed behind it.
    if let Some(_guard) = AgentLock::acquire(lock_file).await? {
        let _ = fs::remove_file(&pid_file).await;
        let _ = remove_socket_if_present(&socket).await;
        return Ok(Outcome::AgentNotRunning(AgentNotRunning {}));
    }

    let metadata = require_metadata(&pid_file).await?;
    send_signal(metadata.pid, libc::SIGTERM)
        .with_context(|| format!("failed to signal ssh-agent process {}", metadata.pid))?;
    wait_for_process_exit(metadata.pid).await?;
    remove_pid_file_owned_by(&pid_file, metadata.pid).await;
    wait_for_socket_removal(&socket).await?;
    Ok(Outcome::AgentStopped(AgentStopped {}))
}

pub async fn status(args: AgentPathArgs) -> Result<Outcome> {
    let AgentPaths {
        socket,
        pid_file,
        lock_file,
    } = AgentPaths::resolve(args.socket, args.pid_file)?;

    if !is_lock_held_by_other(lock_file).await? {
        return Err(anyhow!("ssh-agent is not running"));
    }

    let AgentMetadata {
        pid,
        socket_mode,
        keys,
    } = require_metadata(&pid_file).await?;
    if !is_process_alive(pid) {
        return Err(anyhow!("ssh-agent pid {} is not running", pid));
    }
    if probe_agent_socket(&socket).await.is_err() {
        return Err(anyhow!(
            "ssh-agent pid {} is marked running but socket {} is not serving requests",
            pid,
            socket.display()
        ));
    }
    Ok(Outcome::AgentStatusReport(AgentRunning {
        pid,
        socket: socket.display().to_string(),
        socket_mode,
        keys,
    }))
}

pub async fn internal_run(args: InternalRunArgs, options: &AuthOptions) -> Result<Outcome> {
    let mut registry = auth::LoadedRegistry::load().await?;
    let selected = select_keys(options, args.key, &mut registry)?;
    let mut clients: BTreeMap<_, OrganizationClient> = BTreeMap::new();
    let mut keys = Vec::with_capacity(selected.len());
    let mut entries = BTreeMap::new();
    for entry in selected {
        let organization_id = entry.organization_id;
        let client = match clients.get(&organization_id) {
            Some(client) => Arc::clone(client),
            None => {
                let auth = registry
                    .resolve_for_organization(options, organization_id)
                    .await
                    .with_context(|| {
                        format!("select a credential for SSH organization {organization_id}")
                    })?;
                let client = Arc::new(build_turnkey_client(auth.stamper, &auth.api_base_url)?);
                clients.insert(organization_id, Arc::clone(&client));
                client
            }
        };
        keys.push(entry.fingerprint().to_string());
        entries.insert(entry.public_key, (entry, client));
    }
    let keyring = Arc::new(RegistryKeyring {
        entries,
        backoff: BACKOFF,
    });

    let lock_file = resolve_lock_file(&args.pid_file);
    let _lock = AgentLock::acquire(lock_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent is already running"))?;
    let metadata = AgentMetadata {
        pid: process::id(),
        socket_mode: Some(args.socket_mode),
        keys,
    };
    write_pid_file(&args.pid_file, &metadata).await?;

    let result = agent::run(args.socket, args.socket_mode, keyring).await;
    let _ = fs::remove_file(&args.pid_file).await;
    result.map(|()| Outcome::AgentDaemonExited(MachineOnly {}))
}

fn select_keys(
    options: &AuthOptions,
    requested: Vec<SshKeyName>,
    registry: &mut auth::LoadedRegistry,
) -> Result<Vec<SshKeyEntry>> {
    let mut table = registry.take_ssh_keys()?;
    if table.is_empty() {
        return Err(selection_error(SelectError::Empty, "name one with --key"));
    }
    if let Some((organization_id, source)) = registry.explicit_organization(options)? {
        table.retain_organization(organization_id);
        if table.is_empty() {
            return Err(InvalidInput(format!(
                "organization {organization_id} selected by {source} has no registered SSH keys; register one with tk ssh keys add --private-key-id <id>, or drop the identity selection"
            ))
            .into());
        }
    }

    let entries = if requested.is_empty() {
        table.into_entries().collect()
    } else {
        requested
            .into_iter()
            .map(|name| {
                table
                    .select_ref(name)
                    .cloned()
                    .map_err(|error| selection_error(error, "name one with --key"))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let mut unique = BTreeMap::new();
    for entry in entries {
        unique.insert(entry.fingerprint(), entry);
    }
    Ok(unique.into_values().collect())
}

fn forwarded_auth_arguments(options: &AuthOptions) -> Vec<OsString> {
    let mut forwarded = Vec::new();
    if let Some(profile) = options.profile() {
        forwarded.push(OsString::from("--profile"));
        forwarded.push(profile.into());
    }
    if let Some(organization_id) = options.organization_id() {
        forwarded.push(OsString::from("--organization-id"));
        forwarded.push(organization_id.to_string().into());
    }
    if let Some(api_base_url) = options.api_base_url() {
        forwarded.push(OsString::from("--api-base-url"));
        forwarded.push(api_base_url.into());
    }
    forwarded
}

fn default_socket_path() -> Result<PathBuf> {
    Ok(default_agent_dir()?.join("ssh-agent.sock"))
}

fn default_pid_path() -> Result<PathBuf> {
    Ok(default_agent_dir()?.join("ssh-agent.pid"))
}

pub async fn is_default_running() -> bool {
    let Ok(pid_file) = default_pid_path() else {
        return false;
    };
    is_lock_held_by_other(resolve_lock_file(&pid_file))
        .await
        .unwrap_or(false)
}

fn default_agent_dir() -> Result<PathBuf> {
    auth::config_dir()
        .ok_or_else(|| anyhow!("missing HOME; use --socket and --pid-file to set paths"))
}

async fn wait_for_startup(socket: &Path, child: &mut Child) -> Result<()> {
    let iterations = START_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if probe_agent_socket(socket).await.is_ok() {
            return Ok(());
        }
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    pipe.read_to_string(&mut stderr).await?;
                }
                let detail = stderr.trim();
                if detail.is_empty() {
                    return Err(anyhow!("background ssh-agent exited early: {status}"));
                }
                return Err(anyhow!(
                    "background ssh-agent exited early: {status}: {detail}"
                ));
            }
            Err(error) => {
                return Err(Error::new(error).context("failed to poll background ssh-agent status"));
            }
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!(
        "timed out waiting for ssh-agent socket at {}",
        socket.display()
    ))
}

async fn create_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

async fn remove_stale_pid_file(path: &Path) -> Result<()> {
    // An unreadable pid file may be one another agent is writing right now, so
    // only a document that names a dead process counts as stale.
    match read_metadata(path).await {
        Ok(Some(metadata)) if is_process_alive(metadata.pid) => return Ok(()),
        Ok(Some(_)) | Ok(None) => {}
        Err(_) => return Ok(()),
    }
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

async fn remove_pid_file_owned_by(path: &Path, pid: u32) {
    if matches!(read_metadata(path).await, Ok(Some(metadata)) if metadata.pid == pid) {
        let _ = fs::remove_file(path).await;
    }
}

async fn write_pid_file(path: &Path, metadata: &AgentMetadata) -> Result<()> {
    // A reader must never observe a partially written document, so the bytes
    // land on a sibling path first and are renamed over the pid file.
    let temporary = PathBuf::from(format!("{}.{}.tmp", path.display(), metadata.pid));
    fs::write(&temporary, serde_json::to_vec(metadata)?)
        .await
        .with_context(|| format!("failed to write pid file at {}", temporary.display()))?;
    match fs::rename(&temporary, path).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary).await;
            Err(error).with_context(|| format!("failed to write pid file at {}", path.display()))
        }
    }
}

async fn require_metadata(pid_file: &Path) -> Result<AgentMetadata> {
    read_metadata(pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))
}

async fn read_metadata(path: &Path) -> Result<Option<AgentMetadata>> {
    let raw = match fs::read(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse pid file at {}", path.display()))
        .map(Some)
}

async fn path_exists(path: &Path) -> Result<bool> {
    fs::try_exists(path)
        .await
        .with_context(|| format!("failed to check {}", path.display()))
}

async fn remove_socket_if_present(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)
                .await
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    Ok(())
}

async fn probe_agent_socket(socket: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("failed to connect to ssh-agent socket {}", socket.display()))?;
    let request = protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    stream
        .write_all(&request)
        .await
        .context("failed to write readiness probe")?;
    let frame = timeout(PROBE_TIMEOUT, protocol::read_frame(&mut stream))
        .await
        .unwrap_or_else(|_| Err(io::Error::from(ErrorKind::TimedOut)))
        .context("failed to read readiness probe response")?
        .ok_or_else(|| anyhow!("empty ssh-agent readiness response"))?;
    // A frame carries its four-byte length prefix, so the message type is at index 4.
    match frame.get(4).copied() {
        Some(protocol::SSH_AGENT_IDENTITIES_ANSWER | protocol::SSH_AGENT_FAILURE) => Ok(()),
        Some(message_type) => Err(anyhow!(
            "unexpected ssh-agent readiness response: message_type={message_type}"
        )),
        None => Err(anyhow!("empty ssh-agent readiness response")),
    }
}

async fn wait_for_process_exit(pid: u32) -> Result<()> {
    let iterations = STOP_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if !is_process_alive(pid) {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!("timed out waiting for ssh-agent pid {pid} to exit"))
}

async fn wait_for_socket_removal(socket: &Path) -> Result<()> {
    let iterations = STOP_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if !path_exists(socket).await? {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!(
        "timed out waiting for ssh-agent socket {} to be removed",
        socket.display()
    ))
}

fn is_process_alive(pid: u32) -> bool {
    pid != 0
        && match send_signal(pid, 0) {
            Ok(()) => true,
            Err(error) => error.raw_os_error() != Some(libc::ESRCH),
        }
}

fn send_signal(pid: u32, signal: i32) -> io::Result<()> {
    // SAFETY: libc::kill is an FFI syscall wrapper and does not dereference
    // Rust pointers or access Rust-managed memory.
    let rc = unsafe { libc::kill(pid as i32, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Asserts on the classified error code.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::auth::ResolvedAuth;
    use crate::errors::{ErrorCode, classify};
    use crate::ssh::registry::PrivateKeyId;

    const ORG: &str = "00000000-0000-4000-8000-000000000001";

    /// The server is returned so it outlives the request; a dropped server
    /// goes back to wiremock's pool and answers another test.
    async fn keyring_against(
        responses: Vec<ResponseTemplate>,
    ) -> (MockServer, RegistryKeyring, Ed25519PublicKey) {
        let server = MockServer::start().await;
        let last = responses.len() - 1;
        for (index, response) in responses.into_iter().enumerate() {
            let mock =
                Mock::given(path("/public/v1/submit/sign_raw_payload")).respond_with(response);
            if index < last {
                mock.up_to_n_times(1).mount(&server).await;
            } else {
                mock.mount(&server).await;
            }
        }
        let auth = ResolvedAuth::for_tests(ORG, &server.uri(), TurnkeyP256ApiKey::generate());
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url).unwrap();
        let public_key = Ed25519PublicKey::from_bytes([1; 32]);
        let entry = SshKeyEntry {
            organization_id: auth.org_id,
            private_key_id: PrivateKeyId::from("private-key-id".to_string()),
            public_key,
        };
        let keyring = RegistryKeyring {
            entries: [(public_key, (entry, Arc::new(client)))].into(),
            backoff: Duration::ZERO,
        };
        (server, keyring, public_key)
    }

    /// The directory is returned so it outlives the paths inside it.
    fn agent_paths() -> (TempDir, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("ssh-agent.pid");
        let socket = directory.path().join("ssh-agent.sock");
        (directory, pid_file, socket)
    }

    fn metadata(pid: u32) -> AgentMetadata {
        AgentMetadata {
            pid,
            socket_mode: Some("600".parse().unwrap()),
            keys: vec!["SHA256:example".to_string()],
        }
    }

    #[tokio::test]
    async fn a_signing_request_needing_approval_is_a_signer_error_classified_as_approval() {
        let (_server, keyring, public_key) =
            keyring_against(vec![ResponseTemplate::new(200).set_body_json(json!({
                "activity": {
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "id": "activity-1",
                    "organizationId": ORG,
                    "fingerprint": "sha256:example",
                }
            }))])
            .await;
        let SignError::Signer(error) = keyring
            .sign(&public_key, b"payload")
            .await
            .expect_err("consensus should fail the signature")
        else {
            panic!("a refused signature must not be reported as an unknown key")
        };
        assert_eq!(classify(&error).code, ErrorCode::ApprovalRequired);
        assert_eq!(
            error.to_string(),
            "signing requires additional approval (activity id: activity-1)"
        );
    }

    #[tokio::test]
    async fn a_rate_limited_signing_request_is_retried_until_it_completes() {
        let (server, keyring, public_key) = keyring_against(vec![
            ResponseTemplate::new(429).set_body_string("Resource exhausted"),
            ResponseTemplate::new(200).set_body_json(json!({
                "activity": {
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                    "status": "ACTIVITY_STATUS_COMPLETED",
                    "id": "activity-1",
                    "organizationId": ORG,
                    "fingerprint": "sha256:example",
                    "result": {
                        "signRawPayloadResult": {
                            "r": "11".repeat(32),
                            "s": "22".repeat(32),
                            "v": "00",
                        }
                    }
                }
            })),
        ])
        .await;
        let signature = keyring
            .sign(&public_key, b"payload")
            .await
            .expect("the retried request should sign");
        let mut expected = [0x11; 64];
        expected[32..].fill(0x22);
        assert_eq!(signature, expected);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_server_error_during_signing_is_a_signer_error_classified_as_api_error() {
        let (server, keyring, public_key) = keyring_against(vec![
            ResponseTemplate::new(500).set_body_string("unavailable"),
        ])
        .await;
        let SignError::Signer(error) = keyring
            .sign(&public_key, b"payload")
            .await
            .expect_err("a server error should fail the signature")
        else {
            panic!("a server error must not be reported as an unknown key")
        };
        assert_eq!(classify(&error).code, ErrorCode::ApiError);
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn a_pid_file_from_an_older_daemon_parses_without_a_socket_mode() {
        let (_directory, pid_file, _socket) = agent_paths();
        fs::write(&pid_file, br#"{"pid":4242,"keys":["SHA256:example"]}"#)
            .await
            .unwrap();

        assert_eq!(
            require_metadata(&pid_file).await.unwrap(),
            AgentMetadata {
                pid: 4242,
                socket_mode: None,
                keys: vec!["SHA256:example".to_string()],
            }
        );
    }

    #[tokio::test]
    async fn a_failed_start_removes_only_the_pid_file_it_owns() {
        let (_directory, pid_file, _socket) = agent_paths();
        fs::write(&pid_file, serde_json::to_vec(&metadata(4242)).unwrap())
            .await
            .unwrap();

        remove_pid_file_owned_by(&pid_file, 9999).await;
        assert!(path_exists(&pid_file).await.unwrap());

        remove_pid_file_owned_by(&pid_file, 4242).await;
        assert!(!path_exists(&pid_file).await.unwrap());
    }

    #[tokio::test]
    async fn a_stop_that_takes_the_lock_clears_the_pid_file_and_socket() {
        let (_directory, pid_file, socket) = agent_paths();
        write_pid_file(&pid_file, &metadata(4242)).await.unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();

        let outcome = stop(AgentPathArgs {
            socket: Some(socket.clone()),
            pid_file: Some(pid_file.clone()),
        })
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::AgentNotRunning(_)));
        assert!(!path_exists(&pid_file).await.unwrap());
        assert!(!path_exists(&socket).await.unwrap());
        drop(listener);
    }

    #[tokio::test]
    async fn a_stop_racing_a_held_lock_leaves_the_pid_file_and_socket_alone() {
        let (_directory, pid_file, socket) = agent_paths();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        // Stands in for the agent that won the lock; its pid file is not
        // written yet, so an unlocked stop would unlink the socket regardless.
        let _held = AgentLock::acquire(resolve_lock_file(&pid_file))
            .await
            .unwrap()
            .expect("the lock should be free before the test takes it");

        let Err(error) = stop(AgentPathArgs {
            socket: Some(socket.clone()),
            pid_file: Some(pid_file.clone()),
        })
        .await
        else {
            panic!("a stop without metadata cannot signal the running agent")
        };

        assert_eq!(
            error.to_string(),
            format!("ssh-agent pid file not found at {}", pid_file.display())
        );
        assert!(path_exists(&socket).await.unwrap());
        drop(listener);
    }

    #[tokio::test]
    async fn a_partially_written_pid_file_survives_stale_removal() {
        let (_directory, pid_file, _socket) = agent_paths();

        fs::write(&pid_file, b"").await.unwrap();
        remove_stale_pid_file(&pid_file).await.unwrap();
        assert!(path_exists(&pid_file).await.unwrap());

        fs::write(&pid_file, br#"{"pid":4242,"ke"#).await.unwrap();
        remove_stale_pid_file(&pid_file).await.unwrap();
        assert!(path_exists(&pid_file).await.unwrap());

        write_pid_file(&pid_file, &metadata(0)).await.unwrap();
        remove_stale_pid_file(&pid_file).await.unwrap();
        assert!(!path_exists(&pid_file).await.unwrap());
    }
}
