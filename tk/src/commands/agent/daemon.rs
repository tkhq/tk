use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, anyhow};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::sleep;
use turnkey_auth::config::default_config_dir_from_home;
use turnkey_auth::ssh::protocol;

use super::{InternalRunArgs, StartArgs, StatusArgs, StopArgs};

const START_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Starts the background SSH agent.
pub async fn start(args: StartArgs) -> anyhow::Result<()> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file)?;
    let lock_file = resolve_lock_file(&pid_file);
    create_parent_dir(&socket).await?;
    create_parent_dir(&pid_file).await?;
    create_parent_dir(&lock_file).await?;

    if path_exists(&socket).await? {
        if probe_agent_socket(&socket).await.is_ok() || is_lock_held_by_other(&lock_file).await? {
            return Err(anyhow!(
                "ssh-agent is already running on {}",
                socket.display()
            ));
        }

        remove_socket_if_present(&socket).await?;
    }
    remove_file_if_present(&pid_file).await?;

    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg("ssh-agent")
        .arg("internal-run")
        .arg("--socket")
        .arg(&socket)
        .arg("--pid-file")
        .arg(&pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn background ssh-agent")?;

    let pid = child
        .id()
        .context("background ssh-agent pid was not available")?;

    match wait_for_startup(&socket, &mut child).await {
        Ok(()) => {
            println!("ssh-agent running with pid {pid} on {}", socket.display());
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&pid_file).await;
            let _ = child.start_kill();
            Err(error)
        }
    }
}

/// Stops the background SSH agent.
pub async fn stop(args: StopArgs) -> anyhow::Result<()> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file)?;
    let lock_file = resolve_lock_file(&pid_file);

    if !is_lock_held_by_other(&lock_file).await? {
        let _ = fs::remove_file(&pid_file).await;
        let _ = remove_socket_if_present(&socket).await;
        println!("ssh-agent was not running");
        return Ok(());
    }

    let pid = read_pid_file(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;

    send_signal(pid, libc::SIGTERM)
        .with_context(|| format!("failed to signal ssh-agent process {pid}"))?;
    wait_for_process_exit(pid).await?;
    let _ = fs::remove_file(&pid_file).await;
    wait_for_socket_removal(&socket).await?;
    println!("ssh-agent stopped");
    Ok(())
}

/// Reports the background SSH agent status.
pub async fn status(args: StatusArgs) -> anyhow::Result<()> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file)?;
    let lock_file = resolve_lock_file(&pid_file);

    if !is_lock_held_by_other(&lock_file).await? {
        return Err(anyhow!("ssh-agent is not running"));
    }

    let pid = read_pid_file(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;

    if !is_process_alive(pid) {
        return Err(anyhow!("ssh-agent pid {pid} is not running"));
    }

    if probe_agent_socket(&socket).await.is_err() {
        return Err(anyhow!(
            "ssh-agent pid {pid} is marked running but socket {} is not serving requests",
            socket.display()
        ));
    }

    println!("ssh-agent running with pid {pid} on {}", socket.display());

    Ok(())
}

/// Runs the hidden in-process SSH agent daemon.
pub async fn internal_run(args: InternalRunArgs) -> anyhow::Result<()> {
    let lock_file = resolve_lock_file(&args.pid_file);
    let _lock = AgentLock::acquire(&lock_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent is already running"))?;
    write_pid_file(&args.pid_file, std::process::id()).await?;

    let result = turnkey_auth::ssh::agent::run(args.socket).await;

    let _ = fs::remove_file(&args.pid_file).await;
    result
}

async fn wait_for_startup(socket: &Path, child: &mut tokio::process::Child) -> anyhow::Result<()> {
    let iterations = START_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        // First, see whether the agent is already answering on the socket
        if probe_agent_socket(socket).await.is_ok() {
            return Ok(());
        }

        // If it exited before coming up, surface that immediately
        if let Some(status) = child
            .try_wait()
            .context("failed to poll background ssh-agent status")?
        {
            return Err(anyhow!("background ssh-agent exited early: {status}"));
        }

        // Otherwise, wait a moment and try again until the timeout expires
        sleep(POLL_INTERVAL).await;
    }

    Err(anyhow!(
        "timed out waiting for ssh-agent socket at {}",
        socket.display()
    ))
}

async fn wait_for_process_exit(pid: u32) -> anyhow::Result<()> {
    let iterations = STOP_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if !is_process_alive(pid) {
            return Ok(());
        }

        sleep(POLL_INTERVAL).await;
    }

    Err(anyhow!("timed out waiting for ssh-agent pid {pid} to exit"))
}

async fn wait_for_socket_removal(socket: &Path) -> anyhow::Result<()> {
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

fn resolve_pid_file(socket: &Path, pid_file: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match pid_file {
        Some(pid_file) => Ok(pid_file),
        None => Ok(PathBuf::from(format!("{}.pid", socket.display()))),
    }
}

fn resolve_lock_file(pid_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", pid_file.display()))
}

fn resolve_socket_path(socket: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match socket {
        Some(socket) => Ok(socket),
        None => default_socket_path(),
    }
}

fn default_socket_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("missing HOME; use --socket to set a path"))?;
    Ok(default_config_dir_from_home(Path::new(&home))
        .join("tk")
        .join("ssh-agent.sock"))
}

async fn create_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    Ok(())
}

async fn write_pid_file(path: &Path, pid: u32) -> anyhow::Result<()> {
    fs::write(path, format!("{pid}\n"))
        .await
        .with_context(|| format!("failed to write pid file at {}", path.display()))
}

async fn remove_file_if_present(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

async fn read_pid_file(path: &Path) -> anyhow::Result<Option<u32>> {
    let raw = match fs::read_to_string(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };

    let pid = raw
        .trim()
        .parse::<u32>()
        .with_context(|| format!("failed to parse pid file at {}", path.display()))?;
    Ok(Some(pid))
}

async fn path_exists(path: &Path) -> anyhow::Result<bool> {
    fs::try_exists(path)
        .await
        .with_context(|| format!("failed to check {}", path.display()))
}

async fn remove_socket_if_present(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)
                .await
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }

    Ok(())
}

async fn probe_agent_socket(socket: &Path) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("failed to connect to ssh-agent socket {}", socket.display()))?;
    let request = protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    stream
        .write_all(&request)
        .await
        .context("failed to write readiness probe")?;

    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .context("failed to read readiness probe length")?;
    let body_len = u32::from_be_bytes(length) as usize;
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .await
        .context("failed to read readiness probe body")?;

    match body.first().copied() {
        Some(protocol::SSH_AGENT_IDENTITIES_ANSWER | protocol::SSH_AGENT_FAILURE) => Ok(()),
        Some(message_type) => Err(anyhow!(
            "unexpected ssh-agent readiness response {message_type}"
        )),
        None => Err(anyhow!("empty ssh-agent readiness response")),
    }
}

async fn is_lock_held_by_other(path: &Path) -> anyhow::Result<bool> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = open_lock_file(&path)?;
        match try_lock_exclusive(&file) {
            Ok(true) => {
                unlock_file(&file)?;
                Ok(false)
            }
            Ok(false) => Ok(true),
            Err(error) => Err(error),
        }
    })
    .await
    .context("failed to join lock inspection task")?
}

fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    match send_signal(pid, 0) {
        Ok(()) => true,
        Err(error) => error.raw_os_error() != Some(libc::ESRCH),
    }
}

fn send_signal(pid: u32, signal: i32) -> std::io::Result<()> {
    // SAFETY: libc::kill is an FFI syscall wrapper and does not dereference
    // Rust pointers or access Rust managed memory
    let rc = unsafe { libc::kill(pid as i32, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

struct AgentLock {
    _file: File,
}

impl AgentLock {
    async fn acquire(path: &Path) -> anyhow::Result<Option<Self>> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let file = open_lock_file(&path)?;
            if try_lock_exclusive(&file)? {
                Ok(Some(Self { _file: file }))
            } else {
                Ok(None)
            }
        })
        .await
        .context("failed to join lock acquisition task")?
    }
}

fn open_lock_file(path: &Path) -> anyhow::Result<File> {
    // The file contents do not matter - flock just cares about the file descriptor.
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("failed to open lock file {}", path.display()))
}

fn try_lock_exclusive(file: &File) -> anyhow::Result<bool> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(true)
    } else {
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => Ok(false),
            _ => Err(error).context("failed to acquire ssh-agent lock"),
        }
    }
}

fn unlock_file(file: &File) -> anyhow::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("failed to release ssh-agent lock")
    }
}
