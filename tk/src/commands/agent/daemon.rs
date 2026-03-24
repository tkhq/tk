use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, anyhow};
use tokio::fs;
use tokio::time::sleep;

use super::{StartArgs, StatusArgs, StopArgs};

const START_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub async fn start(args: StartArgs) -> anyhow::Result<()> {
    let socket = resolve_socket_path(args.socket)?;
    create_socket_parent_dir(&socket).await?;
    let pid_file = resolve_pid_file(&socket, args.pid_file)?;

    if let Some(pid) = read_pid_file(&pid_file).await? {
        if is_process_alive(pid) {
            return Err(anyhow!(
                "ssh-agent is already running with pid {pid} ({})",
                pid_file.display()
            ));
        }

        fs::remove_file(&pid_file).await.with_context(|| {
            format!("failed to remove stale pid file at {}", pid_file.display())
        })?;
    }

    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg("ssh-agent")
        .arg("internal-run")
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn background ssh-agent")?;

    let pid = child
        .id()
        .context("background ssh-agent pid was not available")?;
    write_pid_file(&pid_file, pid).await?;

    match wait_for_startup(&socket, &pid_file, &mut child).await {
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

pub async fn stop(args: StopArgs) -> anyhow::Result<()> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file)?;
    let pid = read_pid_file(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;

    if !is_process_alive(pid) {
        let _ = fs::remove_file(&pid_file).await;
        let _ = remove_socket_if_present(&socket).await;
        println!("ssh-agent was not running");
        return Ok(());
    }

    send_signal(pid, libc::SIGTERM)
        .with_context(|| format!("failed to signal ssh-agent process {pid}"))?;
    wait_for_process_exit(pid).await?;
    let _ = fs::remove_file(&pid_file).await;
    wait_for_socket_removal(&socket).await?;
    println!("ssh-agent stopped");
    Ok(())
}

pub async fn status(args: StatusArgs) -> anyhow::Result<()> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file)?;
    let pid = read_pid_file(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent is not running"))?;

    if !is_process_alive(pid) {
        return Err(anyhow!("ssh-agent pid {pid} is not running"));
    }

    if !path_exists(&socket).await? {
        return Err(anyhow!(
            "ssh-agent pid {pid} is running but socket {} is missing",
            socket.display()
        ));
    }

    println!("ssh-agent running with pid {pid} on {}", socket.display());

    Ok(())
}

async fn wait_for_startup(
    socket: &Path,
    pid_file: &Path,
    child: &mut tokio::process::Child,
) -> anyhow::Result<()> {
    let iterations = START_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if path_exists(socket).await? {
            return Ok(());
        }

        if let Some(status) = child
            .try_wait()
            .context("failed to poll background ssh-agent status")?
        {
            let _ = fs::remove_file(pid_file).await;
            return Err(anyhow!("background ssh-agent exited early: {status}"));
        }

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

fn resolve_socket_path(socket: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match socket {
        Some(socket) => Ok(socket),
        None => default_socket_path(),
    }
}

fn default_socket_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow!("missing HOME; use --socket to set a path"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("turnkey")
        .join("tk")
        .join("ssh-agent.sock"))
}

async fn create_socket_parent_dir(socket: &Path) -> anyhow::Result<()> {
    if let Some(parent) = socket.parent() {
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
    let rc = unsafe { libc::kill(pid as i32, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
