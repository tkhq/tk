use std::path::PathBuf;

use clap::{Args as ClapArgs, Subcommand};

const DEFAULT_SOCKET_DIR: &str = "/tmp";

#[derive(Debug, ClapArgs)]
#[command(about = "Manage the Turnkey SSH agent.", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Unix socket path to bind for SSH agent connections.
    /// Used only when running without a subcommand (foreground mode).
    #[arg(long, value_name = "path", global = true)]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the SSH agent as a background daemon.
    Start,
    /// Stop a running SSH agent daemon.
    Stop,
    /// Check if the SSH agent daemon is running.
    Status,
}

/// Runs the `tk ssh-agent` subcommand.
pub async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        None => {
            let socket = args.socket.ok_or_else(|| {
                anyhow::anyhow!("--socket is required when running in foreground mode")
            })?;
            turnkey_auth::ssh::agent::run(socket).await
        }
        Some(Command::Start) => {
            let socket = resolve_socket_path(args.socket.as_ref());
            let pid_path = pid_file_path();

            if let Some(pid) = read_running_pid(&pid_path) {
                println!("SSH agent already running (pid {pid})");
                print_env(&socket);
                return Ok(());
            }

            let exe = std::env::current_exe()?;
            let mut cmd = tokio::process::Command::new(exe);
            cmd.arg("ssh-agent")
                .arg("--socket")
                .arg(&socket)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());

            // SAFETY: setsid() is async-signal-safe and is the standard way to
            // detach a daemon from the controlling terminal after fork, before exec.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }

            let child = cmd.spawn()?;
            let pid = child
                .id()
                .ok_or_else(|| anyhow::anyhow!("failed to get daemon pid"))?;

            if let Some(parent) = pid_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&pid_path, pid.to_string()).await?;

            // Wait briefly for socket to appear.
            for _ in 0..20 {
                if tokio::fs::try_exists(&socket).await.unwrap_or(false) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            println!("SSH agent started (pid {pid})");
            print_env(&socket);
            Ok(())
        }
        Some(Command::Stop) => {
            let pid_path = pid_file_path();
            let socket = resolve_socket_path(args.socket.as_ref());

            if let Some(pid) = read_running_pid(&pid_path) {
                // Verify it is actually our agent by probing the socket.
                if !probe_agent(&socket).await {
                    anyhow::bail!(
                        "pid {pid} is running but the socket is not responding as an SSH agent"
                    );
                }

                let pid_t = libc::pid_t::try_from(pid)
                    .map_err(|_| anyhow::anyhow!("pid {pid} exceeds valid range"))?;

                // SAFETY: kill with SIGTERM requests graceful termination of a validated PID.
                let rc = unsafe { libc::kill(pid_t, libc::SIGTERM) };
                if rc == -1 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EPERM) {
                        anyhow::bail!(
                            "permission denied sending signal to pid {pid} \
                             (process may belong to another user)"
                        );
                    }
                }
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(&socket);

                println!("SSH agent stopped (pid {pid})");
                Ok(())
            } else {
                println!("SSH agent is not running");
                Ok(())
            }
        }
        Some(Command::Status) => {
            let pid_path = pid_file_path();
            if let Some(pid) = read_running_pid(&pid_path) {
                let socket = resolve_socket_path(args.socket.as_ref());
                println!("SSH agent is running (pid {pid})");
                print_env(&socket);
                Ok(())
            } else {
                println!("SSH agent is not running");
                Ok(())
            }
        }
    }
}

fn resolve_socket_path(explicit: Option<&PathBuf>) -> PathBuf {
    explicit.cloned().unwrap_or_else(|| {
        // SAFETY: getuid() is always safe and has no failure mode.
        let uid = unsafe { libc::getuid() };
        PathBuf::from(DEFAULT_SOCKET_DIR).join(format!("tk-agent-{uid}.sock"))
    })
}

fn pid_file_path() -> PathBuf {
    // SAFETY: getuid() is always safe and has no failure mode.
    let uid = unsafe { libc::getuid() };
    PathBuf::from(DEFAULT_SOCKET_DIR).join(format!("tk-agent-{uid}.pid"))
}

fn read_running_pid(path: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    let pid: u32 = content.trim().parse().ok()?;

    let pid_t = libc::pid_t::try_from(pid).ok()?;
    // SAFETY: kill with signal 0 performs a permission check without sending a signal.
    let rc = unsafe { libc::kill(pid_t, 0) };
    if rc == 0 {
        return Some(pid);
    }

    // EPERM means the process exists but belongs to another user. Treat it as alive
    // to avoid removing a PID file for a process we cannot manage.
    let errno = std::io::Error::last_os_error();
    if errno.raw_os_error() == Some(libc::EPERM) {
        return Some(pid);
    }

    // Process does not exist, clean up stale PID file.
    let _ = std::fs::remove_file(path);
    None
}

/// Probes the socket with an SSH agent request-identities message to verify
/// it is actually our agent before sending SIGTERM.
async fn probe_agent(socket: &std::path::Path) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(5), probe_agent_inner(socket))
        .await
        .unwrap_or(false)
}

async fn probe_agent_inner(socket: &std::path::Path) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let Ok(mut stream) = UnixStream::connect(socket).await else {
        return false;
    };

    // SSH_AGENTC_REQUEST_IDENTITIES = 11, frame: [0,0,0,1,11]
    let request = [0u8, 0, 0, 1, 11];
    if stream.write_all(&request).await.is_err() {
        return false;
    }

    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return false;
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 1 << 20 {
        return false;
    }

    let mut body = vec![0u8; len];
    if stream.read_exact(&mut body).await.is_err() {
        return false;
    }

    // SSH_AGENT_IDENTITIES_ANSWER = 12
    body[0] == 12
}

fn print_env(socket: &std::path::Path) {
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket.display());
}
