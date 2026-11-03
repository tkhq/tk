//! Verifies update cancellation without downloading a release.

use std::{env, fs, process::Stdio, time::Duration};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{net::TcpListener, process::Command, time::timeout};

#[tokio::test]
async fn interrupt_preserves_the_binary_and_removes_staged_files() -> Result<()> {
    let directory = tempdir()?;
    let install = directory.path().join("install");
    let temporary = directory.path().join("temporary");
    fs::create_dir(&install)?;
    fs::create_dir(&temporary)?;
    let binary = install.join("tk");
    fs::copy(env!("CARGO_BIN_EXE_tk"), &binary)?;
    let before = fs::read(&binary)?;
    let proxy = TcpListener::bind("127.0.0.1:0").await?;
    let child = Command::new(&binary)
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", directory.path())
        .env("TMPDIR", &temporary)
        .env("HTTPS_PROXY", format!("http://{}", proxy.local_addr()?))
        .args(["--message-format", "json", "update", "--tag", "v0.4.0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let (_connection, _) = timeout(Duration::from_secs(10), proxy.accept()).await??;
    assert_eq!(fs::read_dir(&install)?.count(), 2);
    let pid = child.id().context("the update must still be running")?;
    assert_eq!(unsafe { libc::kill(pid.cast_signed(), libc::SIGINT) }, 0);
    let output = timeout(Duration::from_secs(10), child.wait_with_output()).await??;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let record: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        record,
        json!({
            "reason": "command_error",
            "code": "command_error",
            "message": "tk update interrupted",
        })
    );
    assert_eq!(fs::read(&binary)?, before);
    assert_eq!(fs::read_dir(&install)?.count(), 1);
    assert_eq!(fs::read_dir(&temporary)?.count(), 0);
    Ok(())
}
