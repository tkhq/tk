use std::{fs::File, io, os::fd::AsRawFd, path::PathBuf};

use anyhow::{Context, Result};
use tokio::task::spawn_blocking;

use crate::socket::{open_agent_lock, try_lock_agent};

pub(super) struct AgentLock {
    _file: File,
}

impl AgentLock {
    pub(super) async fn acquire(pid_file: PathBuf) -> Result<Option<Self>> {
        spawn_blocking(move || {
            let file = open_agent_lock(&pid_file)?;
            Ok(try_lock_agent(file)
                .context("failed to acquire ssh-agent lock")?
                .map(|file| Self { _file: file }))
        })
        .await
        .context("failed to join lock acquisition task")?
    }
}

pub(super) async fn is_lock_held_by_other(pid_file: PathBuf) -> Result<bool> {
    spawn_blocking(move || {
        let file = open_agent_lock(&pid_file)?;
        match try_lock_agent(file).context("failed to acquire ssh-agent lock")? {
            Some(file) => {
                unlock_file(&file)?;
                Ok(false)
            }
            None => Ok(true),
        }
    })
    .await
    .context("failed to join lock inspection task")?
}

fn unlock_file(file: &File) -> Result<()> {
    // SAFETY: `flock` only inspects the raw file descriptor borrowed from
    // `file`.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()).context("failed to release ssh-agent lock")
    }
}
