use std::{
    fs::{File, OpenOptions},
    io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tokio::task::spawn_blocking;

pub(super) struct AgentLock {
    _file: File,
}

impl AgentLock {
    pub(super) async fn acquire(path: PathBuf) -> Result<Option<Self>> {
        spawn_blocking(move || {
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

pub(super) fn resolve_lock_file(pid_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", pid_file.display()))
}

pub(super) async fn is_lock_held_by_other(path: PathBuf) -> Result<bool> {
    spawn_blocking(move || {
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

fn open_lock_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("failed to open lock file {}", path.display()))
}

fn try_lock_exclusive(file: &File) -> Result<bool> {
    // SAFETY: `flock` only inspects the raw file descriptor borrowed from
    // `file`.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(true)
    } else {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EWOULDBLOCK) => Ok(false),
            _ => Err(error).context("failed to acquire ssh-agent lock"),
        }
    }
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
