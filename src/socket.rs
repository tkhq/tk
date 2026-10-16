use std::{
    fmt::{self, Display, Formatter},
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{self, ErrorKind},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SocketMode(u32);

#[derive(Debug, Error)]
#[error("socket mode must be an octal value from 000 through 777")]
pub struct SocketModeError;

impl FromStr for SocketMode {
    type Err = SocketModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        u32::from_str_radix(value, 8)
            .ok()
            .filter(|mode| *mode <= 0o777)
            .map(Self)
            .ok_or(SocketModeError)
    }
}

pub(crate) fn agent_lock_path(path: &Path) -> PathBuf {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    lock_name.into()
}

pub fn open_agent_lock(guarded: &Path) -> Result<File> {
    let path = agent_lock_path(guarded);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("failed to open agent lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect agent lock {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("refusing to use non-regular agent lock {}", path.display());
    }
    // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "refusing to use agent lock {} owned by another user",
            path.display()
        );
    }
    file.set_permissions(Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict agent lock {}", path.display()))?;
    Ok(file)
}

pub fn try_lock_agent(file: File) -> io::Result<Option<File>> {
    // SAFETY: flock only observes the valid file descriptor owned by `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let error = io::Error::last_os_error();
    if error.kind() == ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error)
}

pub fn restrict_agent_socket(path: &Path, mode: SocketMode) -> Result<Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect agent socket {}", path.display()))?;
    if !metadata.file_type().is_socket() {
        bail!("refusing to restrict non-socket path {}", path.display());
    }
    fs::set_permissions(path, Permissions::from_mode(mode.0))
        .with_context(|| format!("failed to restrict agent socket {}", path.display()))?;
    Ok(metadata)
}

impl Display for SocketMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:03o}", self.0)
    }
}

impl Serialize for SocketMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SocketMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::{fs::symlink, net::UnixListener};

    use super::*;

    #[test]
    fn restricting_a_symlinked_socket_leaves_the_target_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.sock");
        let link = directory.path().join("agent.sock");
        let _listener = UnixListener::bind(&target).unwrap();
        fs::set_permissions(&target, Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &link).unwrap();

        let error = restrict_agent_socket(&link, "600".parse().unwrap()).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("refusing to restrict non-socket path {}", link.display())
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
