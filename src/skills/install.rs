use std::{
    collections::BTreeSet,
    env,
    fs::{self, Permissions},
    io::{self, ErrorKind},
    mem::take,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use thiserror::Error;
use uuid::Uuid;

use super::bundle::{DIGEST, FILES, InstallManifest, Installed, MANIFEST_FILE, ROOT, VERSION};
use crate::errors::{InvalidInput, Malformed};

const DIR_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;

#[derive(Clone, Debug)]
pub struct InstallDir(PathBuf);

#[derive(Debug, Error)]
#[error("contains ..; pass the resolved directory instead")]
pub struct ParentDirComponent;

impl TryFrom<PathBuf> for InstallDir {
    type Error = ParentDirComponent;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        path.components()
            .map(|component| match component {
                Component::ParentDir => Err(ParentDirComponent),
                Component::CurDir => Ok(None),
                Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                    Ok(Some(component))
                }
            })
            .filter_map(Result::transpose)
            .collect::<Result<PathBuf, _>>()
            .map(Self)
    }
}

struct Guard(PathBuf);

impl Guard {
    fn publish(mut self) -> PathBuf {
        take(&mut self.0)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

pub fn install(InstallDir(given): InstallDir) -> Result<Installed> {
    let into = env::current_dir()
        .context("resolve the current directory for --into")?
        .join(given);
    for ancestor in into.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(InvalidInput(format!(
                    "--into {} is a symlink; pass the resolved directory instead",
                    ancestor.display()
                ))
                .into());
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(InvalidInput(format!(
                    "--into {} is not a directory",
                    ancestor.display()
                ))
                .into());
            }
            Ok(_) if fs::symlink_metadata(ancestor.join(MANIFEST_FILE)).is_ok() => {
                return Err(InvalidInput(format!(
                    "--into {} is inside a {ROOT} install",
                    ancestor.display()
                ))
                .into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect --into {}", ancestor.display()));
            }
        }
    }
    fs::create_dir_all(&into).with_context(|| format!("create --into {}", into.display()))?;

    let destination = into.join(ROOT);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(InvalidInput(format!(
                "{} is a symlink; remove it or choose another --into",
                destination.display()
            ))
            .into());
        }
        Ok(metadata) if metadata.is_dir() => {
            let persisted = destination.join(MANIFEST_FILE);
            let InstallManifest {
                binary_version: _,
                digest,
                files,
            } = match fs::read_to_string(&persisted) {
                Ok(text) => serde_json::from_str(&text).map_err(|error| {
                    Malformed::new(
                        format!(
                            "{} is not a {ROOT} install manifest; remove {} to reinstall",
                            persisted.display(),
                            destination.display()
                        ),
                        error,
                    )
                })?,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Err(InvalidInput(format!(
                        "{} exists without a {MANIFEST_FILE}; if no other install is running, remove it or choose another --into",
                        destination.display()
                    ))
                    .into());
                }
                Err(error) => {
                    return Err(Malformed::new(
                        format!(
                            "{} could not be read; remove {} to reinstall",
                            persisted.display(),
                            destination.display()
                        ),
                        error,
                    )
                    .into());
                }
            };
            if digest != DIGEST {
                return Err(InvalidInput(format!(
                    "{} holds a different {ROOT} package; remove it to install this one",
                    destination.display()
                ))
                .into());
            }
            return Ok(Installed {
                destination,
                version: VERSION,
                digest: DIGEST,
                files,
                already_installed: true,
            });
        }
        Ok(_) => {
            return Err(InvalidInput(format!(
                "{} exists and is not a directory",
                destination.display()
            ))
            .into());
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", destination.display()));
        }
    }

    let manifest = InstallManifest::embedded();
    let staging = Guard(into.join(format!(".{ROOT}.{}", Uuid::new_v4())));
    (|| -> Result<()> {
        let mkdir = |path: &Path| -> io::Result<()> {
            fs::create_dir(path)?;
            fs::set_permissions(path, Permissions::from_mode(DIR_MODE))
        };
        let write = |path: &Path, content: &[u8]| -> io::Result<()> {
            fs::write(path, content)?;
            fs::set_permissions(path, Permissions::from_mode(FILE_MODE))
        };
        mkdir(&staging.0)?;
        let directories: BTreeSet<&Path> = FILES
            .iter()
            .filter_map(|file| Path::new(file.path).parent())
            .filter(|parent| !parent.as_os_str().is_empty())
            .collect();
        for directory in directories {
            mkdir(&staging.0.join(directory))?;
        }
        for file in FILES {
            write(&staging.0.join(file.path), file.content.as_bytes())?;
        }
        write(
            &staging.0.join(MANIFEST_FILE),
            serde_json::to_string_pretty(&manifest)
                .context("encode the install manifest")?
                .as_bytes(),
        )?;
        Ok(())
    })()
    .with_context(|| format!("stage {ROOT} under {}", into.display()))?;

    let claimed = match fs::create_dir(&destination) {
        Ok(()) => Guard(destination),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return Err(InvalidInput(format!(
                "{} appeared while installing; nothing was replaced",
                destination.display()
            ))
            .into());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("create {}", destination.display()));
        }
    };
    (|| -> Result<()> {
        fs::set_permissions(&claimed.0, Permissions::from_mode(DIR_MODE))?;
        for entry in fs::read_dir(&staging.0)? {
            let entry = entry?;
            let name = entry.file_name();
            if name != MANIFEST_FILE {
                fs::rename(entry.path(), claimed.0.join(name))?;
            }
        }
        fs::rename(staging.0.join(MANIFEST_FILE), claimed.0.join(MANIFEST_FILE))?;
        Ok(())
    })()
    .with_context(|| format!("publish {ROOT} to {}", claimed.0.display()))?;

    Ok(Installed {
        destination: claimed.publish(),
        version: VERSION,
        digest: DIGEST,
        files: manifest.files,
        already_installed: false,
    })
}
