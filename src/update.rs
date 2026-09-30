//! Replaces the running `tk` binary with a published release.

use std::{
    collections::BTreeMap,
    env,
    fmt::{self, Display, Formatter},
    fs::{self, OpenOptions, Permissions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    str::{self, FromStr},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use flate2::read::GzDecoder;
use hex::FromHex;
use reqwest::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use tokio::{process::Command, time::timeout};
use uuid::Uuid;

use crate::{errors::UnexpectedHttpStatus, outcome::Outcome};

const CURRENT: &str = env!("CARGO_PKG_VERSION");
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 4 * 1024;
const BINARY_MODE: u32 = 0o755;

// Linux releases are static musl builds, so they also replace a glibc build.
const TARGET: Option<&str> = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some("x86_64-unknown-linux-musl")
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    Some("aarch64-unknown-linux-musl")
} else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
    Some("x86_64-apple-darwin")
} else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    Some("aarch64-apple-darwin")
} else {
    None
};

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Install this release or pull request prerelease tag, even an older one, instead of the latest release.
    #[arg(long, value_name = "TAG")]
    tag: Option<ReleaseTag>,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(transparent)]
struct ReleaseTag(String);

#[derive(Debug, Error)]
#[error("must be a release or prerelease tag such as v0.4.0 or pr-44-abc1234")]
struct InvalidReleaseTag;

impl FromStr for ReleaseTag {
    type Err = InvalidReleaseTag;

    fn from_str(tag: &str) -> Result<Self, Self::Err> {
        if tag.is_empty()
            || tag.starts_with('.')
            || !tag
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(InvalidReleaseTag);
        }
        Ok(Self(tag.to_owned()))
    }
}

impl Display for ReleaseTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct Updated {
    from: &'static str,
    to: ReleaseTag,
    path: PathBuf,
}

impl Display for Updated {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "updated tk {} to {} at {}",
            self.from,
            self.to,
            self.path.display()
        )
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct AlreadyUpToDate {
    version: &'static str,
    latest: ReleaseTag,
}

impl Display for AlreadyUpToDate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tk {} is up to date; the latest release is {}",
            self.version, self.latest
        )
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct UpdateViaCargo {
    command: String,
}

impl Display for UpdateViaCargo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cargo installed this tk; update it with `{}`",
            self.command
        )
    }
}

#[derive(Deserialize)]
struct CargoInstalls {
    v1: BTreeMap<String, Vec<String>>,
}

struct Staged(PathBuf);

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub async fn run(UpdateArgs { tag }: UpdateArgs) -> Result<Outcome> {
    let executable = env::current_exe()
        .and_then(fs::canonicalize)
        .context("locate the running tk binary")?;
    // A canonical path to the running binary names a file, so it always has a parent.
    #[allow(clippy::expect_used)]
    let directory = executable
        .parent()
        .expect("the running tk binary has a parent directory");
    if let Some(command) = cargo_update_command(directory)? {
        return Ok(Outcome::UpdateViaCargo(UpdateViaCargo { command }));
    }
    let Some(target) = TARGET else {
        bail!(
            "tk releases do not support {} {}",
            env::consts::OS,
            env::consts::ARCH
        );
    };
    let client = Client::builder()
        .user_agent(concat!("tk/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build()
        .context("build the release download client")?;

    let tag = match tag {
        Some(tag) => tag,
        None => {
            // The /releases/latest redirect names the newest release without an API token.
            let url = format!("{REPOSITORY}/releases/latest");
            let response = client
                .head(&url)
                .send()
                .await
                .with_context(|| format!("resolve the latest tk release from {url}"))?;
            let status = response.status();
            if !status.is_success() {
                return Err(anyhow::Error::new(UnexpectedHttpStatus {
                    status: status.as_u16(),
                    body: String::new(),
                })
                .context(format!("resolve the latest tk release from {url}")));
            }
            let final_url = response.url();
            let latest = final_url
                .path_segments()
                .and_then(|mut segments| {
                    match (
                        segments.next_back(),
                        segments.next_back(),
                        segments.next_back(),
                    ) {
                        (Some(tag), Some("tag"), Some("releases")) => Some(tag),
                        _ => None,
                    }
                })
                .with_context(|| format!("{final_url} does not name a tk release"))?
                .parse::<ReleaseTag>()
                .with_context(|| format!("{final_url} does not name a tk release"))?;
            let latest_version = Version::parse(latest.0.strip_prefix('v').unwrap_or_default())
                .with_context(|| format!("the latest tk release {latest} is not a vX.Y.Z tag"))?;
            // Cargo rejects a package version that is not semver, so parsing it cannot fail.
            #[allow(clippy::expect_used)]
            let current = Version::parse(CURRENT).expect("CARGO_PKG_VERSION is semver");
            if latest_version <= current {
                return Ok(Outcome::AlreadyUpToDate(AlreadyUpToDate {
                    version: CURRENT,
                    latest,
                }));
            }
            latest
        }
    };

    let package = format!("tk-{target}-{tag}");
    let download = format!("{REPOSITORY}/releases/download/{tag}/{package}.tar.gz");
    let checksum_url = format!("{download}.sha256");
    let (archive, checksum) = tokio::try_join!(
        fetch(&client, &download, MAX_ARCHIVE_BYTES),
        fetch(&client, &checksum_url, MAX_CHECKSUM_BYTES),
    )?;
    let binary = verified_binary(&archive, &checksum, &package)?;

    let staged = Staged(directory.join(format!(".tk.{}", Uuid::new_v4())));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged.0)
            .with_context(|| format!("stage the new tk binary at {}", staged.0.display()))?;
        file.set_permissions(Permissions::from_mode(BINARY_MODE))
            .and_then(|()| file.write_all(&binary))
            .and_then(|()| file.sync_all())
            .with_context(|| format!("write the new tk binary to {}", staged.0.display()))?;
    }
    match timeout(
        READ_TIMEOUT,
        Command::new(&staged.0)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    {
        Ok(Ok(smoke)) if smoke.status.success() => {}
        Ok(Err(error)) => return Err(error).with_context(|| format!("run the {tag} tk binary")),
        _ => bail!("the {tag} tk binary cannot run on this system"),
    }
    fs::rename(&staged.0, &executable)
        .with_context(|| format!("replace {} with the {tag} binary", executable.display()))?;

    Ok(Outcome::Updated(Updated {
        from: CURRENT,
        to: tag,
        path: executable,
    }))
}

fn cargo_update_command(bin: &Path) -> Result<Option<String>> {
    let Some(root) = bin
        .parent()
        .filter(|_| bin.file_name() == Some("bin".as_ref()))
    else {
        return Ok(None);
    };
    let path = root.join(".crates.toml");
    let installs = match fs::read_to_string(&path) {
        Ok(installs) => installs,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    };
    let CargoInstalls { v1 } =
        toml::from_str(&installs).with_context(|| format!("parse {}", path.display()))?;
    let owned = v1.into_iter().any(|(package, binaries)| {
        package.starts_with("turnkey_tk ") && binaries.iter().any(|binary| binary == "tk")
    });
    if !owned {
        return Ok(None);
    }
    let command = "cargo install turnkey_tk --locked";
    let default_root = env::var_os("CARGO_INSTALL_ROOT")
        .or_else(|| env::var_os("CARGO_HOME"))
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .and_then(|root| fs::canonicalize(root).ok());
    Ok(Some(if default_root.as_deref() == Some(root) {
        command.to_owned()
    } else {
        let quoted = root.display().to_string().replace('\'', r"'\''");
        format!("{command} --root '{quoted}'")
    }))
}

async fn fetch(client: &Client, url: &str, limit: usize) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("download {url}"))?;
    let mut bytes = Vec::with_capacity(response.content_length().map_or(0, |length| {
        usize::try_from(length).unwrap_or(limit).min(limit)
    }));
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("download {url}"))?
    {
        if bytes.len() + chunk.len() > limit {
            bail!("{url} exceeds the {limit}-byte download limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::Error::new(UnexpectedHttpStatus {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
        .context(format!("download {url}")));
    }
    Ok(bytes)
}

fn verified_binary(archive: &[u8], checksum: &[u8], package: &str) -> Result<Vec<u8>> {
    let archive_name = format!("{package}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let checksum =
        str::from_utf8(checksum).with_context(|| format!("{checksum_name} is not UTF-8"))?;
    let mut fields = checksum.split_whitespace();
    let (Some(expected), Some(listed), None) = (fields.next(), fields.next(), fields.next()) else {
        bail!("{checksum_name} is not one `shasum -a 256` line");
    };
    let listed = listed.trim_start_matches('*');
    if listed != archive_name {
        bail!("{checksum_name} names {listed} instead of {archive_name}");
    }
    let expected = <[u8; 32]>::from_hex(expected)
        .with_context(|| format!("{checksum_name} does not hold a SHA-256 digest"))?;
    if expected[..] != Sha256::digest(archive)[..] {
        bail!("{archive_name} does not match {checksum_name}");
    }

    let root = Path::new(package);
    let expected_binary = root.join("tk");
    let mut entries = Archive::new(GzDecoder::new(archive));
    let mut binary = None;
    for entry in entries
        .entries()
        .with_context(|| format!("read {archive_name}"))?
    {
        let mut entry = entry.with_context(|| format!("read {archive_name}"))?;
        let path = entry
            .path()
            .with_context(|| format!("read {archive_name}"))?
            .into_owned();
        if !path.starts_with(root)
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            bail!("{archive_name} holds {} outside {package}/", path.display());
        }
        if path != expected_binary {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            bail!(
                "{archive_name} holds {} as something other than a regular file",
                path.display()
            );
        }
        if binary.is_some() {
            bail!("{archive_name} holds more than one {}", path.display());
        }
        let Some(size) = usize::try_from(entry.size())
            .ok()
            .filter(|&size| size <= MAX_ARCHIVE_BYTES)
        else {
            bail!(
                "{archive_name} holds a {} larger than {MAX_ARCHIVE_BYTES} bytes",
                path.display()
            );
        };
        let mut bytes = Vec::with_capacity(size);
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("extract {} from {archive_name}", path.display()))?;
        binary = Some(bytes);
    }
    binary.with_context(|| {
        format!(
            "{archive_name} does not contain {}",
            expected_binary.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, EntryType, Header};

    use super::*;

    const PACKAGE: &str = "tk-aarch64-apple-darwin-v1.0.0";

    fn archive(entries: &[(&str, EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, kind, contents) in entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            // `append_data` rejects `..`, so write the raw name to build hostile archives.
            header.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *contents).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn checksum(archive: &[u8], name: &str) -> Vec<u8> {
        format!("{}  {name}\n", hex::encode(Sha256::digest(archive))).into_bytes()
    }

    fn valid_checksum(archive: &[u8]) -> Vec<u8> {
        checksum(archive, &format!("{PACKAGE}.tar.gz"))
    }

    fn error(archive: &[u8], checksum: &[u8]) -> String {
        verified_binary(archive, checksum, PACKAGE)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn refuses_a_checksum_for_another_file_or_hash() {
        let archive = archive(&[(
            "tk-aarch64-apple-darwin-v1.0.0/tk",
            EntryType::Regular,
            b"binary",
        )]);

        assert_eq!(
            error(&archive, &checksum(&archive, "other.tar.gz")),
            format!("{PACKAGE}.tar.gz.sha256 names other.tar.gz instead of {PACKAGE}.tar.gz")
        );
        assert_eq!(
            error(
                &archive,
                &checksum(b"other bytes", &format!("{PACKAGE}.tar.gz"))
            ),
            format!("{PACKAGE}.tar.gz does not match {PACKAGE}.tar.gz.sha256")
        );
    }

    #[test]
    fn refuses_paths_outside_the_package_and_non_file_binaries() {
        let escaping = archive(&[(
            "tk-aarch64-apple-darwin-v1.0.0/../tk",
            EntryType::Regular,
            b"binary",
        )]);
        assert_eq!(
            error(&escaping, &valid_checksum(&escaping)),
            format!(
                "{PACKAGE}.tar.gz holds tk-aarch64-apple-darwin-v1.0.0/../tk outside {PACKAGE}/"
            )
        );

        let linked = archive(&[("tk-aarch64-apple-darwin-v1.0.0/tk", EntryType::Symlink, b"")]);
        assert_eq!(
            error(&linked, &valid_checksum(&linked)),
            format!(
                "{PACKAGE}.tar.gz holds tk-aarch64-apple-darwin-v1.0.0/tk as something other than a regular file"
            )
        );
    }

    #[test]
    fn release_tags_are_limited_to_url_safe_characters() {
        for tag in ["v0.4.0", "pr-44-abc1234"] {
            assert_eq!(tag.parse::<ReleaseTag>().unwrap().0, tag);
        }
        for tag in ["", ".", "..", ".x", "v0.4.0/../x", "v0.4.0?x", "v0 4"] {
            assert!(tag.parse::<ReleaseTag>().is_err(), "{tag}");
        }
    }
}
