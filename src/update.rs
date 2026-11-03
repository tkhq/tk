//! Replaces the running `tk` binary with a published release.

use std::{
    collections::BTreeMap,
    env,
    fmt::{self, Display, Formatter},
    fs::{self, OpenOptions, Permissions},
    io::{self, ErrorKind, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
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
use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
    time::timeout,
};
use uuid::Uuid;

use crate::{
    errors::{InvalidInput, UnexpectedHttpStatus},
    outcome::Outcome,
};

const CURRENT: &str = env!("CARGO_PKG_VERSION");
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 4 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const BINARY_MODE: u32 = 0o755;

// Linux releases are static musl builds, so they also replace a glibc build.
const TARGET: Option<&str> = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some("x86_64-unknown-linux-musl")
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    Some("aarch64-unknown-linux-musl")
} else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    Some("aarch64-apple-darwin")
} else {
    None
};

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Install this release tag instead of the latest release.
    #[arg(long, value_name = "TAG")]
    tag: Option<ReleaseTag>,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(transparent)]
struct ReleaseTag(String);

#[derive(Debug, Error)]
#[error("must be a release tag such as v0.4.0")]
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

impl ReleaseTag {
    fn version(&self) -> Result<Version, semver::Error> {
        Version::parse(self.0.strip_prefix('v').unwrap_or_default())
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

struct AttestedArchive {
    package: String,
    bytes: Vec<u8>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub async fn run(args: UpdateArgs) -> Result<Outcome> {
    let mut interrupt =
        signal(SignalKind::interrupt()).context("listen for SIGINT during update")?;
    tokio::select! {
        biased;
        _ = interrupt.recv() => Err(io::Error::new(ErrorKind::Interrupted, "tk update interrupted").into()),
        result = update(args) => result,
    }
}

async fn update(UpdateArgs { tag }: UpdateArgs) -> Result<Outcome> {
    let executable = env::current_exe()
        .and_then(fs::canonicalize)
        .context("locate the running tk binary")?;
    // A canonical path to the running binary names a file, so it always has a parent.
    #[allow(clippy::expect_used)]
    let directory = executable
        .parent()
        .expect("the running tk binary has a parent directory");
    if let Some(command) = cargo_update_command(directory, tag.as_ref())? {
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
            let latest_version = latest
                .version()
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

    install_release(
        &client,
        &format!("{REPOSITORY}/releases/download"),
        target,
        tag,
        executable,
        Path::new("cosign"),
    )
    .await
}

async fn install_release(
    client: &Client,
    releases: &str,
    target: &str,
    tag: ReleaseTag,
    executable: PathBuf,
    cosign: &Path,
) -> Result<Outcome> {
    let staged = Staged(executable.with_file_name(format!(".tk.{}", Uuid::new_v4())));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged.0)
            .with_context(|| format!("stage the new tk binary at {}", staged.0.display()))?;
        file.set_permissions(Permissions::from_mode(BINARY_MODE))
            .with_context(|| format!("write the new tk binary to {}", staged.0.display()))?;
        let archive = download_attested_archive(client, releases, target, &tag, cosign).await?;
        extract_verified_binary(&archive, &mut file)?;
        file.sync_all()
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

async fn download_attested_archive(
    client: &Client,
    releases: &str,
    target: &str,
    tag: &ReleaseTag,
    cosign: &Path,
) -> Result<AttestedArchive> {
    let package = format!("tk-{target}-{tag}");
    let download = format!("{releases}/{tag}/{package}.tar.gz");
    let checksum_url = format!("{download}.sha256");
    let bundle_url = format!("{download}.sigstore.json");
    let (archive, checksum, bundle) = tokio::try_join!(
        fetch(client, &download, MAX_ARCHIVE_BYTES),
        fetch(client, &checksum_url, MAX_CHECKSUM_BYTES),
        fetch(client, &bundle_url, MAX_BUNDLE_BYTES),
    )?;
    let archive_name = format!("{package}.tar.gz");
    let checksum_name = format!("{archive_name}.sha256");
    let checksum =
        str::from_utf8(&checksum).with_context(|| format!("{checksum_name} is not UTF-8"))?;
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
    if expected[..] != Sha256::digest(&archive)[..] {
        bail!("{archive_name} does not match {checksum_name}");
    }

    let temporary = tempfile::tempdir().context("create a directory for release verification")?;
    let archive_path = temporary.path().join("archive.tar.gz");
    let bundle_path = temporary.path().join("provenance.sigstore.json");
    fs::write(&archive_path, &archive).context("stage the release archive for verification")?;
    fs::write(&bundle_path, bundle).context("stage the release provenance for verification")?;
    let identity = format!("{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}");
    let verified = timeout(
        VERIFICATION_TIMEOUT,
        Command::new(cosign)
            .arg("verify-blob-attestation")
            .arg(&archive_path)
            .arg("--bundle")
            .arg(&bundle_path)
            .args(["--type", "slsaprovenance1"])
            .args([
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ])
            .args(["--certificate-identity", &identity])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Cosign release verification timed out")?
    .context("run cosign to verify the release; install Cosign 2.4.2 or later on PATH")?;
    if !verified.status.success() {
        bail!(
            "Cosign rejected the {tag} release provenance: {}",
            String::from_utf8_lossy(&verified.stderr).trim()
        );
    }
    Ok(AttestedArchive {
        package,
        bytes: archive,
    })
}

fn cargo_update_command(bin: &Path, tag: Option<&ReleaseTag>) -> Result<Option<String>> {
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
    let command = match tag {
        None => "cargo install turnkey_tk --locked".to_owned(),
        Some(tag) => {
            let Ok(version) = tag.version() else {
                return Err(InvalidInput(format!(
                    "cargo installed this tk, and crates.io publishes only vX.Y.Z releases, not {tag}"
                ))
                .into());
            };
            format!("cargo install turnkey_tk --locked --version {version}")
        }
    };
    let default_root = env::var_os("CARGO_INSTALL_ROOT")
        .or_else(|| env::var_os("CARGO_HOME"))
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .and_then(|root| fs::canonicalize(root).ok());
    Ok(Some(if default_root.as_deref() == Some(root) {
        command
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
    let status = response.status();
    if !status.is_success() {
        let mut body = Vec::new();
        while body.len() < MAX_CHECKSUM_BYTES
            && let Some(chunk) = response
                .chunk()
                .await
                .with_context(|| format!("download {url}"))?
        {
            body.extend_from_slice(&chunk);
        }
        body.truncate(MAX_CHECKSUM_BYTES);
        return Err(anyhow::Error::new(UnexpectedHttpStatus {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&body).into_owned(),
        })
        .context(format!("download {url}")));
    }
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
    Ok(bytes)
}

fn extract_verified_binary(
    AttestedArchive { package, bytes }: &AttestedArchive,
    binary: &mut impl Write,
) -> Result<()> {
    let archive_name = format!("{package}.tar.gz");
    let expected_binary = Path::new(package).join("tk");
    let mut entries = Archive::new(GzDecoder::new(bytes.as_slice()));
    for entry in entries
        .entries()
        .with_context(|| format!("read {archive_name}"))?
    {
        let mut entry = entry.with_context(|| format!("read {archive_name}"))?;
        let path = entry
            .path()
            .with_context(|| format!("read {archive_name}"))?
            .into_owned();
        if path != expected_binary {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            bail!(
                "{archive_name} holds {} as something other than a regular file",
                path.display()
            );
        }
        if usize::try_from(entry.size()).map_or(true, |size| size > MAX_ARCHIVE_BYTES) {
            bail!(
                "{archive_name} holds a {} larger than {MAX_ARCHIVE_BYTES} bytes",
                path.display()
            );
        }
        io::copy(&mut entry, binary)
            .with_context(|| format!("extract {} from {archive_name}", path.display()))?;
        return Ok(());
    }
    bail!(
        "{archive_name} does not contain {}",
        expected_binary.display()
    );
}

#[cfg(test)]
mod tests {
    use flate2::{Compression, write::GzEncoder};
    use serde_json::{json, to_value};
    use tar::{Builder, EntryType, Header};
    use tokio::sync::mpsc;
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate, Times,
        matchers::{method, path},
    };

    use super::*;

    const DARWIN_TARGET: &str = "aarch64-apple-darwin";
    const PACKAGE: &str = "tk-aarch64-apple-darwin-v1.0.0";

    fn archive(path: &str, kind: EntryType, contents: &[u8]) -> Vec<u8> {
        let mut builder = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mut header = Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(contents.len() as u64);
        header.set_mode(0o755);
        builder.append_data(&mut header, path, contents).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn checksum(archive: &[u8], name: &str) -> Vec<u8> {
        format!("{}  {name}\n", hex::encode(Sha256::digest(archive))).into_bytes()
    }

    fn cosign_stub(directory: &Path, script: &str) -> Result<PathBuf> {
        let cosign = directory.join("cosign");
        fs::write(&cosign, script)?;
        fs::set_permissions(&cosign, Permissions::from_mode(0o755))?;
        Ok(cosign)
    }

    async fn release_server(
        archive: impl Into<Vec<u8>>,
        listed_checksum: Option<Vec<u8>>,
        bundle: impl Into<Vec<u8>>,
        archive_downloads: impl Into<Times>,
        bundle_downloads: impl Into<Times>,
    ) -> MockServer {
        let server = MockServer::start().await;
        let archive = archive.into();
        let listed_checksum =
            listed_checksum.unwrap_or_else(|| checksum(&archive, &format!("{PACKAGE}.tar.gz")));
        let checksum = Mock::given(path(format!("/v1.0.0/{PACKAGE}.tar.gz.sha256")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(listed_checksum));
        let archive = Mock::given(path(format!("/v1.0.0/{PACKAGE}.tar.gz")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
            .expect(archive_downloads);
        let bundle = Mock::given(path(format!("/v1.0.0/{PACKAGE}.tar.gz.sigstore.json")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle))
            .expect(bundle_downloads);
        tokio::join!(
            archive.mount(&server),
            checksum.mount(&server),
            bundle.mount(&server)
        );
        server
    }

    #[tokio::test]
    async fn refuses_a_checksum_for_another_file_or_hash() -> Result<()> {
        let archive = archive(
            "tk-aarch64-apple-darwin-v1.0.0/tk",
            EntryType::Regular,
            b"binary",
        );
        let tag = "v1.0.0".parse()?;
        for (listed_checksum, expected) in [
            (
                checksum(&archive, "other.tar.gz"),
                format!("{PACKAGE}.tar.gz.sha256 names other.tar.gz instead of {PACKAGE}.tar.gz"),
            ),
            (
                checksum(b"other bytes", &format!("{PACKAGE}.tar.gz")),
                format!("{PACKAGE}.tar.gz does not match {PACKAGE}.tar.gz.sha256"),
            ),
        ] {
            let server =
                release_server(archive.clone(), Some(listed_checksum), b"bundle", 1, 1).await;
            let error = download_attested_archive(
                &Client::new(),
                &server.uri(),
                DARWIN_TARGET,
                &tag,
                Path::new("/missing-cosign"),
            )
            .await
            .err()
            .context("a mismatched checksum must fail")?;
            assert_eq!(error.to_string(), expected);
        }
        Ok(())
    }

    #[test]
    fn refuses_non_file_binaries() {
        let linked = AttestedArchive {
            package: PACKAGE.to_owned(),
            bytes: archive("tk-aarch64-apple-darwin-v1.0.0/tk", EntryType::Symlink, b""),
        };
        assert_eq!(
            extract_verified_binary(&linked, &mut io::sink())
                .unwrap_err()
                .to_string(),
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

    #[tokio::test]
    async fn verified_release_replaces_the_binary_and_runs_the_new_version() -> Result<()> {
        let binary = r#"#!/bin/sh
echo 'tk 1.0.0'
"#;
        let archive = archive(
            &format!("{PACKAGE}/tk"),
            EntryType::Regular,
            binary.as_bytes(),
        );
        let server = release_server(archive, None, b"bundle", 1, 1).await;
        let directory = tempfile::tempdir()?;
        let install = directory.path().join("install");
        fs::create_dir(&install)?;
        let executable = install.join("tk");
        fs::write(&executable, "old binary")?;
        let cosign = cosign_stub(
            directory.path(),
            r#"#!/bin/sh
exit 0
"#,
        )?;
        let updated = install_release(
            &Client::new(),
            &server.uri(),
            "aarch64-apple-darwin",
            "v1.0.0".parse()?,
            executable.clone(),
            &cosign,
        )
        .await?;
        assert_eq!(
            to_value(updated)?,
            json!({
                "reason": "updated",
                "from": CURRENT,
                "to": "v1.0.0",
                "path": executable,
            })
        );
        assert_eq!(fs::read_to_string(&executable)?, binary);
        let version = Command::new(&executable).arg("--version").output().await?;
        assert!(version.status.success(), "{version:?}");
        assert_eq!(version.stdout, b"tk 1.0.0\n");
        assert_eq!(fs::read_dir(&install)?.count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_verification_removes_its_archive_bundle_and_directory() -> Result<()> {
        let server = release_server(b"archive", None, b"bundle", .., ..).await;
        let (sender, mut receiver) = mpsc::channel(1);
        Mock::given(path("/ready"))
            .and(method("POST"))
            .respond_with(move |request: &Request| {
                let _ = sender.try_send(request.body.clone());
                ResponseTemplate::new(200).set_delay(Duration::from_secs(30))
            })
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir()?;
        let cosign = cosign_stub(
            directory.path(),
            &format!(
                r#"#!/bin/sh
set -eu
test -f "$2"
test -f "$4"
exec curl --silent --show-error --data-binary "$2
$4" "{}/ready"
"#,
                server.uri()
            ),
        )?;
        let client = Client::new();
        let releases = server.uri();
        let tag = "v1.0.0".parse()?;
        let paths = tokio::select! {
            result = download_attested_archive(&client, &releases, DARWIN_TARGET, &tag, &cosign) => {
                result?;
                bail!("verification finished before cancellation");
            },
            paths = timeout(Duration::from_secs(10), receiver.recv()) => {
                paths?.context("verification did not stage its files")?
            },
        };
        let paths: Vec<_> = str::from_utf8(&paths)?.lines().map(PathBuf::from).collect();
        assert_eq!(paths.len(), 2);
        for path in paths {
            assert!(!path.exists(), "{}", path.display());
            assert!(!path.parent().context("staged file directory")?.exists());
        }
        Ok(())
    }

    #[tokio::test]
    async fn cosign_checks_the_archive_and_exact_release_identity() -> Result<()> {
        let server = release_server(b"archive", None, b"bundle", 3, 3).await;
        let directory = tempfile::tempdir()?;
        let cosign = cosign_stub(
            directory.path(),
            r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "${0%/*}/arguments"
cp "$2" "${0%/*}/archive"
cp "$4" "${0%/*}/bundle"
read -r status < "${0%/*}/exit"
echo 'verification diagnostic' >&2
exit "$status"
"#,
        )?;
        let client = Client::new();
        let tag = "v1.0.0".parse::<ReleaseTag>()?;
        for status in [0, 17] {
            fs::write(directory.path().join("exit"), format!("{status}\n"))?;
            let result =
                download_attested_archive(&client, &server.uri(), DARWIN_TARGET, &tag, &cosign)
                    .await;
            if status == 0 {
                assert_eq!(result?.bytes, b"archive");
            } else {
                assert_eq!(
                    result.err().context("verification must fail")?.to_string(),
                    "Cosign rejected the v1.0.0 release provenance: verification diagnostic"
                );
            }
        }
        let arguments = fs::read_to_string(directory.path().join("arguments"))?;
        let arguments: Vec<_> = arguments.lines().collect();
        assert_eq!(
            arguments,
            [
                "verify-blob-attestation",
                arguments[1],
                "--bundle",
                arguments[3],
                "--type",
                "slsaprovenance1",
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--certificate-identity",
                "https://github.com/tkhq/tk/.github/workflows/release.yml@refs/tags/v1.0.0",
            ]
        );
        assert_eq!(fs::read(directory.path().join("archive"))?, b"archive");
        assert_eq!(fs::read(directory.path().join("bundle"))?, b"bundle");
        assert!(!Path::new(arguments[1]).exists());
        assert!(!Path::new(arguments[3]).exists());
        fs::remove_file(&cosign)?;
        let error = download_attested_archive(&client, &server.uri(), DARWIN_TARGET, &tag, &cosign)
            .await
            .err()
            .context("missing cosign must fail")?;
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(ErrorKind::NotFound)
        );
        Ok(())
    }

    #[tokio::test]
    async fn oversized_provenance_cannot_produce_an_attested_archive() -> Result<()> {
        let server =
            release_server(b"archive", None, vec![b' '; MAX_BUNDLE_BYTES + 1], .., 1).await;
        let error = download_attested_archive(
            &Client::new(),
            &server.uri(),
            DARWIN_TARGET,
            &"v1.0.0".parse()?,
            Path::new("/missing-cosign"),
        )
        .await
        .err()
        .context("oversized provenance must fail")?;
        assert_eq!(
            error.to_string(),
            format!(
                "{}/v1.0.0/{PACKAGE}.tar.gz.sigstore.json exceeds the {MAX_BUNDLE_BYTES}-byte download limit",
                server.uri()
            )
        );
        Ok(())
    }
}
