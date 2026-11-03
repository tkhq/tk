//! Verifies installer ordering and atomic replacement with local release fixtures.

use std::{
    fs::{self, Permissions},
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
};

use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use tar::{Builder, Header};
use tempfile::{TempDir, tempdir};

const VERSION: &str = "v1.2.3";
const PACKAGE: &str = "tk-x86_64-unknown-linux-musl-v1.2.3";
const BINARY: &str = r#"#!/bin/sh
printf 'ran' > "$TK_TEST_ROOT/executed"
"#;

fn executable(path: &Path, script: &str) -> Result<()> {
    fs::write(path, script)?;
    fs::set_permissions(path, Permissions::from_mode(0o755))?;
    Ok(())
}

struct Installer(TempDir);

impl Installer {
    fn new() -> Result<Self> {
        let root = tempdir()?;
        let tools = root.path().join("tools");
        let assets = root.path().join("assets");
        let install = root.path().join("install");
        fs::create_dir(&tools)?;
        fs::create_dir(&assets)?;
        fs::create_dir(&install)?;
        fs::write(install.join("tk"), "existing binary")?;
        for tool in [
            "awk", "cp", "gzip", "install", "mkdir", "mktemp", "mv", "rm", "sh", "tar",
        ] {
            let output = Command::new("sh")
                .args(["-c", r#"command -v "$1""#, "sh", tool])
                .output()?;
            assert!(output.status.success(), "{tool}: {output:?}");
            let path = String::from_utf8(output.stdout)?;
            symlink(path.trim(), tools.join(tool))?;
        }
        let output = Command::new("sh")
            .args(["-c", "command -v shasum || command -v sha256sum"])
            .output()?;
        assert!(output.status.success(), "{output:?}");
        let hash = String::from_utf8(output.stdout)?;
        let hash = Path::new(hash.trim());
        symlink(hash, tools.join(hash.file_name().context("checksum tool")?))?;
        executable(
            &tools.join("uname"),
            r#"#!/bin/sh
case "$1" in
    -s) echo Linux ;;
    -m) echo x86_64 ;;
esac
"#,
        )?;
        executable(
            &tools.join("curl"),
            r#"#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            destination=$2
            shift 2
            ;;
        https://*)
            printf '%s\n' "${1##*/}" >> "$TK_TEST_ROOT/downloads"
            cp "$TK_TEST_ROOT/assets/${1##*/}" "$destination"
            shift
            ;;
        *) shift ;;
    esac
done
"#,
        )?;
        executable(
            &tools.join("cosign"),
            r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$TK_TEST_ROOT/verification"
test ! -e "$TK_TEST_ROOT/executed"
exit "$TK_TEST_VERIFY_EXIT"
"#,
        )?;
        let mut archive = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mut header = Header::new_gnu();
        header.set_size(BINARY.len() as u64);
        header.set_mode(0o755);
        archive.append_data(&mut header, format!("{PACKAGE}/tk"), BINARY.as_bytes())?;
        let archive = archive.into_inner()?.finish()?;
        fs::write(assets.join(format!("{PACKAGE}.tar.gz")), &archive)?;
        fs::write(
            assets.join(format!("{PACKAGE}.tar.gz.sha256")),
            format!(
                r#"{}  {PACKAGE}.tar.gz
"#,
                hex::encode(Sha256::digest(archive))
            ),
        )?;
        fs::write(
            assets.join(format!("{PACKAGE}.tar.gz.sigstore.json")),
            "bundle",
        )?;
        Ok(Self(root))
    }

    fn run(&self, verification_exit: &str) -> Result<Output> {
        Ok(Command::new("sh")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
            .env("PATH", self.0.path().join("tools"))
            .env("TK_TEST_ROOT", self.0.path())
            .env("TK_TEST_VERIFY_EXIT", verification_exit)
            .env("TK_INSTALL_DIR", self.0.path().join("install"))
            .env("TK_VERSION", VERSION)
            .output()?)
    }

    fn assert_preserved(&self) -> Result<()> {
        assert_eq!(
            fs::read_to_string(self.0.path().join("install/tk"))?,
            "existing binary"
        );
        assert!(!self.0.path().join("executed").exists());
        assert_eq!(fs::read_dir(self.0.path().join("install"))?.count(), 1);
        Ok(())
    }
}

#[test]
fn installer_verifies_the_exact_workflow_and_tag_before_running_the_binary() -> Result<()> {
    let installer = Installer::new()?;
    let output = installer.run("0")?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(installer.0.path().join("install/tk"))?,
        BINARY
    );
    let arguments = fs::read_to_string(installer.0.path().join("verification"))?;
    let arguments: Vec<_> = arguments.lines().collect();
    let archive = Path::new(arguments[1]);
    let bundle = Path::new(arguments[3]);
    assert_eq!(
        archive.file_name(),
        Some(format!("{PACKAGE}.tar.gz").as_ref())
    );
    assert_eq!(
        bundle.file_name(),
        Some(format!("{PACKAGE}.tar.gz.sigstore.json").as_ref())
    );
    assert_eq!(archive.parent(), bundle.parent());
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
            "https://github.com/tkhq/tk/.github/workflows/release.yml@refs/tags/v1.2.3",
        ]
    );
    assert!(!archive.exists());
    assert!(!bundle.exists());
    assert_eq!(
        fs::read_to_string(installer.0.path().join("executed"))?,
        "ran"
    );
    Ok(())
}

#[test]
fn installer_preserves_the_binary_when_cosign_rejects_provenance() -> Result<()> {
    let installer = Installer::new()?;
    let output = installer.run("17")?;
    assert_eq!(output.status.code(), Some(17), "{output:?}");
    installer.assert_preserved()
}

#[test]
fn installer_preserves_the_binary_when_the_bundle_is_missing() -> Result<()> {
    let installer = Installer::new()?;
    fs::remove_file(
        installer
            .0
            .path()
            .join(format!("assets/{PACKAGE}.tar.gz.sigstore.json")),
    )?;
    let output = installer.run("0")?;
    assert!(!output.status.success(), "{output:?}");
    assert!(!installer.0.path().join("verification").exists());
    installer.assert_preserved()
}

#[test]
fn installer_uses_checksums_without_cosign_or_a_provenance_bundle() -> Result<()> {
    let installer = Installer::new()?;
    fs::remove_file(installer.0.path().join("tools/cosign"))?;
    fs::remove_file(
        installer
            .0
            .path()
            .join(format!("assets/{PACKAGE}.tar.gz.sigstore.json")),
    )?;
    let output = installer.run("0")?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(installer.0.path().join("downloads"))?,
        format!(
            r#"{PACKAGE}.tar.gz
{PACKAGE}.tar.gz.sha256
"#
        )
    );
    assert!(!installer.0.path().join("verification").exists());
    assert_eq!(
        fs::read_to_string(installer.0.path().join("install/tk"))?,
        BINARY
    );
    Ok(())
}

#[test]
fn installer_rejects_a_checksum_mismatch_without_cosign() -> Result<()> {
    let installer = Installer::new()?;
    fs::remove_file(installer.0.path().join("tools/cosign"))?;
    fs::write(
        installer
            .0
            .path()
            .join(format!("assets/{PACKAGE}.tar.gz.sha256")),
        format!(
            r#"{}  {PACKAGE}.tar.gz
"#,
            hex::encode([0; 32])
        ),
    )?;
    let output = installer.run("0")?;
    assert!(!output.status.success(), "{output:?}");
    assert!(!installer.0.path().join("verification").exists());
    installer.assert_preserved()
}
