//! GnuPG interoperability test for the OpenPGP byte layer. It exports a
//! public key, imports it with the real `gpg` binary, and has `gpg` verify a
//! detached signature, so the framing is proven against an outside
//! implementation rather than against this crate's own byte layout. It skips,
//! with a printed reason, when `gpg` is not installed.

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::anyhow;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use tempfile::tempdir;
use tokio::fs;
use tokio::process::Command;
use turnkey_auth::openpgp::entity::{
    EcdsaSignature, OpenPgpKey, SignDigest, SignDigestFuture, UserId, armor_signature,
    detached_signature, export_public_key,
};
use turnkey_auth::openpgp::key::UncompressedPoint;

/// A [`SignDigest`] backed by an in-process `p256::ecdsa::SigningKey`,
/// standing in for a Turnkey wallet account.
struct LocalSigner(SigningKey);

impl SignDigest for LocalSigner {
    fn sign_digest<'a>(
        &'a self,
        _signer: UncompressedPoint,
        digest: [u8; 32],
    ) -> SignDigestFuture<'a> {
        Box::pin(async move {
            let signature: Signature = self
                .0
                .sign_prehash(digest.as_slice())
                .map_err(|error| anyhow!("local test signer failed to sign: {error}"))?;
            let (r, s) = signature.split_bytes();
            Ok(EcdsaSignature {
                r: r.into(),
                s: s.into(),
            })
        })
    }
}

/// Returns the `gpg` binary's path, or `None` when it is not installed.
async fn locate_gpg() -> Option<PathBuf> {
    let output = Command::new("which")
        .arg("gpg")
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    Some(PathBuf::from(path.trim()))
}

/// Returns the fingerprints in a `gpg --with-colons` listing, in order: the
/// `fpr` record's tenth field (RFC-independent, documented in GnuPG's
/// `doc/DETAILS`).
fn fingerprints_in(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .filter_map(|line| line.strip_prefix("fpr:"))
        .filter_map(|fields| fields.split(':').nth(8))
        .collect()
}

#[tokio::test]
async fn exported_key_and_detached_signature_are_accepted_by_gpg() {
    let Some(gpg) = locate_gpg().await else {
        eprintln!("skipping: `gpg` was not found on PATH");
        return;
    };

    let gnupg_home = tempdir().expect("temp GNUPGHOME should be creatable");

    // A fixed, arbitrary nonzero scalar well below the P-256 order; not a
    // secret, just a deterministic in-process test key standing in for a
    // Turnkey wallet account.
    let mut scalar = [0u8; 32];
    for (i, byte) in scalar.iter_mut().enumerate() {
        *byte = (i + 7) as u8;
    }
    let signing_key =
        SigningKey::from_slice(&scalar).expect("fixed scalar should be a valid P-256 key");
    let encoded_point = signing_key.verifying_key().to_encoded_point(false);
    let point_bytes: [u8; 65] = encoded_point
        .as_bytes()
        .try_into()
        .expect("uncompressed point is 65 bytes");
    let point = UncompressedPoint::try_from(point_bytes)
        .expect("a p256 uncompressed point should be accepted");

    let key = OpenPgpKey {
        user_id: UserId::parse("Turnkey GPG Test <gpg-test@example.com>".to_string())
            .expect("test user id should parse"),
        signing_point: point,
        created: 1_700_000_000,
    };
    let signer = LocalSigner(signing_key);
    let now = 1_700_000_100;

    let armored_key = export_public_key(&key, &signer)
        .await
        .expect("public key export should succeed");
    let key_path = gnupg_home.path().join("key.asc");
    fs::write(&key_path, &armored_key)
        .await
        .expect("armored key should be written");

    let import_status = Command::new(&gpg)
        .env("GNUPGHOME", gnupg_home.path())
        .args(["--batch", "--yes", "--import"])
        .arg(&key_path)
        .status()
        .await
        .expect("gpg --import should run");
    assert!(
        import_status.success(),
        "gpg should import the exported key"
    );

    let list_output = Command::new(&gpg)
        .env("GNUPGHOME", gnupg_home.path())
        .args(["--batch", "--list-keys", "--with-colons"])
        .output()
        .await
        .expect("gpg --list-keys should run");
    assert!(
        list_output.status.success(),
        "gpg --list-keys should succeed"
    );
    let listing = String::from_utf8(list_output.stdout).expect("gpg listing should be UTF-8");
    let fingerprints = fingerprints_in(&listing);
    assert_eq!(
        fingerprints.first().copied(),
        Some(key.fingerprint_hex().as_str()),
        "gpg should list the imported primary key first, by its fingerprint"
    );
    assert_eq!(
        fingerprints.len(),
        1,
        "gpg should list the primary key alone, with no subkey"
    );
    assert!(
        !listing.lines().any(|line| line.starts_with("sub:")),
        "the exported key should carry no subkey: {listing}"
    );

    let payload_path = gnupg_home.path().join("payload.txt");
    let payload = b"tk gpg signing proof of concept";
    fs::write(&payload_path, payload)
        .await
        .expect("payload should be written");

    let raw_signature = detached_signature(&key, payload, &signer, now)
        .await
        .expect("detached signature should build");
    let signature_path = gnupg_home.path().join("payload.txt.sig");
    fs::write(&signature_path, armor_signature(&raw_signature))
        .await
        .expect("armored signature should be written");

    let verify_status = Command::new(&gpg)
        .env("GNUPGHOME", gnupg_home.path())
        .arg("--verify")
        .arg(&signature_path)
        .arg(&payload_path)
        .status()
        .await
        .expect("gpg --verify should run");
    assert!(
        verify_status.success(),
        "gpg should verify the detached signature"
    );

    let kill_status = Command::new("gpgconf")
        .env("GNUPGHOME", gnupg_home.path())
        .args(["--kill", "gpg-agent"])
        .status()
        .await
        .expect("gpgconf --kill should run");
    assert!(
        kill_status.success(),
        "gpgconf should be able to stop the test gpg-agent"
    );
}
