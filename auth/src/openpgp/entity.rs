//! Public key export (RFC 4880 11.1) and detached signatures (11.4).

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, Result};

use super::OpenPgpError;
use super::armor::{BlockType, armor};
use super::key::{UncompressedPoint, fingerprint_hex, key_id, primary_key_packet};
use super::packet::{new_format_packet, subpacket};
use super::signature::{
    SignedObject, creation_time_subpacket, digest, hashed_portion, issuer_fingerprint_subpacket,
    issuer_key_id_subpacket, key_hash_prefix, signature_packet,
};

/// RFC 4880 5.2.3.21 key flags: certify | sign.
const SIGNING_KEY_FLAGS: u8 = 0x03;
/// RFC 4880 9.2, 9.4, 9.3 preferences: AES-128, SHA-256, uncompressed. The
/// values are fixed: they are hashed into the self signature of every key
/// already exported, so changing one would change their exported blocks.
const PREFERRED_SYMMETRIC_AES128: u8 = 0x07;
const PREFERRED_HASH_SHA256: u8 = 0x08;
const PREFERRED_COMPRESSION_NONE: u8 = 0x00;

/// RFC 4880 5.2.3 subpacket types.
const SUBPACKET_KEY_FLAGS: u8 = 27;
const SUBPACKET_PREFERRED_SYMMETRIC: u8 = 11;
const SUBPACKET_PREFERRED_HASH: u8 = 21;
const SUBPACKET_PREFERRED_COMPRESSION: u8 = 22;

/// RFC 4880 4.3 packet tags.
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_USER_ID: u8 = 13;

/// The raw big endian scalars of a P-256 ECDSA signature.
#[derive(Clone, Copy)]
pub struct EcdsaSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

pub type SignDigestFuture<'a> = Pin<Box<dyn Future<Output = Result<EcdsaSignature>> + Send + 'a>>;

pub trait SignDigest {
    fn sign_digest<'a>(
        &'a self,
        signer: UncompressedPoint,
        digest: [u8; 32],
    ) -> SignDigestFuture<'a>;
}

/// Non-empty User ID packet contents, for example `Name <email>`.
#[derive(Clone, Debug)]
pub struct UserId(String);

impl UserId {
    /// Rejects an empty value, which GnuPG refuses, and a NUL, CR, or LF,
    /// which would corrupt the packet or a line based listing.
    pub fn parse(value: String) -> Result<Self, OpenPgpError> {
        if value.is_empty() {
            return Err(OpenPgpError::EmptyUserId);
        }
        if value.contains(['\0', '\r', '\n']) {
            return Err(OpenPgpError::UserIdControlByte);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// The fingerprint and key ID are functions of these two fields.
#[derive(Clone, Copy)]
pub struct SigningKey {
    pub point: UncompressedPoint,
    /// The signing account's creation time in Unix seconds, never the clock.
    pub created: u32,
}

impl SigningKey {
    pub fn fingerprint(&self) -> [u8; 20] {
        primary_key_packet(self.point, self.created).fingerprint
    }

    /// 40 upper case hex characters, the form GnuPG prints and accepts.
    pub fn fingerprint_hex(&self) -> String {
        fingerprint_hex(&self.fingerprint())
    }
}

/// A Turnkey backed OpenPGP identity: one P-256 signing key and its user
/// ID. The key certifies and signs. It does not decrypt, so it carries no
/// subkey.
#[derive(Clone)]
pub struct OpenPgpKey {
    pub user_id: UserId,
    pub signing: SigningKey,
}

async fn build_signature(
    object: SignedObject,
    hashed_subpackets: Vec<u8>,
    unhashed_subpackets: Vec<u8>,
    data_to_hash: &[u8],
    signing_point: UncompressedPoint,
    signer: &dyn SignDigest,
) -> Result<Vec<u8>> {
    let hashed = hashed_portion(object, &hashed_subpackets);
    let digest_bytes = digest(data_to_hash, &hashed);
    let signature = signer
        .sign_digest(signing_point, digest_bytes)
        .await
        .with_context(|| format!("failed to sign the {object} digest"))?;

    Ok(signature_packet(
        hashed,
        &unhashed_subpackets,
        &digest_bytes,
        &signature.r,
        &signature.s,
    ))
}

/// An armored public key block: primary key, User ID, and a self signature
/// over the User ID made with the key itself. The clock is never read, so
/// exporting the same key twice yields the same bytes.
pub async fn export_public_key(key: &OpenPgpKey, signer: &dyn SignDigest) -> Result<String> {
    let primary = primary_key_packet(key.signing.point, key.signing.created);
    let issuer_key_id = key_id(&primary.fingerprint);
    let user_id_bytes = key.user_id.as_bytes();

    let self_hashed = {
        let mut hashed = creation_time_subpacket(key.signing.created);
        for (kind, value) in [
            (SUBPACKET_KEY_FLAGS, SIGNING_KEY_FLAGS),
            (SUBPACKET_PREFERRED_SYMMETRIC, PREFERRED_SYMMETRIC_AES128),
            (SUBPACKET_PREFERRED_HASH, PREFERRED_HASH_SHA256),
            (SUBPACKET_PREFERRED_COMPRESSION, PREFERRED_COMPRESSION_NONE),
        ] {
            hashed.extend_from_slice(&subpacket(kind, false, &[value]));
        }
        hashed.extend_from_slice(&issuer_fingerprint_subpacket(&primary.fingerprint));
        hashed
    };

    // A self signature covers the primary key packet and the User ID packet,
    // each under its own RFC 4880 5.2.4 hash prefix: 0x99 and a u16 length
    // for the key, 0xB4 and a u32 length for the User ID.
    let self_signed_data = {
        let mut data = key_hash_prefix(&primary.body);
        data.push(0xb4);
        data.extend_from_slice(&(user_id_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(user_id_bytes);
        data
    };
    let self_signature = build_signature(
        SignedObject::UserId,
        self_hashed,
        issuer_key_id_subpacket(&issuer_key_id),
        &self_signed_data,
        key.signing.point,
        signer,
    )
    .await?;

    let mut data = new_format_packet(TAG_PUBLIC_KEY, &primary.body);
    data.extend_from_slice(&new_format_packet(TAG_USER_ID, user_id_bytes));
    data.extend_from_slice(&self_signature);

    Ok(armor(BlockType::PublicKeyBlock, &data))
}

/// A binary document signature over `data`, as raw tag 2 packet bytes.
pub async fn detached_signature(
    key: SigningKey,
    data: &[u8],
    signer: &dyn SignDigest,
    now: u32,
) -> Result<Vec<u8>> {
    let fingerprint = key.fingerprint();
    let mut hashed = creation_time_subpacket(now);
    hashed.extend_from_slice(&issuer_fingerprint_subpacket(&fingerprint));
    build_signature(
        SignedObject::Document,
        hashed,
        issuer_key_id_subpacket(&key_id(&fingerprint)),
        data,
        key.point,
        signer,
    )
    .await
}

pub fn armor_signature(packet: &[u8]) -> String {
    armor(BlockType::Signature, packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_parse_rejects_a_nul_or_a_newline() {
        for value in ["Ada\u{0}", "Ada\r\nFrom: forged", "Ada\n<ada@example.com>"] {
            let error =
                UserId::parse(value.to_string()).expect_err("a control byte should be rejected");
            assert!(
                matches!(error, OpenPgpError::UserIdControlByte),
                "{value:?} should be rejected as a control byte"
            );
        }
    }
}
