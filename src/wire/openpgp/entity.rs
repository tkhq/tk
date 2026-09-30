//! Public key export (RFC 4880 11.1) and detached signatures (11.4).

use std::pin::Pin;

use anyhow::{Context, Result};

pub use super::armor::ArmoredSignature;
use super::{
    OpenPgpError,
    armor::{BlockType, armor},
    key::{Fingerprint, UncompressedPoint, primary_key_packet},
    packet::{new_format_packet, subpacket},
    signature::{
        P256Scalar, SignedObject, creation_time_subpacket, digest, hashed_portion,
        issuer_fingerprint_subpacket, issuer_key_id_subpacket, key_hash_prefix, signature_packet,
    },
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
pub struct EcdsaSignature {
    /// The `r` scalar.
    pub r: [u8; 32],
    /// The `s` scalar.
    pub s: [u8; 32],
}

/// The future returned by [`SignDigest::sign_digest`].
pub type SignDigestFuture<'a> = Pin<Box<dyn Future<Output = Result<EcdsaSignature>> + Send + 'a>>;

/// Signs a SHA-256 digest with the private key held by Turnkey.
pub trait SignDigest {
    /// Signs `digest` with the key identified by `signer`.
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
    /// Rejects an empty value, which `GnuPG` refuses, and a NUL, CR, or LF,
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

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The user ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the user ID and returns its string.
    pub fn into_string(self) -> String {
        self.0
    }
}

/// The fingerprint and key ID are functions of these two fields.
#[derive(Clone, Copy)]
pub struct SigningKey {
    /// The signing account's public key point.
    pub point: UncompressedPoint,
    /// The signing account's creation time in Unix seconds, never the clock.
    pub created: u32,
}

impl SigningKey {
    /// The fingerprint of the primary key packet these fields produce.
    pub fn fingerprint(&self) -> Fingerprint {
        primary_key_packet(self.point, self.created).fingerprint
    }
}

/// A Turnkey backed `OpenPGP` identity: one P-256 key that certifies and signs, plus its user ID.
pub struct OpenPgpKey {
    /// The identity's user ID.
    pub user_id: UserId,
    /// The identity's signing key.
    pub signing: SigningKey,
}

async fn build_signature<S: SignDigest + ?Sized>(
    object: SignedObject,
    hashed_subpackets: Vec<u8>,
    key: SigningKey,
    data_to_hash: &[u8],
    signer: &S,
) -> Result<Vec<u8>> {
    let issuer = key.fingerprint();
    let hashed = hashed_portion(object, &hashed_subpackets);
    let digest_bytes = digest(data_to_hash, &hashed);
    let EcdsaSignature { r, s } = signer
        .sign_digest(key.point, digest_bytes)
        .await
        .with_context(|| format!("failed to sign the {object} digest"))?;
    let (r, s) = P256Scalar::parse(r)
        .zip(P256Scalar::parse(s))
        .ok_or(OpenPgpError::SignatureScalarOutOfRange)
        .context("encode the OpenPGP signature packet")?;

    Ok(signature_packet(
        hashed,
        &issuer_key_id_subpacket(issuer),
        &digest_bytes,
        r.as_bytes(),
        s.as_bytes(),
    ))
}

/// A byte-for-byte reproducible armored public key block: primary key, User ID, and self signature.
pub async fn export_public_key<S: SignDigest + ?Sized>(
    key: &OpenPgpKey,
    signer: &S,
) -> Result<String> {
    let primary = primary_key_packet(key.signing.point, key.signing.created);
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
        hashed.extend_from_slice(&issuer_fingerprint_subpacket(primary.fingerprint));
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
        key.signing,
        &self_signed_data,
        signer,
    )
    .await?;

    let mut data = new_format_packet(TAG_PUBLIC_KEY, &primary.body);
    data.extend_from_slice(&new_format_packet(TAG_USER_ID, user_id_bytes));
    data.extend_from_slice(&self_signature);

    Ok(armor(BlockType::PublicKeyBlock, &data))
}

/// An ASCII armored document signature with validated hashed metadata.
pub async fn armored_detached_signature<S: SignDigest + ?Sized>(
    key: SigningKey,
    data: &[u8],
    signer: &S,
    now: u32,
) -> Result<ArmoredSignature> {
    let mut hashed = creation_time_subpacket(now);
    hashed.extend_from_slice(&issuer_fingerprint_subpacket(key.fingerprint()));
    let packet = build_signature(SignedObject::Document, hashed, key, data, signer).await?;
    Ok(ArmoredSignature::from_parts(
        &packet,
        now,
        key.fingerprint(),
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct CellSigner {
        next_scalar: Cell<u8>,
    }

    impl SignDigest for CellSigner {
        fn sign_digest<'a>(
            &'a self,
            _signer: UncompressedPoint,
            _digest: [u8; 32],
        ) -> SignDigestFuture<'a> {
            let scalar = self.next_scalar.get();
            self.next_scalar.set(scalar.wrapping_add(1));
            let signature = EcdsaSignature {
                r: [scalar; 32],
                s: [scalar; 32],
            };
            Box::pin(async move { Ok(signature) })
        }
    }

    #[tokio::test]
    async fn armored_detached_signature_retains_metadata_and_accepts_a_non_sync_signer() {
        let cell_signer = CellSigner {
            next_scalar: Cell::new(1),
        };
        let signer: &dyn SignDigest = &cell_signer;
        let key = SigningKey {
            point: [4; 65]
                .try_into()
                .expect("an uncompressed point should parse"),
            created: 1_700_000_000,
        };

        let signature = armored_detached_signature(key, b"document", signer, 1_700_000_001)
            .await
            .expect("the owned signature future should complete");

        assert_eq!(signature.created(), 1_700_000_001);
        assert_eq!(signature.fingerprint(), &key.fingerprint());
        assert_eq!(cell_signer.next_scalar.get(), 2);
    }

    #[tokio::test]
    async fn export_public_key_rejects_a_self_signature_scalar_at_or_above_the_curve_order() {
        let cell_signer = CellSigner {
            next_scalar: Cell::new(0xff),
        };
        let key = OpenPgpKey {
            user_id: UserId::parse("Ada <ada@example.com>".to_owned()).unwrap(),
            signing: SigningKey {
                point: [4; 65]
                    .try_into()
                    .expect("an uncompressed point should parse"),
                created: 1_700_000_000,
            },
        };

        let error = export_public_key(&key, &cell_signer)
            .await
            .expect_err("an out of range scalar should be rejected");

        assert!(matches!(
            error.downcast_ref::<OpenPgpError>(),
            Some(OpenPgpError::SignatureScalarOutOfRange)
        ));
    }

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
