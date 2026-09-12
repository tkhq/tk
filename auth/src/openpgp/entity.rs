//! Exporting a Turnkey backed identity as an OpenPGP entity: a public key
//! export (RFC 4880 section 11.1) and detached signatures (section 11.4).

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, Result};

use super::OpenPgpError;
use super::armor::{BlockType, armor};
use super::key::{UncompressedPoint, fingerprint_hex, key_id, primary_key_packet};
use super::packet::{new_format_packet, subpacket};
use super::signature::{
    SignatureRequest, SignedObject, creation_time_subpacket, digest, hashed_portion,
    issuer_fingerprint_subpacket, issuer_key_id_subpacket, key_hash_prefix, signature_packet,
};

/// Key flags (RFC 4880 5.2.3.21) for the primary signing key: certify data
/// (0x01) and sign data (0x02).
const SIGNING_KEY_FLAGS: u8 = 0x03;
/// Preferred symmetric algorithm (RFC 4880 9.2): AES-128. The value is
/// fixed: it is hashed into the self signature of every key already
/// exported, so changing it would change their exported blocks.
const PREFERRED_SYMMETRIC_AES128: u8 = 0x07;
/// Preferred hash algorithm (RFC 4880 9.4): SHA-256.
const PREFERRED_HASH_SHA256: u8 = 0x08;
/// Preferred compression algorithm (RFC 4880 9.3): uncompressed.
const PREFERRED_COMPRESSION_NONE: u8 = 0x00;

/// Signature subpacket type: key flags (RFC 4880 5.2.3.21).
const SUBPACKET_KEY_FLAGS: u8 = 27;
/// Signature subpacket type: preferred symmetric algorithms (RFC 4880
/// 5.2.3.7).
const SUBPACKET_PREFERRED_SYMMETRIC: u8 = 11;
/// Signature subpacket type: preferred hash algorithms (RFC 4880 5.2.3.8).
const SUBPACKET_PREFERRED_HASH: u8 = 21;
/// Signature subpacket type: preferred compression algorithms (RFC 4880
/// 5.2.3.9).
const SUBPACKET_PREFERRED_COMPRESSION: u8 = 22;

/// New format packet tag for a primary public key (RFC 4880 4.3).
const TAG_PUBLIC_KEY: u8 = 6;
/// New format packet tag for a User ID (RFC 4880 4.3).
const TAG_USER_ID: u8 = 13;

/// The raw big endian scalars of a P-256 ECDSA signature. Holding one is
/// proof of the width the MPI encoder needs: each scalar is exactly 32
/// bytes, so no length check runs again deeper in the framing.
#[derive(Clone, Copy)]
pub struct EcdsaSignature {
    /// The big endian `r` scalar.
    pub r: [u8; 32],
    /// The big endian `s` scalar.
    pub s: [u8; 32],
}

/// The future a [`SignDigest`] implementation returns: the ECDSA signature
/// over a signed digest.
pub type SignDigestFuture<'a> = Pin<Box<dyn Future<Output = Result<EcdsaSignature>> + Send + 'a>>;

/// Signs a 32 byte digest with the private key behind a wallet account. A
/// boxed future stands in for `#[async_trait::async_trait]`, which is not
/// available to this crate.
pub trait SignDigest {
    /// Signs `digest` with the private key whose public point is `signer`.
    fn sign_digest<'a>(
        &'a self,
        signer: UncompressedPoint,
        digest: [u8; 32],
    ) -> SignDigestFuture<'a>;
}

/// The contents of an OpenPGP User ID packet, for example `Name <email>`.
/// Holding one is proof that the identity names something: OpenPGP has no
/// meaning for an empty User ID, and GnuPG rejects a key that carries one.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct UserId(String);

impl UserId {
    /// Parses User ID packet contents. An empty string is rejected because
    /// OpenPGP has no meaning for it. A NUL, a carriage return, or a line
    /// feed is rejected because it would corrupt the packet and any line
    /// based listing that prints the identity.
    pub fn parse(value: String) -> Result<Self, OpenPgpError> {
        if value.is_empty() {
            return Err(OpenPgpError::EmptyUserId);
        }
        if value.contains(['\0', '\r', '\n']) {
            return Err(OpenPgpError::UserIdControlByte);
        }
        Ok(Self(value))
    }

    /// Returns the User ID packet contents as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the UTF-8 bytes the User ID packet carries.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Consumes the User ID and returns the text it carries, for callers
    /// that need the owned string and are done with the proof.
    pub fn into_string(self) -> String {
        self.0
    }
}

/// A Turnkey backed OpenPGP identity: one P-256 signing key. The key
/// certifies and signs. It does not decrypt, so it carries no subkey.
pub struct OpenPgpKey {
    /// The identity this key names.
    pub user_id: UserId,
    /// The signing account's public key. It is the one authority for which
    /// key signs: callers that need the wallet account address hex encode
    /// it rather than carrying a second copy.
    pub signing_point: UncompressedPoint,
    /// The primary key packet's creation time (seconds since the Unix
    /// epoch). Never the current time: it is the signing account's own
    /// creation time, an input the caller supplies. Changing it changes the
    /// fingerprint and the key ID.
    pub created: u32,
}

impl OpenPgpKey {
    /// Returns the primary signing key's v4 fingerprint.
    pub(crate) fn fingerprint(&self) -> [u8; 20] {
        primary_key_packet(self.signing_point, self.created).fingerprint
    }

    /// Returns the primary signing key's fingerprint as 40 upper case hex
    /// characters, the form GnuPG prints and accepts.
    pub fn fingerprint_hex(&self) -> String {
        fingerprint_hex(&self.fingerprint())
    }
}

/// Hashes `data_to_hash` under `request`, signs the digest through `signer`,
/// and frames the result as a full tag 2 signature packet.
async fn build_signature(
    request: SignatureRequest,
    data_to_hash: &[u8],
    signing_point: UncompressedPoint,
    signer: &dyn SignDigest,
) -> Result<Vec<u8>> {
    let SignatureRequest {
        object,
        hashed_subpackets,
        unhashed_subpackets,
    } = request;

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

/// Exports `key` as an armored OpenPGP public key block: the primary key,
/// a User ID, and a self signature over the User ID, in that order.
///
/// The key packet carries the signing account's creation time, and the self
/// signature carries it too. The clock is never read here: it would make
/// every export of the same key a different block, and callers depend on a
/// stable one.
///
/// The self signature is made with the key itself, so this export signs.
pub async fn export_public_key(key: &OpenPgpKey, signer: &dyn SignDigest) -> Result<String> {
    let primary = primary_key_packet(key.signing_point, key.created);
    let issuer_key_id = key_id(&primary.fingerprint);
    let user_id_bytes = key.user_id.as_bytes();

    let self_request = {
        let mut hashed = creation_time_subpacket(key.created);
        hashed.extend_from_slice(&subpacket(SUBPACKET_KEY_FLAGS, false, &[SIGNING_KEY_FLAGS]));
        hashed.extend_from_slice(&subpacket(
            SUBPACKET_PREFERRED_SYMMETRIC,
            false,
            &[PREFERRED_SYMMETRIC_AES128],
        ));
        hashed.extend_from_slice(&subpacket(
            SUBPACKET_PREFERRED_HASH,
            false,
            &[PREFERRED_HASH_SHA256],
        ));
        hashed.extend_from_slice(&subpacket(
            SUBPACKET_PREFERRED_COMPRESSION,
            false,
            &[PREFERRED_COMPRESSION_NONE],
        ));
        hashed.extend_from_slice(&issuer_fingerprint_subpacket(&primary.fingerprint));
        SignatureRequest {
            object: SignedObject::UserId,
            hashed_subpackets: hashed,
            unhashed_subpackets: issuer_key_id_subpacket(&issuer_key_id),
        }
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
    let self_signature =
        build_signature(self_request, &self_signed_data, key.signing_point, signer).await?;

    let mut data = new_format_packet(TAG_PUBLIC_KEY, &primary.body);
    data.extend_from_slice(&new_format_packet(TAG_USER_ID, user_id_bytes));
    data.extend_from_slice(&self_signature);

    Ok(armor(BlockType::PublicKeyBlock, &data))
}

/// Produces a detached signature over `data` (RFC 4880 5.2.1, a binary
/// document signature), as raw tag 2 signature packet bytes. `now` timestamps
/// the signature.
pub async fn detached_signature(
    key: &OpenPgpKey,
    data: &[u8],
    signer: &dyn SignDigest,
    now: u32,
) -> Result<Vec<u8>> {
    let fingerprint = key.fingerprint();
    let request = {
        let mut hashed = creation_time_subpacket(now);
        hashed.extend_from_slice(&issuer_fingerprint_subpacket(&fingerprint));
        SignatureRequest {
            object: SignedObject::Document,
            hashed_subpackets: hashed,
            unhashed_subpackets: issuer_key_id_subpacket(&key_id(&fingerprint)),
        }
    };

    build_signature(request, data, key.signing_point, signer).await
}

/// Wraps a raw signature packet in ASCII armor as a `PGP SIGNATURE` block,
/// the form a `.asc` signature file carries.
pub fn armor_signature(packet: &[u8]) -> String {
    armor(BlockType::Signature, packet)
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;
    use crate::openpgp::key::parse_point_hex;

    /// The NIST P-256 generator point G, uncompressed: `04 || Gx || Gy`.
    fn generator_point() -> UncompressedPoint {
        parse_point_hex(concat!(
            "04",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        ))
        .expect("generator point should parse")
    }

    fn test_key() -> OpenPgpKey {
        OpenPgpKey {
            user_id: UserId::parse("Test User <test@example.com>".to_string())
                .expect("test user id should parse"),
            signing_point: generator_point(),
            created: 1_700_000_000,
        }
    }

    /// A signer that returns fixed (r, s) scalars, for tests that only
    /// check byte layout rather than cryptographic validity.
    struct FixedSigner;

    impl SignDigest for FixedSigner {
        fn sign_digest<'a>(
            &'a self,
            _signer: UncompressedPoint,
            _digest: [u8; 32],
        ) -> SignDigestFuture<'a> {
            Box::pin(async {
                Ok(EcdsaSignature {
                    r: [0x01; 32],
                    s: [0x02; 32],
                })
            })
        }
    }

    /// Reads one RFC 4880 length (4.2.2 for packets, 5.2.3.1 for
    /// subpackets), returning the length and how many octets encoded it.
    /// Test-only: it does not handle partial body lengths, which none of
    /// this module's output uses.
    fn read_length(data: &[u8]) -> (usize, usize) {
        match data[0] {
            first if first < 192 => (first as usize, 1),
            first if first < 255 => (((first as usize - 192) << 8) + data[1] as usize + 192, 2),
            _ => (
                u32::from_be_bytes(data[1..5].try_into().expect("4 length octets")) as usize,
                5,
            ),
        }
    }

    /// Reads every new format packet in `data` (RFC 4880 4.2.2), returning
    /// each packet's tag and body.
    fn read_new_format_packets(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut packets = Vec::new();
        while !data.is_empty() {
            let tag = data[0] & 0x3f;
            data = &data[1..];
            let (len, consumed) = read_length(data);
            data = &data[consumed..];
            packets.push((tag, data[..len].to_vec()));
            data = &data[len..];
        }
        packets
    }

    /// Reads every signature subpacket in `data` (RFC 4880 5.2.3.1),
    /// returning each subpacket's type (critical bit stripped) and body.
    fn read_subpackets(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while !data.is_empty() {
            let (len, consumed) = read_length(data);
            data = &data[consumed..];
            out.push((data[0] & 0x7f, data[1..len].to_vec()));
            data = &data[len..];
        }
        out
    }

    /// Returns the hashed subpackets of a tag 2 signature packet body.
    fn hashed_subpackets_of(signature_body: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let hashed_len = u16::from_be_bytes([signature_body[4], signature_body[5]]) as usize;
        read_subpackets(&signature_body[6..6 + hashed_len])
    }

    fn dearmor_body(armored: &str) -> Vec<u8> {
        let mut lines = armored.lines();
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
        }
        let mut b64 = String::new();
        for line in lines.by_ref() {
            if line.starts_with('=') || line.starts_with("-----END") {
                break;
            }
            b64.push_str(line);
        }
        STANDARD.decode(b64).expect("test armor body should decode")
    }

    #[test]
    fn user_id_parse_rejects_an_empty_string() {
        let error = UserId::parse(String::new()).expect_err("empty user id should be rejected");
        assert!(matches!(error, OpenPgpError::EmptyUserId));
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

    #[test]
    fn user_id_carries_its_utf8_bytes() {
        let user_id = UserId::parse("Ada <ada@example.com>".to_string())
            .expect("a non-empty user id should parse");
        assert_eq!(user_id.as_bytes(), b"Ada <ada@example.com>");
    }

    #[tokio::test]
    async fn export_public_key_orders_packets_and_self_signature_subpackets() {
        let key = test_key();
        let armored = export_public_key(&key, &FixedSigner)
            .await
            .expect("export should succeed");

        let data = dearmor_body(&armored);
        let packets = read_new_format_packets(&data);
        let tags: Vec<u8> = packets.iter().map(|(tag, _)| *tag).collect();
        assert_eq!(tags, vec![TAG_PUBLIC_KEY, TAG_USER_ID, 2]);
        assert_eq!(packets[1].1, key.user_id.as_bytes());

        // The self signature is the third and last packet.
        let self_signature = &packets[2].1;
        assert_eq!(self_signature[1], SignedObject::UserId.type_octet());
        let self_subpackets = hashed_subpackets_of(self_signature);
        let self_types: Vec<u8> = self_subpackets.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(
            self_types,
            vec![
                2, // creation time
                SUBPACKET_KEY_FLAGS,
                SUBPACKET_PREFERRED_SYMMETRIC,
                SUBPACKET_PREFERRED_HASH,
                SUBPACKET_PREFERRED_COMPRESSION,
                33, // issuer fingerprint
            ]
        );
        assert_eq!(self_subpackets[0].1, key.created.to_be_bytes());
        assert_eq!(self_subpackets[1].1, vec![SIGNING_KEY_FLAGS]);
        assert_eq!(self_subpackets[5].1[1..], key.fingerprint());
    }

    #[tokio::test]
    async fn detached_signature_verifies_with_p256() {
        use anyhow::anyhow;
        use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
        use p256::ecdsa::{Signature, SigningKey};

        // A fixed, arbitrary nonzero scalar well below the P-256 order; not
        // a secret, just a deterministic in-process test key.
        let mut scalar = [0u8; 32];
        for (i, byte) in scalar.iter_mut().enumerate() {
            *byte = (i + 1) as u8;
        }
        let signing_key =
            SigningKey::from_slice(&scalar).expect("fixed scalar should be a valid P-256 key");
        let verifying_key = *signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let point_bytes: [u8; 65] = encoded_point
            .as_bytes()
            .try_into()
            .expect("uncompressed point is 65 bytes");

        struct P256Signer(SigningKey);
        impl SignDigest for P256Signer {
            fn sign_digest<'a>(
                &'a self,
                _signer: UncompressedPoint,
                digest: [u8; 32],
            ) -> SignDigestFuture<'a> {
                Box::pin(async move {
                    let signature: Signature = self
                        .0
                        .sign_prehash(digest.as_slice())
                        .map_err(|error| anyhow!("test signer failed to sign: {error}"))?;
                    let (r, s) = signature.split_bytes();
                    Ok(EcdsaSignature {
                        r: r.into(),
                        s: s.into(),
                    })
                })
            }
        }

        let mut key = test_key();
        key.signing_point = point_bytes
            .try_into()
            .expect("a p256 uncompressed point should parse");
        let signer = P256Signer(signing_key);
        let now = 1_700_000_200;
        let data = b"hello openpgp";

        let sig_packet = detached_signature(&key, data, &signer, now)
            .await
            .expect("detached signature should build");

        // Recompute the digest the same way detached_signature does, using
        // this module's own (separately tested) subpacket and digest
        // helpers, so the recomputation is independent of the signer.
        let fingerprint = key.fingerprint();
        let mut hashed_subpackets = creation_time_subpacket(now);
        hashed_subpackets.extend_from_slice(&issuer_fingerprint_subpacket(&fingerprint));
        let hashed = hashed_portion(SignedObject::Document, &hashed_subpackets);
        let digest_bytes = digest(data, &hashed);

        // Parse the produced packet back to raw r, s scalars by walking the
        // tag 2 body layout: hashed || u16 len(unhashed) || unhashed ||
        // digest[0..2] || mpi(r) || mpi(s).
        let packets = read_new_format_packets(&sig_packet);
        assert_eq!(packets.len(), 1);
        let (tag, body) = &packets[0];
        assert_eq!(*tag, 2);

        let mut offset = hashed.len();
        let unhashed_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2 + unhashed_len;
        offset += 2; // digest prefix
        let (r, next) = read_mpi(body, offset);
        let (s, _) = read_mpi(body, next);

        let signature = Signature::from_scalars(pad32(&r), pad32(&s))
            .expect("scalars should form a valid ECDSA signature");

        verifying_key
            .verify_prehash(&digest_bytes, &signature)
            .expect("signature should verify against the recomputed digest");
    }

    fn read_mpi(data: &[u8], offset: usize) -> (Vec<u8>, usize) {
        let bits = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        let byte_len = bits.div_ceil(8);
        let start = offset + 2;
        (data[start..start + byte_len].to_vec(), start + byte_len)
    }

    fn pad32(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        out
    }
}
