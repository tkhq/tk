//! v4 public key packets, fingerprints, and key IDs (RFC 4880 sections
//! 5.5.2 and 12.2).

use sha1::{Digest, Sha1};

use super::OpenPgpError;
use super::packet::mpi;
use super::signature::key_hash_prefix;

/// RFC 4880 9.1 algorithm ID for ECDSA.
const ALGORITHM_ECDSA: u8 = 19;
/// NIST P-256 OID 1.2.840.10045.3.1.7 as OpenPGP encodes it, with no DER tag.
const P256_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub(crate) const POINT_LEN: usize = 65;
const UNCOMPRESSED_PREFIX: u8 = 0x04;

/// An uncompressed SEC1 P-256 point, `04 || X || Y`. Proof of length and
/// prefix only, not that the point lies on the curve.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct UncompressedPoint([u8; POINT_LEN]);

impl UncompressedPoint {
    pub fn as_bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }
}

impl TryFrom<[u8; POINT_LEN]> for UncompressedPoint {
    type Error = OpenPgpError;

    fn try_from(bytes: [u8; POINT_LEN]) -> Result<Self, Self::Error> {
        if bytes[0] != UNCOMPRESSED_PREFIX {
            return Err(OpenPgpError::CompressedPoint);
        }
        Ok(Self(bytes))
    }
}

/// Accepts an optional `0x` prefix.
pub fn parse_point_hex(address: &str) -> Result<UncompressedPoint, OpenPgpError> {
    let bytes = hex::decode(address.trim().trim_start_matches("0x"))?;
    let actual = bytes.len();
    let bytes: [u8; POINT_LEN] = bytes
        .try_into()
        .map_err(|_| OpenPgpError::PointLength { actual })?;
    bytes.try_into()
}

pub(crate) struct PublicKeyPacket {
    /// The packet body without its header.
    pub(crate) body: Vec<u8>,
    pub(crate) fingerprint: [u8; 20],
}

/// A v4 primary key packet, algorithm 19 over NIST P-256 (RFC 4880 5.5.2).
pub(crate) fn primary_key_packet(point: UncompressedPoint, created: u32) -> PublicKeyPacket {
    let mut body = vec![0x04];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(ALGORITHM_ECDSA);
    body.push(P256_OID.len() as u8);
    body.extend_from_slice(&P256_OID);
    body.extend_from_slice(&mpi(point.as_bytes()));
    // RFC 4880 12.2: the fingerprint is SHA-1 over the same prefixed body a
    // self signature hashes.
    let fingerprint = Sha1::digest(key_hash_prefix(&body)).into();
    PublicKeyPacket { body, fingerprint }
}

pub(crate) fn key_id(fingerprint: &[u8; 20]) -> [u8; 8] {
    fingerprint[12..20]
        .try_into()
        .expect("a 20 byte slice sliced to 8 bytes is 8 bytes")
}

pub fn fingerprint_hex(fingerprint: &[u8; 20]) -> String {
    hex::encode_upper(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator_point() -> UncompressedPoint {
        parse_point_hex(concat!(
            "04",
            "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
            "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        ))
        .expect("generator point should parse")
    }

    #[test]
    fn primary_key_packet_fingerprint_matches_an_independent_computation() {
        // Computed once, independently of this crate, by hand building the
        // v4 public key body (04 || u32 created || 19 || 08 ||
        // 2A8648CE3D030107 || mpi(point)) in Python and hashing it with
        // hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body), then
        // cross checked with `gpg --list-packets` against the same raw
        // packet bytes, which reported the matching key ID
        // 2D007ACDCD30CCA6.
        let packet = primary_key_packet(generator_point(), 1_700_000_000);
        assert_eq!(
            fingerprint_hex(&packet.fingerprint),
            "13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6"
        );
        assert_eq!(
            hex::encode_upper(key_id(&packet.fingerprint)),
            "2D007ACDCD30CCA6"
        );
    }

    #[test]
    fn parse_point_hex_rejects_bad_input_and_strips_a_0x_prefix() {
        let error = parse_point_hex("0400").expect_err("short input should be rejected");
        assert!(matches!(error, OpenPgpError::PointLength { actual: 2 }));
        // The right length with a compressed point prefix (0x02) instead of 0x04.
        let compressed = format!("02{}", "11".repeat(64));
        let error = parse_point_hex(&compressed).expect_err("compressed point should be rejected");
        assert!(matches!(error, OpenPgpError::CompressedPoint));
        let error = parse_point_hex("zz").expect_err("non hex input should be rejected");
        assert!(matches!(error, OpenPgpError::NotHex(_)));
        let with_prefix = format!("0x{}", hex::encode(generator_point().as_bytes()));
        assert_eq!(
            parse_point_hex(&with_prefix).expect("prefixed input should parse"),
            generator_point()
        );
    }
}
