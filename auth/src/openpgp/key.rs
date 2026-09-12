//! v4 OpenPGP public key packets: bodies, fingerprints, and key IDs (RFC
//! 4880 sections 5.5.2 and 12.2).

use sha1::{Digest, Sha1};

use super::OpenPgpError;
use super::packet::mpi;

/// ECDSA algorithm ID (RFC 4880 9.1), used for the primary signing key.
const ALGORITHM_ECDSA: u8 = 19;
/// NIST P-256 (ANSI X9.62 prime256v1) OID, 1.2.840.10045.3.1.7, as OpenPGP
/// encodes it: a length byte followed by the arc bytes, with no DER tag.
const P256_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// Length, in bytes, of an uncompressed SEC1 P-256 point: a `0x04` prefix
/// plus two 32 byte coordinates.
pub(crate) const POINT_LEN: usize = 65;
/// The SEC1 prefix byte that marks an uncompressed point.
const UNCOMPRESSED_PREFIX: u8 = 0x04;

/// An uncompressed SEC1 P-256 public key point, `04 || X || Y`. Holding one is
/// proof of the two properties the key packet framing depends on: 65 bytes
/// long, carrying the uncompressed prefix. It is not proof that the point lies
/// on the curve.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct UncompressedPoint([u8; POINT_LEN]);

impl UncompressedPoint {
    /// Returns the SEC1 encoding, `04 || X || Y`.
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

/// Parses an [`UncompressedPoint`] from 130 hex characters. An optional
/// leading `0x` is stripped first, matching Turnkey's public key hex
/// convention.
pub fn parse_point_hex(address: &str) -> Result<UncompressedPoint, OpenPgpError> {
    let bytes = hex::decode(address.trim().trim_start_matches("0x"))?;
    let actual = bytes.len();
    let bytes: [u8; POINT_LEN] = bytes
        .try_into()
        .map_err(|_| OpenPgpError::PointLength { actual })?;
    bytes.try_into()
}

/// A v4 OpenPGP public key packet body plus its fingerprint.
pub(crate) struct PublicKeyPacket {
    /// The packet body: version, creation time, algorithm, OID, and point
    /// MPI. It carries no packet header; framing it as a packet is the
    /// caller's step.
    pub(crate) body: Vec<u8>,
    /// The SHA-1 fingerprint of this packet (RFC 4880 12.2).
    pub(crate) fingerprint: [u8; 20],
}

/// Computes the RFC 4880 12.2 v4 fingerprint of a public key packet body:
/// `SHA1(0x99 || u16 len(body) || body)`.
fn fingerprint_of(body: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update((body.len() as u16).to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

/// Builds a v4 primary key packet (algorithm 19, ECDSA over NIST P-256) from
/// a public key point and the packet's creation time (RFC 4880 5.5.2).
pub(crate) fn primary_key_packet(point: UncompressedPoint, created: u32) -> PublicKeyPacket {
    let mut body = vec![0x04];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(ALGORITHM_ECDSA);
    body.push(P256_OID.len() as u8);
    body.extend_from_slice(&P256_OID);
    body.extend_from_slice(&mpi(point.as_bytes()));
    let fingerprint = fingerprint_of(&body);
    PublicKeyPacket { body, fingerprint }
}

/// Returns the key ID (RFC 4880 12.2): the last 8 bytes of the fingerprint.
pub(crate) fn key_id(fingerprint: &[u8; 20]) -> [u8; 8] {
    fingerprint[12..20]
        .try_into()
        .expect("a 20 byte slice sliced to 8 bytes is 8 bytes")
}

/// Renders a fingerprint as 40 upper case hex characters.
pub(crate) fn fingerprint_hex(fingerprint: &[u8; 20]) -> String {
    hex::encode_upper(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NIST P-256 generator point G, uncompressed: `04 || Gx || Gy`.
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
            packet.fingerprint.to_vec(),
            hex::decode("13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6")
                .expect("test vector should be valid hex")
        );
    }

    #[test]
    fn key_id_is_the_last_8_bytes_of_the_fingerprint() {
        let packet = primary_key_packet(generator_point(), 1_700_000_000);
        assert_eq!(
            key_id(&packet.fingerprint).to_vec(),
            hex::decode("2D007ACDCD30CCA6").expect("test vector should be valid hex")
        );
    }

    #[test]
    fn fingerprint_hex_is_upper_case_and_40_characters() {
        let packet = primary_key_packet(generator_point(), 1_700_000_000);
        assert_eq!(
            fingerprint_hex(&packet.fingerprint),
            "13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6"
        );
    }

    #[test]
    fn parse_point_hex_rejects_wrong_length() {
        let error = parse_point_hex("0400").expect_err("short input should be rejected");
        assert!(matches!(error, OpenPgpError::PointLength { actual: 2 }));
    }

    #[test]
    fn parse_point_hex_rejects_compressed_points() {
        // A 65 byte input (correct length) with a compressed point prefix
        // (0x02) instead of the required 0x04.
        let compressed = format!("02{}", "11".repeat(64));
        let error = parse_point_hex(&compressed).expect_err("compressed point should be rejected");
        assert!(matches!(error, OpenPgpError::CompressedPoint));
    }

    #[test]
    fn parse_point_hex_rejects_non_hex_input() {
        let error = parse_point_hex("zz").expect_err("non hex input should be rejected");
        assert!(matches!(error, OpenPgpError::NotHex(_)));
    }

    #[test]
    fn parse_point_hex_strips_a_0x_prefix() {
        let with_prefix = format!("0x{}", hex::encode(generator_point().as_bytes()));
        assert_eq!(
            parse_point_hex(&with_prefix).expect("prefixed input should parse"),
            generator_point()
        );
    }
}
