//! v4 OpenPGP signature packets: the hashed data that gets signed, digest
//! computation, and packet assembly from a raw ECDSA signature (RFC 4880
//! section 5.2).

use std::fmt::{self, Display, Formatter};

use sha2::{Digest, Sha256};

use super::packet::{mpi, new_format_packet, subpacket};

/// Public key algorithm ID (RFC 4880 9.1) baked into every v4 signature this
/// crate makes: ECDSA.
const PUBKEY_ALGORITHM_ECDSA: u8 = 19;
/// Hash algorithm ID (RFC 4880 9.4) baked into every v4 signature this crate
/// makes: SHA-256.
const HASH_ALGORITHM_SHA256: u8 = 8;
/// Signature subpacket type: signature creation time (RFC 4880 5.2.3.4).
const SUBPACKET_CREATION_TIME: u8 = 2;
/// Signature subpacket type: issuer key ID (RFC 4880 5.2.3.5).
const SUBPACKET_ISSUER_KEY_ID: u8 = 16;
/// Signature subpacket type: issuer fingerprint (RFC 9580 5.2.3.35).
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;
/// New format packet tag for a signature (RFC 4880 4.3).
const TAG_SIGNATURE: u8 = 2;

/// What a signature covers. This is the only set of RFC 4880 5.2.1 signature
/// types this layer makes, so the type octet is derived from the choice
/// rather than passed alongside it. Its [`Display`] names the signature for
/// error context.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) enum SignedObject {
    /// A self signature over the primary key's own User ID.
    UserId,
    /// A binary document, which is what a detached signature covers.
    Document,
}

impl SignedObject {
    /// Returns the RFC 4880 5.2.1 signature type octet.
    pub(crate) fn type_octet(self) -> u8 {
        match self {
            Self::UserId => 0x13,
            Self::Document => 0x00,
        }
    }
}

impl Display for SignedObject {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UserId => "self signature",
            Self::Document => "detached signature",
        })
    }
}

/// Everything a signature needs beyond the data it covers: what it signs and
/// its already-framed subpackets.
pub(crate) struct SignatureRequest {
    /// What this signature covers, which fixes its type octet.
    pub(crate) object: SignedObject,
    /// Already-framed hashed subpackets, concatenated in the order they
    /// should appear.
    pub(crate) hashed_subpackets: Vec<u8>,
    /// Already-framed unhashed subpackets, concatenated.
    pub(crate) unhashed_subpackets: Vec<u8>,
}

/// Builds the hashed portion of a v4 signature (RFC 4880 5.2.3): version,
/// signature type, public key algorithm (19, ECDSA), hash algorithm (8,
/// SHA-256), and the length-prefixed hashed subpackets.
pub(crate) fn hashed_portion(object: SignedObject, hashed_subpackets: &[u8]) -> Vec<u8> {
    let mut out = vec![
        0x04,
        object.type_octet(),
        PUBKEY_ALGORITHM_ECDSA,
        HASH_ALGORITHM_SHA256,
    ];
    out.extend_from_slice(&(hashed_subpackets.len() as u16).to_be_bytes());
    out.extend_from_slice(hashed_subpackets);
    out
}

/// Computes the SHA-256 digest a v4 signature signs: the data being signed,
/// the hashed portion, and the RFC 4880 5.2.4 trailer over that portion
/// (version, `0xFF`, and its length as a big endian `u32`).
pub(crate) fn digest(data_to_hash: &[u8], hashed: &[u8]) -> [u8; 32] {
    let mut trailer = vec![0x04, 0xff];
    trailer.extend_from_slice(&(hashed.len() as u32).to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(data_to_hash);
    hasher.update(hashed);
    hasher.update(trailer);
    hasher.finalize().into()
}

/// Assembles a full tag 2 signature packet from a raw ECDSA signature over
/// `digest`: `hashed || u16 len(unhashed) || unhashed || digest[0..2] ||
/// mpi(r) || mpi(s)`. Takes `hashed` by value: the caller is finished with
/// it once the digest is computed, and the packet body grows out of it.
pub(crate) fn signature_packet(
    hashed: Vec<u8>,
    unhashed_subpackets: &[u8],
    digest: &[u8; 32],
    r: &[u8],
    s: &[u8],
) -> Vec<u8> {
    let mut body = hashed;
    body.extend_from_slice(&(unhashed_subpackets.len() as u16).to_be_bytes());
    body.extend_from_slice(unhashed_subpackets);
    body.extend_from_slice(&digest[..2]);
    body.extend_from_slice(&mpi(r));
    body.extend_from_slice(&mpi(s));
    new_format_packet(TAG_SIGNATURE, &body)
}

/// Builds the signature creation time subpacket (RFC 4880 5.2.3.4, type 2,
/// critical).
pub(crate) fn creation_time_subpacket(now: u32) -> Vec<u8> {
    subpacket(SUBPACKET_CREATION_TIME, true, &now.to_be_bytes())
}

/// Builds the issuer fingerprint subpacket (RFC 9580 5.2.3.35, type 33): a
/// version byte (4) followed by the 20 byte fingerprint.
pub(crate) fn issuer_fingerprint_subpacket(fingerprint: &[u8; 20]) -> Vec<u8> {
    let mut body = vec![0x04];
    body.extend_from_slice(fingerprint);
    subpacket(SUBPACKET_ISSUER_FINGERPRINT, false, &body)
}

/// Builds the issuer key ID subpacket (RFC 4880 5.2.3.5, type 16).
pub(crate) fn issuer_key_id_subpacket(key_id: &[u8; 8]) -> Vec<u8> {
    subpacket(SUBPACKET_ISSUER_KEY_ID, false, key_id)
}

/// Builds the hash prefix a public key packet body contributes to a
/// signature's hashed data (RFC 4880 5.2.4): `0x99`, the body's big endian
/// `u16` length, then the body itself.
pub(crate) fn key_hash_prefix(key_body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x99];
    out.extend_from_slice(&(key_body.len() as u16).to_be_bytes());
    out.extend_from_slice(key_body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_portion_frames_version_type_algorithms_and_subpackets() {
        assert_eq!(
            hashed_portion(SignedObject::UserId, &[0xaa, 0xbb]),
            vec![0x04, 0x13, 19, 8, 0x00, 0x02, 0xaa, 0xbb]
        );
    }

    #[test]
    fn signature_type_octets_match_rfc_4880() {
        assert_eq!(SignedObject::UserId.type_octet(), 0x13);
        assert_eq!(SignedObject::Document.type_octet(), 0x00);
    }

    #[test]
    fn digest_hashes_the_data_the_hashed_portion_and_the_trailer() {
        let hashed = hashed_portion(SignedObject::Document, &[]);
        assert_eq!(hashed, vec![0x04, 0x00, 19, 8, 0x00, 0x00]);

        // The same three pieces, with the RFC 4880 5.2.4 trailer written out
        // byte by byte rather than rebuilt by the code under test.
        let mut hashed_input = b"payload".to_vec();
        hashed_input.extend_from_slice(&hashed);
        hashed_input.extend_from_slice(&[0x04, 0xff, 0x00, 0x00, 0x00, 0x06]);
        let expected: [u8; 32] = Sha256::digest(&hashed_input).into();

        assert_eq!(digest(b"payload", &hashed), expected);
    }

    #[test]
    fn signature_packet_lays_out_hashed_unhashed_prefix_and_mpis() {
        let packet = signature_packet(vec![0x01, 0x02], &[0x03], &[0x99; 32], &[0x01], &[0x02]);
        assert_eq!(
            packet,
            vec![
                0xc2, // tag 2, new format header
                0x0d, // one octet body length
                0x01, 0x02, // hashed portion
                0x00, 0x01, // u16 len(unhashed)
                0x03, // unhashed subpackets
                0x99, 0x99, // digest prefix
                0x00, 0x01, 0x01, // mpi(r), r = 0x01 needs 1 bit
                0x00, 0x02, 0x02, // mpi(s), s = 0x02 needs 2 bits
            ]
        );
    }

    #[test]
    fn issuer_fingerprint_subpacket_has_version_byte_and_fingerprint() {
        let mut expected = vec![
            22,   // length: 1 type octet + 1 version + 20 fingerprint bytes
            33,   // subpacket type
            0x04, // fingerprint version
        ];
        expected.extend_from_slice(&[0x11; 20]);
        assert_eq!(issuer_fingerprint_subpacket(&[0x11; 20]), expected);
    }

    #[test]
    fn issuer_key_id_subpacket_is_type_16_and_the_key_id() {
        assert_eq!(
            issuer_key_id_subpacket(&[0x22; 8]),
            vec![9, 16, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]
        );
    }

    #[test]
    fn creation_time_subpacket_is_critical_type_2_and_big_endian() {
        assert_eq!(
            creation_time_subpacket(1_700_000_000),
            vec![5, 0x82, 0x65, 0x53, 0xf1, 0x00]
        );
    }

    #[test]
    fn key_hash_prefix_is_0x99_then_length_then_body() {
        assert_eq!(
            key_hash_prefix(&[0xaa; 4]),
            vec![0x99, 0x00, 0x04, 0xaa, 0xaa, 0xaa, 0xaa]
        );
    }
}
