//! v4 signature packets (RFC 4880 section 5.2).

use std::fmt::{self, Display, Formatter};

use sha2::{Digest, Sha256};

use super::packet::{mpi, new_format_packet, subpacket};

/// RFC 4880 9.1 and 9.4 algorithm IDs.
const PUBKEY_ALGORITHM_ECDSA: u8 = 19;
const HASH_ALGORITHM_SHA256: u8 = 8;
/// RFC 4880 5.2.3 subpacket types; the issuer fingerprint is RFC 9580 5.2.3.35.
const SUBPACKET_CREATION_TIME: u8 = 2;
const SUBPACKET_ISSUER_KEY_ID: u8 = 16;
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;
const TAG_SIGNATURE: u8 = 2;

/// What a signature covers; fixes the RFC 4880 5.2.1 type octet.
#[derive(Clone, Copy)]
pub(crate) enum SignedObject {
    UserId,
    Document,
}

impl SignedObject {
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

/// The hashed portion of a v4 signature (RFC 4880 5.2.3).
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

/// `SHA256(data || hashed || trailer)` with the RFC 4880 5.2.4 trailer.
pub(crate) fn digest(data_to_hash: &[u8], hashed: &[u8]) -> [u8; 32] {
    let mut trailer = vec![0x04, 0xff];
    trailer.extend_from_slice(&(hashed.len() as u32).to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(data_to_hash);
    hasher.update(hashed);
    hasher.update(trailer);
    hasher.finalize().into()
}

/// `hashed || u16 len(unhashed) || unhashed || digest[0..2] || mpi(r) || mpi(s)`.
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

pub(crate) fn creation_time_subpacket(now: u32) -> Vec<u8> {
    subpacket(SUBPACKET_CREATION_TIME, true, &now.to_be_bytes())
}

pub(crate) fn issuer_fingerprint_subpacket(fingerprint: &[u8; 20]) -> Vec<u8> {
    let mut body = vec![0x04];
    body.extend_from_slice(fingerprint);
    subpacket(SUBPACKET_ISSUER_FINGERPRINT, false, &body)
}

pub(crate) fn issuer_key_id_subpacket(key_id: &[u8; 8]) -> Vec<u8> {
    subpacket(SUBPACKET_ISSUER_KEY_ID, false, key_id)
}

/// RFC 4880 5.2.4 key hash prefix: `0x99 || u16 len(body) || body`.
pub(crate) fn key_hash_prefix(key_body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x99];
    out.extend_from_slice(&(key_body.len() as u16).to_be_bytes());
    out.extend_from_slice(key_body);
    out
}
