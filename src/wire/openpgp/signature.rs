//! v4 signature packets (RFC 4880 section 5.2).

use std::fmt::{self, Display, Formatter};

use sha2::{Digest, Sha256};

use super::{
    key::Fingerprint,
    packet::{mpi, new_format_packet, subpacket},
};

/// RFC 4880 9.1 and 9.4 algorithm IDs.
const PUBKEY_ALGORITHM_ECDSA: u8 = 19;
const HASH_ALGORITHM_SHA256: u8 = 8;
/// RFC 4880 5.2.3 subpacket types; the issuer fingerprint is RFC 9580 5.2.3.35.
const SUBPACKET_CREATION_TIME: u8 = 2;
const SUBPACKET_ISSUER_KEY_ID: u8 = 16;
const SUBPACKET_ISSUER_FINGERPRINT: u8 = 33;
const TAG_SIGNATURE: u8 = 2;
const P256_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

pub(crate) struct P256Scalar([u8; 32]);

impl P256Scalar {
    pub(crate) fn parse(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0; 32] && bytes < P256_CURVE_ORDER).then_some(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) struct DetachedSignaturePacket {
    pub(crate) created: u32,
    pub(crate) fingerprint: Fingerprint,
}

impl DetachedSignaturePacket {
    pub(crate) fn parse(packet: &[u8]) -> Option<Self> {
        let (&tag, packet) = packet.split_first()?;
        if tag != 0xc0 | TAG_SIGNATURE {
            return None;
        }
        let (body_len, length_len) = parse_canonical_length(packet)?;
        let body = packet.get(length_len..)?;
        if body.len() != body_len {
            return None;
        }

        let mut body = body;
        if take(&mut body, 4)?
            != [
                0x04,
                SignedObject::Document.type_octet(),
                PUBKEY_ALGORITHM_ECDSA,
                HASH_ALGORITHM_SHA256,
            ]
        {
            return None;
        }
        let hashed_len = usize::from(u16::from_be_bytes(take(&mut body, 2)?.try_into().ok()?));
        let mut hashed = take(&mut body, hashed_len)?;
        let creation = take_subpacket(&mut hashed)?;
        if creation.len() != 5 || creation[0] != SUBPACKET_CREATION_TIME | 0x80 {
            return None;
        }
        let created = u32::from_be_bytes(creation[1..].try_into().ok()?);
        let issuer = take_subpacket(&mut hashed)?;
        if issuer.len() != 22
            || issuer[0] != SUBPACKET_ISSUER_FINGERPRINT
            || issuer[1] != 0x04
            || !hashed.is_empty()
        {
            return None;
        }
        let fingerprint = Fingerprint::from_bytes(issuer[2..].try_into().ok()?);

        let unhashed_len = usize::from(u16::from_be_bytes(take(&mut body, 2)?.try_into().ok()?));
        let mut unhashed = take(&mut body, unhashed_len)?;
        let key_id = take_subpacket(&mut unhashed)?;
        if key_id.len() != 9
            || key_id[0] != SUBPACKET_ISSUER_KEY_ID
            || key_id[1..] != fingerprint.key_id()
            || !unhashed.is_empty()
        {
            return None;
        }

        take(&mut body, 2)?;
        take_canonical_p256_mpi(&mut body)?;
        take_canonical_p256_mpi(&mut body)?;
        body.is_empty().then_some(Self {
            created,
            fingerprint,
        })
    }
}

fn parse_canonical_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    match first {
        0..=191 => Some((usize::from(first), 1)),
        192..=223 => {
            let second = usize::from(*bytes.get(1)?);
            Some((((usize::from(first) - 192) << 8) + second + 192, 2))
        }
        255 => {
            let len =
                usize::try_from(u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?)).ok()?;
            (len >= 8384).then_some((len, 5))
        }
        224..=254 => None,
    }
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let value = bytes.get(..len)?;
    *bytes = bytes.get(len..)?;
    Some(value)
}

fn take_subpacket<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, length_len) = parse_canonical_length(bytes)?;
    take(bytes, length_len)?;
    if len == 0 { None } else { take(bytes, len) }
}

fn take_canonical_p256_mpi(bytes: &mut &[u8]) -> Option<P256Scalar> {
    let bits = u16::from_be_bytes(take(bytes, 2)?.try_into().ok()?);
    if !(1..=256).contains(&bits) {
        return None;
    }
    let value = take(bytes, usize::from(bits).div_ceil(8))?;
    let first = *value.first()?;
    let canonical_bits = (value.len() - 1) * 8 + (8 - first.leading_zeros() as usize);
    if first == 0 || canonical_bits != usize::from(bits) {
        return None;
    }
    let mut padded = [0; 32];
    padded[32 - value.len()..].copy_from_slice(value);
    P256Scalar::parse(padded)
}

/// What a signature covers; fixes the RFC 4880 5.2.1 type octet.
#[derive(Clone, Copy)]
pub(crate) enum SignedObject {
    UserId,
    Document,
}

impl SignedObject {
    fn type_octet(self) -> u8 {
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

pub(crate) fn issuer_fingerprint_subpacket(fingerprint: Fingerprint) -> Vec<u8> {
    let mut body = vec![0x04];
    body.extend_from_slice(fingerprint.as_bytes());
    subpacket(SUBPACKET_ISSUER_FINGERPRINT, false, &body)
}

pub(crate) fn issuer_key_id_subpacket(fingerprint: Fingerprint) -> Vec<u8> {
    subpacket(SUBPACKET_ISSUER_KEY_ID, false, &fingerprint.key_id())
}

/// RFC 4880 5.2.4 key hash prefix: `0x99 || u16 len(body) || body`.
pub(crate) fn key_hash_prefix(key_body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x99];
    out.extend_from_slice(&(key_body.len() as u16).to_be_bytes());
    out.extend_from_slice(key_body);
    out
}
