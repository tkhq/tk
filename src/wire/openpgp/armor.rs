//! ASCII armor for `OpenPGP` objects (RFC 4880 section 6).

use std::fmt::{self, Display, Formatter};

use base64::{Engine, engine::general_purpose::STANDARD};

use super::{OpenPgpError, key::Fingerprint, signature::DetachedSignaturePacket};

/// A complete ASCII armored `OpenPGP` signature block with a valid CRC-24 checksum.
#[derive(PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ArmoredSignature {
    value: String,
    created: u32,
    fingerprint: Fingerprint,
}

impl ArmoredSignature {
    pub(crate) fn from_parts(packet: &[u8], created: u32, fingerprint: Fingerprint) -> Self {
        Self {
            value: armor(BlockType::Signature, packet),
            created,
            fingerprint,
        }
    }

    /// Parses an untrusted complete armored signature block.
    pub fn parse(value: String) -> Result<Self, OpenPgpError> {
        const BEGIN: &str = r#"-----BEGIN PGP SIGNATURE-----
"#;
        const END: &str = r#"-----END PGP SIGNATURE-----
"#;

        let invalid = || OpenPgpError::InvalidSignatureArmor;
        let contents = value
            .strip_prefix(BEGIN)
            .and_then(|contents| contents.strip_suffix(END))
            .and_then(|contents| contents.strip_suffix('\n'))
            .ok_or_else(invalid)?;
        let mut lines = contents.split('\n');
        for header in lines.by_ref() {
            if header.is_empty() {
                break;
            }
            if !header
                .split_once(": ")
                .is_some_and(|(name, body)| !name.is_empty() && !body.is_empty())
            {
                return Err(invalid());
            }
        }
        let mut body = String::new();
        let mut checksum = None;
        for line in lines {
            if let Some(encoded) = line.strip_prefix('=') {
                if checksum.is_some() || encoded.len() != 4 {
                    return Err(invalid());
                }
                checksum = Some(encoded);
            } else if checksum.is_some() || line.is_empty() {
                return Err(invalid());
            } else {
                body.push_str(line);
            }
        }
        let decoded = STANDARD.decode(body).map_err(|_error| invalid())?;
        if decoded.is_empty() {
            return Err(invalid());
        }
        let checksum = STANDARD
            .decode(checksum.ok_or_else(invalid)?)
            .map_err(|_error| invalid())?;
        let expected = crc24(&decoded).to_be_bytes();
        if checksum != expected[1..] {
            return Err(invalid());
        }
        let parsed = DetachedSignaturePacket::parse(&decoded).ok_or_else(invalid)?;
        Ok(Self {
            value,
            created: parsed.created,
            fingerprint: parsed.fingerprint,
        })
    }

    /// The complete armored signature block.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the signature and returns its complete armored block.
    pub fn into_string(self) -> String {
        self.value
    }

    /// The hashed signature creation time.
    pub fn created(&self) -> u32 {
        self.created
    }

    /// The hashed issuer fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
}

impl Display for ArmoredSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

/// RFC 4880 6.1.
const CRC24_INIT: u32 = 0x00b7_04ce;
const CRC24_POLY: u32 = 0x0086_4cfb;
const ARMOR_LINE_LENGTH: usize = 64;

/// The armor header label (RFC 4880 6.2).
pub(crate) enum BlockType {
    PublicKeyBlock,
    Signature,
}

impl Display for BlockType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PublicKeyBlock => "PUBLIC KEY BLOCK",
            Self::Signature => "SIGNATURE",
        })
    }
}

fn crc24(data: &[u8]) -> u32 {
    let mut crc = CRC24_INIT;
    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            let top_bit_set = crc & 0x0080_0000 != 0;
            crc = (crc << 1) & 0x00ff_ffff;
            if top_bit_set {
                crc ^= CRC24_POLY;
            }
        }
    }
    crc
}

/// Lines are `\n` separated and the result ends with a newline.
pub(crate) fn armor(block_type: BlockType, data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    let mut body = String::new();
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(ARMOR_LINE_LENGTH));
        body.push_str(line);
        body.push('\n');
        rest = tail;
    }

    let crc = crc24(data);
    let checksum = STANDARD.encode([(crc >> 16) as u8, (crc >> 8) as u8, crc as u8]);

    format!(
        r#"-----BEGIN PGP {block_type}-----

{body}={checksum}
-----END PGP {block_type}-----
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::openpgp::signature::{
        SignedObject, creation_time_subpacket, hashed_portion, issuer_fingerprint_subpacket,
        issuer_key_id_subpacket, signature_packet,
    };

    const CREATED: u32 = 1_700_000_001;
    const FINGERPRINT: &str = "13FFC7DF20CD6ABFCAED58992D007ACDCD30CCA6";

    fn packet_with_scalars(r: &[u8], s: &[u8]) -> Vec<u8> {
        let fingerprint = FINGERPRINT.parse().unwrap();
        let mut subpackets = creation_time_subpacket(CREATED);
        subpackets.extend_from_slice(&issuer_fingerprint_subpacket(fingerprint));
        let hashed = hashed_portion(SignedObject::Document, &subpackets);
        signature_packet(
            hashed,
            &issuer_key_id_subpacket(FINGERPRINT.parse().unwrap()),
            &[0x12; 32],
            r,
            s,
        )
    }

    fn packet() -> Vec<u8> {
        packet_with_scalars(&[1], &[2])
    }

    fn signature() -> String {
        armor(BlockType::Signature, &packet())
    }

    #[test]
    fn parses_a_constrained_signature_and_retains_its_hashed_metadata() {
        let signature = ArmoredSignature::parse(signature()).unwrap();
        let fingerprint: Fingerprint = FINGERPRINT.parse().unwrap();

        assert_eq!(signature.created(), CREATED);
        assert_eq!(signature.fingerprint(), &fingerprint);
        assert_eq!(
            ArmoredSignature::from_parts(&packet(), CREATED, fingerprint),
            signature
        );
    }

    #[test]
    fn rejects_malformed_signature_armor() {
        let valid = signature();
        let cases = [
            "not armored".to_owned(),
            valid.replace(
                "-----BEGIN PGP SIGNATURE-----",
                "-----BEGIN PGP MESSAGE-----",
            ),
            valid.replace("-----END PGP SIGNATURE-----", "-----END PGP MESSAGE-----"),
            valid.replace("\n\n", "\n"),
            valid.replacen("wj", "not-base64", 1),
            valid.replacen('=', "=AAA", 1),
            valid.replacen('=', "=AAAA", 1),
            valid
                .lines()
                .filter(|line| !line.starts_with('='))
                .collect::<Vec<_>>()
                .join("\n"),
        ];

        for value in cases {
            assert!(matches!(
                ArmoredSignature::parse(value),
                Err(OpenPgpError::InvalidSignatureArmor)
            ));
        }
    }

    #[test]
    fn rejects_crc_correct_data_that_is_not_the_emitted_signature_packet_shape() {
        let valid = packet();
        let mut cases = vec![b"test".to_vec()];

        for (offset, replacement) in [(0, 0xc1), (2, 3), (3, 1), (4, 1), (5, 2)] {
            let mut changed = valid.clone();
            changed[offset] = replacement;
            cases.push(changed);
        }

        let mut short_length = valid.clone();
        short_length[1] -= 1;
        cases.push(short_length);
        let mut noncanonical_length = vec![valid[0], 0xff, 0, 0, 0, valid[1]];
        noncanonical_length.extend_from_slice(&valid[2..]);
        cases.push(noncanonical_length);
        let mut partial_length = valid.clone();
        partial_length[1] = 224;
        cases.push(partial_length);
        let mut trailing = valid;
        trailing.push(0);
        cases.push(trailing);

        for bytes in cases {
            assert!(matches!(
                ArmoredSignature::parse(armor(BlockType::Signature, &bytes)),
                Err(OpenPgpError::InvalidSignatureArmor)
            ));
        }
    }

    #[test]
    fn rejects_wrong_or_inconsistent_subpackets() {
        let valid = packet();
        let mut cases = Vec::new();
        for (offset, replacement) in [(9, 2), (15, 34), (16, 5), (40, 17), (48, 0)] {
            let mut changed = valid.clone();
            changed[offset] = replacement;
            cases.push(changed);
        }

        for bytes in cases {
            assert!(matches!(
                ArmoredSignature::parse(armor(BlockType::Signature, &bytes)),
                Err(OpenPgpError::InvalidSignatureArmor)
            ));
        }
    }

    #[test]
    fn rejects_zero_noncanonical_oversized_and_truncated_mpis() {
        let valid = packet();
        let mut cases = Vec::new();
        for mpi in [[0, 0], [0, 7], [1, 1], [0, 9]] {
            let mut changed = valid.clone();
            changed[51..53].copy_from_slice(&mpi);
            cases.push(changed);
        }
        let mut truncated = valid;
        truncated.pop();
        truncated[1] -= 1;
        cases.push(truncated);

        for bytes in cases {
            assert!(matches!(
                ArmoredSignature::parse(armor(BlockType::Signature, &bytes)),
                Err(OpenPgpError::InvalidSignatureArmor)
            ));
        }
    }

    #[test]
    fn rejects_p256_scalars_outside_the_curve_order() {
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];

        for invalid in [ORDER, [0xff; 32]] {
            for bytes in [
                packet_with_scalars(&invalid, &[1]),
                packet_with_scalars(&[1], &invalid),
            ] {
                assert!(matches!(
                    ArmoredSignature::parse(armor(BlockType::Signature, &bytes)),
                    Err(OpenPgpError::InvalidSignatureArmor)
                ));
            }
        }
    }

    #[test]
    fn accepts_p256_curve_order_minus_one_in_either_scalar() {
        const ORDER_MINUS_ONE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x50,
        ];

        for bytes in [
            packet_with_scalars(&ORDER_MINUS_ONE, &[1]),
            packet_with_scalars(&[1], &ORDER_MINUS_ONE),
        ] {
            ArmoredSignature::parse(armor(BlockType::Signature, &bytes)).unwrap();
        }
    }
}
