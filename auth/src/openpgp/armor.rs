//! ASCII armor for OpenPGP objects (RFC 4880 section 6).

use std::fmt::{self, Display, Formatter, Write as _};

use base64::{Engine, engine::general_purpose::STANDARD};

/// RFC 4880 6.1.
const CRC24_INIT: u32 = 0x00b7_04ce;
const CRC24_POLY: u32 = 0x0086_4cfb;
const ARMOR_LINE_LENGTH: usize = 64;

/// The armor header label (RFC 4880 6.2).
#[derive(Clone, Copy)]
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
    let mut out = format!("-----BEGIN PGP {block_type}-----");
    out.push('\n');
    out.push('\n');

    let encoded = STANDARD.encode(data);
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(ARMOR_LINE_LENGTH));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }

    let crc = crc24(data);
    out.push('=');
    out.push_str(&STANDARD.encode([(crc >> 16) as u8, (crc >> 8) as u8, crc as u8]));
    out.push('\n');
    // Writing to a String cannot fail.
    let _ = write!(out, "-----END PGP {block_type}-----");
    out.push('\n');
    out
}
