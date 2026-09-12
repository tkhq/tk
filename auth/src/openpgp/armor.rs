//! ASCII armor for OpenPGP objects (RFC 4880 section 6).

use std::fmt::{self, Display, Formatter, Write as _};

use base64::{Engine, engine::general_purpose::STANDARD};

/// CRC24 initial register value (RFC 4880 6.1).
const CRC24_INIT: u32 = 0x00b7_04ce;
/// CRC24 polynomial (RFC 4880 6.1), applied once the shifted register's top
/// bit (`0x800000`) is set.
const CRC24_POLY: u32 = 0x0086_4cfb;
/// ASCII armor wraps its base64 body at 64 columns (RFC 4880 6.3).
const ARMOR_LINE_LENGTH: usize = 64;

/// The kind of OpenPGP object an armor block carries (RFC 4880 6.2). Its
/// [`Display`] is the label that goes in the armor header and footer.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) enum BlockType {
    /// A transferable public key (RFC 4880 11.1).
    PublicKeyBlock,
    /// One or more detached signature packets (RFC 4880 11.4).
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

/// Computes the CRC24 checksum ASCII armor appends after the base64 body
/// (RFC 4880 6.1).
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

/// Wraps `data` in RFC 4880 ASCII armor: a `-----BEGIN PGP {block_type}-----`
/// header, a blank line, the base64 body at 64 columns, a `=`-prefixed
/// base64 CRC24 line, and a `-----END PGP {block_type}-----` footer. Lines
/// are `\n` separated (never `\r\n`), and the result ends with a trailing
/// newline.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc24_of_empty_input_is_the_initial_register() {
        assert_eq!(crc24(b""), 0x00b7_04ce);
    }

    #[test]
    fn crc24_matches_an_independently_computed_vector() {
        // Computed once with a standalone Python port of the same
        // init/poly (RFC 4880 6.1), not by calling this function:
        //   crc = 0xB704CE
        //   for byte in b"hello":
        //       crc ^= byte << 16
        //       for _ in range(8):
        //           crc <<= 1
        //           if crc & 0x1000000:
        //               crc ^= 0x1864CFB
        //   crc & 0xFFFFFF  ->  0x47F58A
        assert_eq!(crc24(b"hello"), 0x0047_f58a);
    }

    #[test]
    fn armor_of_empty_data_is_a_header_blank_line_crc_and_footer() {
        // CRC24 of empty input is the initial register, 0xB704CE, which
        // base64 encodes to "twTO".
        assert_eq!(
            armor(BlockType::Signature, b""),
            r#"-----BEGIN PGP SIGNATURE-----

=twTO
-----END PGP SIGNATURE-----
"#
        );
    }

    #[test]
    fn armor_wraps_the_base64_body_at_64_columns() {
        // 100 bytes encode to 136 base64 characters: two full lines and a
        // remainder.
        let armored = armor(BlockType::PublicKeyBlock, &[0xab; 100]);
        let body_line_lengths: Vec<usize> = armored
            .lines()
            .skip(2)
            .take_while(|line| !line.starts_with('='))
            .map(str::len)
            .collect();
        assert_eq!(body_line_lengths, vec![64, 64, 8]);
    }
}
