//! Byte level OpenPGP packet framing: new format packet headers, length
//! octets, MPI (multiprecision integer) encoding, and signature subpacket
//! framing (RFC 4880 sections 3.2, 4.2.2, and 5.2.3.1).

/// Encodes RFC 4880 4.2.2 new format length octets: one octet for lengths
/// under 192, two octets for lengths under 8384, five octets otherwise.
/// Signature subpacket lengths (RFC 4880 5.2.3.1) follow the same rule, so
/// [`subpacket`] reuses this helper.
fn encode_new_format_length(len: usize) -> Vec<u8> {
    if len < 192 {
        vec![len as u8]
    } else if len < 8384 {
        let adjusted = len - 192;
        vec![((adjusted >> 8) + 192) as u8, (adjusted & 0xff) as u8]
    } else {
        let mut out = vec![0xff];
        out.extend_from_slice(&(len as u32).to_be_bytes());
        out
    }
}

/// Builds a new format OpenPGP packet (RFC 4880 4.2.2): a header byte
/// (`0xC0 | tag`), then length octets, then `body`.
pub(crate) fn new_format_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | (tag & 0x3f)];
    out.extend_from_slice(&encode_new_format_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// Encodes `bytes` as an OpenPGP MPI (RFC 4880 3.2): strips leading zero
/// bytes, then prefixes what remains with a big endian `u16` bit count. An
/// all-zero (or empty) input encodes as a zero-length MPI: just `00 00`.
pub(crate) fn mpi(bytes: &[u8]) -> Vec<u8> {
    let Some(start) = bytes.iter().position(|&b| b != 0) else {
        return 0u16.to_be_bytes().to_vec();
    };
    let trimmed = &bytes[start..];
    let bit_length = (trimmed.len() as u32 - 1) * 8 + (8 - trimmed[0].leading_zeros());
    let mut out = (bit_length as u16).to_be_bytes().to_vec();
    out.extend_from_slice(trimmed);
    out
}

/// Builds one OpenPGP signature subpacket (RFC 4880 5.2.3.1): length octets
/// covering the type octet and `body`, then the type octet (with the
/// critical bit, `0x80`, set when `critical`), then `body`.
pub(crate) fn subpacket(sub_type: u8, critical: bool, body: &[u8]) -> Vec<u8> {
    let type_octet = if critical { sub_type | 0x80 } else { sub_type };
    let mut content = vec![type_octet];
    content.extend_from_slice(body);
    let mut out = encode_new_format_length(content.len());
    out.extend_from_slice(&content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpi_strips_leading_zero_bytes_and_prefixes_bit_length() {
        assert_eq!(mpi(&[0x00, 0x00, 0x01, 0x02]), vec![0x00, 0x09, 0x01, 0x02]);
    }

    #[test]
    fn mpi_of_all_zero_bytes_is_a_zero_length_mpi() {
        assert_eq!(mpi(&[0x00, 0x00, 0x00]), vec![0x00, 0x00]);
    }

    #[test]
    fn mpi_of_a_single_high_bit_byte_uses_full_byte_bit_length() {
        // 0x80 has its top bit set, so it needs all 8 bits.
        assert_eq!(mpi(&[0x80]), vec![0x00, 0x08, 0x80]);
    }

    #[test]
    fn new_format_packet_uses_two_octet_length_for_300_byte_body() {
        let packet = new_format_packet(6, &[0; 300]);
        assert_eq!(&packet[..3], &[0xc6, 0xc0, 0x6c]);
        assert_eq!(packet.len(), 3 + 300);
    }

    #[test]
    fn new_format_packet_uses_one_octet_length_for_small_body() {
        let packet = new_format_packet(2, &[0xaa; 10]);
        assert_eq!(&packet[..2], &[0xc2, 0x0a]);
    }

    #[test]
    fn subpacket_sets_the_critical_bit_on_the_type_octet() {
        let critical = subpacket(2, true, &[0x01, 0x02, 0x03, 0x04]);
        // length (5 = 1 type octet + 4 body bytes), type | 0x80, body.
        assert_eq!(critical, vec![0x05, 0x82, 0x01, 0x02, 0x03, 0x04]);

        let not_critical = subpacket(2, false, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(not_critical, vec![0x05, 0x02, 0x01, 0x02, 0x03, 0x04]);
    }
}
