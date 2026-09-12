//! New format packet headers, MPI encoding, and signature subpacket framing
//! (RFC 4880 sections 3.2, 4.2.2, and 5.2.3.1).

/// RFC 4880 4.2.2 length octets, shared with subpackets (5.2.3.1).
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

pub(crate) fn new_format_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | (tag & 0x3f)];
    out.extend_from_slice(&encode_new_format_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// RFC 4880 3.2 MPI: leading zero bytes stripped, then a `u16` bit count.
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

pub(crate) fn subpacket(sub_type: u8, critical: bool, body: &[u8]) -> Vec<u8> {
    let type_octet = if critical { sub_type | 0x80 } else { sub_type };
    let mut content = vec![type_octet];
    content.extend_from_slice(body);
    let mut out = encode_new_format_length(content.len());
    out.extend_from_slice(&content);
    out
}
