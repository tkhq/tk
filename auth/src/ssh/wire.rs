use anyhow::{Result, anyhow};

/// SSH algorithm identifier for Ed25519 keys.
pub const SSH_ED25519_ALGORITHM: &str = "ssh-ed25519";

/// Appends an SSH string (4-byte big-endian length prefix + data) to the output buffer.
pub fn encode_string(bytes: &[u8], mut output: Vec<u8>) -> Vec<u8> {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

/// Reads one SSH string (4-byte big-endian length prefix + data) from the cursor,
/// advancing it past the consumed bytes.
pub fn read_ssh_bytes(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    if cursor.len() < 4 {
        return Err(anyhow!("truncated SSH string length"));
    }

    let length = u32::from_be_bytes(cursor[..4].try_into().expect("length slice should be 4"));
    *cursor = &cursor[4..];

    let length = length as usize;
    if cursor.len() < length {
        return Err(anyhow!("truncated SSH string body"));
    }

    let value = cursor[..length].to_vec();
    *cursor = &cursor[length..];
    Ok(value)
}
