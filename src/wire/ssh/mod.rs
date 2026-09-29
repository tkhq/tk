//! SSH public-key and signature wire formats.

use std::str::{self, Utf8Error};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use sha2::{Digest, Sha256, Sha512};

pub mod agent;
pub mod protocol;

const SSH_ED25519_ALGORITHM: &str = "ssh-ed25519";
const SSHSIG_PREAMBLE: &[u8] = b"SSHSIG";
const DEFAULT_HASH_ALGORITHM: &str = "sha512";

/// A parsed Ed25519 public key for SSH wire formats.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Creates a key from its raw Ed25519 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses a complete SSH public-key blob.
    pub fn from_blob(blob: &[u8]) -> Result<Self, PublicKeyParseError> {
        let mut cursor = blob;
        let algorithm = read_ssh_bytes(&mut cursor)?;
        let algorithm =
            str::from_utf8(algorithm).map_err(PublicKeyParseError::InvalidAlgorithmEncoding)?;
        if algorithm != SSH_ED25519_ALGORITHM {
            return Err(PublicKeyParseError::UnsupportedAlgorithm {
                algorithm: algorithm.to_string(),
            });
        }

        let public_key = read_ssh_bytes(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(PublicKeyParseError::TrailingBlobData);
        }
        if public_key.len() != 32 {
            return Err(PublicKeyParseError::InvalidKeyLength {
                actual: public_key.len(),
            });
        }
        let mut bytes = [0; 32];
        bytes.copy_from_slice(public_key);
        Ok(Self(bytes))
    }

    /// Encodes the key as a complete SSH public-key blob.
    pub fn blob(&self) -> Vec<u8> {
        let blob = encode_string(SSH_ED25519_ALGORITHM.as_bytes(), Vec::new());
        encode_string(&self.0, blob)
    }

    /// Encodes the key as an OpenSSH public-key line without a comment.
    pub fn line(&self) -> String {
        format!("{SSH_ED25519_ALGORITHM} {}", STANDARD.encode(self.blob()))
    }

    /// Returns the OpenSSH SHA-256 fingerprint.
    pub fn fingerprint(&self) -> String {
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(self.blob()))
        )
    }
}

/// An invalid or unsupported SSH public key.
#[derive(Debug, thiserror::Error)]
pub enum PublicKeyParseError {
    /// The public-key line has no algorithm field.
    #[error("missing SSH key algorithm")]
    MissingAlgorithm,
    /// The public-key line has no base64 body.
    #[error("missing SSH public key body")]
    MissingBody,
    /// The base64 body is malformed.
    #[error("failed to decode SSH public key body")]
    InvalidBase64(#[source] base64::DecodeError),
    /// The key uses an algorithm this library cannot sign with.
    #[error("unsupported SSH public key algorithm: {algorithm}")]
    UnsupportedAlgorithm {
        /// The algorithm read from the line or blob.
        algorithm: String,
    },
    /// The line and its encoded blob name different algorithms.
    #[error(
        "SSH public key blob algorithm mismatch: expected {line_algorithm}, got {blob_algorithm}"
    )]
    AlgorithmMismatch {
        /// The algorithm declared by the line.
        line_algorithm: String,
        /// The algorithm encoded inside the blob.
        blob_algorithm: String,
    },
    /// The blob algorithm is not UTF-8.
    #[error("SSH algorithm was not valid utf-8")]
    InvalidAlgorithmEncoding(#[source] Utf8Error),
    /// An SSH string has no complete length prefix.
    #[error("truncated SSH string length")]
    TruncatedStringLength,
    /// An SSH string is shorter than its declared length.
    #[error("truncated SSH string body")]
    TruncatedStringBody,
    /// The Ed25519 key is not exactly 32 bytes.
    #[error("expected 32-byte SSH Ed25519 public key, got {actual} bytes")]
    InvalidKeyLength {
        /// The decoded key length.
        actual: usize,
    },
    /// The blob has bytes after the key.
    #[error("unexpected trailing data in SSH public key blob")]
    TrailingBlobData,
}

/// Parses an OpenSSH Ed25519 public-key line, ignoring an optional comment.
pub fn parse_public_key_line(line: &str) -> Result<Ed25519PublicKey, PublicKeyParseError> {
    let mut parts = line.split_whitespace();
    let algorithm = parts.next().ok_or(PublicKeyParseError::MissingAlgorithm)?;
    if algorithm != SSH_ED25519_ALGORITHM {
        return Err(PublicKeyParseError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
        });
    }
    let encoded = parts.next().ok_or(PublicKeyParseError::MissingBody)?;
    let blob = STANDARD
        .decode(encoded)
        .map_err(PublicKeyParseError::InvalidBase64)?;
    match Ed25519PublicKey::from_blob(&blob) {
        Err(PublicKeyParseError::UnsupportedAlgorithm {
            algorithm: blob_algorithm,
        }) => Err(PublicKeyParseError::AlgorithmMismatch {
            line_algorithm: algorithm.to_string(),
            blob_algorithm,
        }),
        result => result,
    }
}

/// Builds the `SSHSIG` signed payload for the given namespace and message.
pub fn build_signed_data(namespace: &str, payload: &[u8]) -> Vec<u8> {
    let digest = Sha512::digest(payload);
    let mut output = Vec::new();
    output.extend_from_slice(SSHSIG_PREAMBLE);
    output = encode_string(namespace.as_bytes(), output);
    output = encode_string(&[], output);
    output = encode_string(DEFAULT_HASH_ALGORITHM.as_bytes(), output);
    output = encode_string(&digest, output);
    output
}

/// Encodes a detached SSH signature in OpenSSH armored format.
pub fn encode_armored_signature(
    public_key_blob: &[u8],
    namespace: &str,
    signature: &[u8; 64],
) -> String {
    let signature_blob = encode_string(
        signature,
        encode_string(SSH_ED25519_ALGORITHM.as_bytes(), Vec::new()),
    );

    let mut blob = Vec::new();
    blob.extend_from_slice(SSHSIG_PREAMBLE);
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob = encode_string(public_key_blob, blob);
    blob = encode_string(namespace.as_bytes(), blob);
    blob = encode_string(&[], blob);
    blob = encode_string(DEFAULT_HASH_ALGORITHM.as_bytes(), blob);
    blob = encode_string(&signature_blob, blob);

    let base64 = STANDARD.encode(blob);
    let wrapped = wrap_base64(&base64, 76);

    format!(
        r#"-----BEGIN SSH SIGNATURE-----
{wrapped}
-----END SSH SIGNATURE-----
"#
    )
}

fn encode_string(bytes: &[u8], mut output: Vec<u8>) -> Vec<u8> {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

fn wrap_base64(input: &str, width: usize) -> String {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < input.len() {
        let end = usize::min(start + width, input.len());
        lines.push(input[start..end].to_string());
        start = end;
    }
    lines.join("\n")
}

fn read_ssh_bytes<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], PublicKeyParseError> {
    let Some((length, rest)) = cursor.split_first_chunk::<4>() else {
        return Err(PublicKeyParseError::TruncatedStringLength);
    };
    *cursor = rest;

    let length = u32::from_be_bytes(*length) as usize;
    if cursor.len() < length {
        return Err(PublicKeyParseError::TruncatedStringBody);
    }

    let value = &cursor[..length];
    *cursor = &cursor[length..];
    Ok(value)
}

#[cfg(test)]
mod tests;
