//! Tests for typed SSH public keys.

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::wire::ssh::{Ed25519PublicKey, PublicKeyParseError, parse_public_key_line};

fn encode_string(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
}

#[test]
fn typed_key_encodes_openssh_formats_and_fingerprint() {
    let key = Ed25519PublicKey::from_bytes([0x66; 32]);

    assert_eq!(
        key.blob(),
        [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]
    );
    assert_eq!(
        key.line(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"
    );
    assert_eq!(
        key.fingerprint(),
        "SHA256:cIkYlH9rWM5DF0rEzMmlxdSnzL+MAAHogVaL1uSWll0"
    );
}

#[test]
fn line_round_trips_with_whitespace_and_comment() {
    let key = Ed25519PublicKey::from_bytes([0x42; 32]);
    let line = format!("  {} workstation key  ", key.line());

    assert_eq!(
        parse_public_key_line(&line).expect("commented key should parse"),
        key
    );
    assert_eq!(
        Ed25519PublicKey::from_blob(&key.blob()).expect("blob should parse"),
        key
    );
}

#[test]
fn line_reports_unsupported_algorithm_before_decoding_body() {
    let error = parse_public_key_line("ssh-rsa not-base64")
        .expect_err("non-Ed25519 line should be rejected by algorithm");

    assert!(matches!(
        error,
        PublicKeyParseError::UnsupportedAlgorithm { algorithm } if algorithm == "ssh-rsa"
    ));
}

#[test]
fn parser_rejects_malformed_and_inconsistent_blobs() {
    let invalid_base64 =
        parse_public_key_line("ssh-ed25519 %%%").expect_err("invalid base64 should be rejected");
    assert!(matches!(
        invalid_base64,
        PublicKeyParseError::InvalidBase64(_)
    ));

    let mut short_blob = Vec::new();
    encode_string(b"ssh-ed25519", &mut short_blob);
    encode_string(&[0x33; 31], &mut short_blob);
    let short_line = format!("ssh-ed25519 {}", STANDARD.encode(short_blob));
    assert!(matches!(
        parse_public_key_line(&short_line),
        Err(PublicKeyParseError::InvalidKeyLength { actual: 31 })
    ));

    let mut rsa_blob = Vec::new();
    encode_string(b"ssh-rsa", &mut rsa_blob);
    encode_string(&[0x44; 32], &mut rsa_blob);
    let mismatched_line = format!("ssh-ed25519 {}", STANDARD.encode(rsa_blob));
    assert!(matches!(
        parse_public_key_line(&mismatched_line),
        Err(PublicKeyParseError::AlgorithmMismatch {
            line_algorithm,
            blob_algorithm,
        }) if line_algorithm == "ssh-ed25519" && blob_algorithm == "ssh-rsa"
    ));

    let mut trailing_blob = Ed25519PublicKey::from_bytes([0x55; 32]).blob();
    trailing_blob.push(0);
    assert!(matches!(
        Ed25519PublicKey::from_blob(&trailing_blob),
        Err(PublicKeyParseError::TrailingBlobData)
    ));
}
