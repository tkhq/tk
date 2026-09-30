//! `OpenPGP` (RFC 4880) byte layer for an identity whose private key stays in
//! Turnkey. The identity signs and certifies; it does not decrypt. This layer
//! only frames bytes: a [`entity::SignDigest`] turns a SHA-256 digest into
//! raw ECDSA scalars.

use key::POINT_LEN;
use thiserror::Error;

pub(crate) mod armor;
pub mod entity;
pub mod key;
pub(crate) mod packet;
pub(crate) mod signature;

/// A public key or user ID that does not meet the `OpenPGP` byte layer's contract.
#[derive(Debug, Error)]
pub enum OpenPgpError {
    /// The public key was not hex.
    #[error("expected a hex encoded public key")]
    NotHex(#[from] hex::FromHexError),
    /// The public key was hex but the wrong length.
    #[error("expected a {POINT_LEN} byte public key, got {actual} bytes")]
    PointLength {
        /// The length that was decoded.
        actual: usize,
    },
    /// The public key point lacked the uncompressed `0x04` prefix.
    #[error("expected an uncompressed public key point (0x04 prefix)")]
    CompressedPoint,
    /// The fingerprint was not 40 hex characters.
    #[error("expected a 40 character hex fingerprint")]
    NotFingerprint,
    /// The user ID was empty, which `GnuPG` refuses.
    #[error("OpenPGP identity has no user ID")]
    EmptyUserId,
    /// The user ID held a byte that would corrupt the packet or a listing.
    #[error("OpenPGP user ID must not contain a NUL, a carriage return, or a line feed")]
    UserIdControlByte,
    /// The signature armor was malformed or its checksum did not match.
    #[error("invalid armored OpenPGP signature")]
    InvalidSignatureArmor,
    /// An ECDSA signature scalar was zero or not below the P-256 curve order.
    #[error("OpenPGP signature scalar must be nonzero and below the P-256 curve order")]
    SignatureScalarOutOfRange,
}
