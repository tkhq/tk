//! OpenPGP (RFC 4880) byte layer for an identity whose private key stays in
//! Turnkey. The identity signs and certifies; it does not decrypt. This layer
//! only frames bytes: a [`entity::SignDigest`] turns a SHA-256 digest into
//! raw ECDSA scalars.

use thiserror::Error;

use key::POINT_LEN;

pub(crate) mod armor;
pub mod entity;
pub mod key;
pub(crate) mod packet;
pub(crate) mod signature;

#[derive(Debug, Error)]
pub enum OpenPgpError {
    #[error("expected a hex encoded public key")]
    NotHex(#[from] hex::FromHexError),
    #[error("expected a {POINT_LEN} byte public key, got {actual} bytes")]
    PointLength { actual: usize },
    #[error("expected an uncompressed public key point (0x04 prefix)")]
    CompressedPoint,
    #[error("OpenPGP identity has no user ID")]
    EmptyUserId,
    #[error("OpenPGP user ID must not contain a NUL, a carriage return, or a line feed")]
    UserIdControlByte,
}
