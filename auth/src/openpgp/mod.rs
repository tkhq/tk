//! OpenPGP (RFC 4880) byte layer for an identity whose private key stays in
//! Turnkey: a v4 public key export and detached signatures over arbitrary
//! data. The identity signs and certifies. It does not decrypt.
//!
//! This layer only frames bytes. It opens no connection and holds no key
//! material: an external signer, described by [`crate::openpgp::entity::SignDigest`], turns a
//! SHA-256 digest into raw ECDSA scalars, and the packet, subpacket, MPI, and
//! ASCII armor framing here wraps them.
//!
//! Inputs whose shape the format depends on are parsed once, at the boundary,
//! into types that carry the proof: [`crate::openpgp::key::UncompressedPoint`] for a SEC1
//! P-256 public key and [`crate::openpgp::entity::UserId`] for User ID packet contents.
//! Everything downstream transforms those infallibly, so [`crate::openpgp::OpenPgpError`]
//! reports only a parse failure; a signing failure reaches callers as the
//! signer's own error with signing context added.

use thiserror::Error;

use key::POINT_LEN;

/// Byte level OpenPGP packet framing: new format packet headers, MPI
/// encoding, and signature subpackets (RFC 4880 sections 3.2, 4.2, 5.2.3.1).
pub(crate) mod packet;

/// ASCII armor for OpenPGP objects: CRC24 and base64 wrapping (RFC 4880
/// section 6).
pub(crate) mod armor;

/// v4 public key packets, fingerprints, and key IDs (RFC 4880 sections
/// 5.5.2 and 12.2).
pub mod key;

/// v4 signature packets: hashed data, digests, and packet assembly (RFC
/// 4880 section 5.2).
pub(crate) mod signature;

/// Exporting a Turnkey backed identity as an OpenPGP entity: public key
/// export and detached signatures (RFC 4880 sections 11.1 and 11.4).
pub mod entity;

/// A rejected input: the caller gave this layer a value it cannot frame as
/// OpenPGP bytes. Raised only by the parsers that mint
/// [`crate::openpgp::key::UncompressedPoint`] and [`crate::openpgp::entity::UserId`].
#[derive(Debug, Error)]
pub enum OpenPgpError {
    /// The public key was not hex, so it could not be decoded to bytes.
    #[error("expected a hex encoded public key")]
    NotHex(#[from] hex::FromHexError),
    /// The decoded public key was the wrong length for a SEC1 P-256 point.
    #[error("expected a {POINT_LEN} byte public key, got {actual} bytes")]
    PointLength {
        /// How many bytes the input decoded to.
        actual: usize,
    },
    /// The decoded public key was not an uncompressed SEC1 point.
    #[error("expected an uncompressed public key point (0x04 prefix)")]
    CompressedPoint,
    /// The identity carried no User ID, which every OpenPGP key needs.
    #[error("OpenPGP identity has no user ID")]
    EmptyUserId,
    /// The User ID held a byte that corrupts the packet or the line based
    /// output that carries it.
    #[error("OpenPGP user ID must not contain a NUL, a carriage return, or a line feed")]
    UserIdControlByte,
}
