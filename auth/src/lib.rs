#![doc = include_str!("../README.md")]

/// Auth configuration resolution and persistence helpers.
pub mod config;
/// Git SSH signing helpers backed by Turnkey.
pub mod git_sign;
/// Public-key helpers backed by Turnkey.
pub mod public_key;
/// SSH wire-format helpers for public keys and signatures.
pub mod ssh;
/// Turnkey-backed signing client helpers.
pub mod turnkey;
