//! Runs the real `tk` binary against a real Turnkey organization:
//!
//! ```sh
//! cargo test -p tk --test e2e -- --ignored
//! ```
//!
//! Configuration comes from `.env.test` at the repository root (gitignored),
//! overridden by the process environment: `TK_E2E_ORGANIZATION_ID`,
//! `TK_E2E_API_PUBLIC_KEY` and `TK_E2E_API_PRIVATE_KEY` (a root-quorum P256
//! credential of the parent organization), and optional `TK_E2E_API_BASE_URL`.
//!
//! Every test creates its own sub-organization named `tk-e2e-<uuid>`, runs
//! all of its commands inside it as that sub-organization's root, and deletes
//! it when the test ends, so tests are isolated from each other and run in
//! parallel. The parent organization only ever sees sub-organization creation
//! and deletion.
mod config;
mod run;

mod activities;
mod api_keys;
mod gpg;
mod identity;
mod policies;
mod request;
mod secrets;
mod users;
mod wallets;
