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

// The runner reports retry progress on stderr; that is this suite's output contract.
#![allow(clippy::print_stderr)]
// Test helpers may panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod config;
mod policy_helpers;
mod run;

mod activities;
mod api_keys;
mod gpg;
mod gpg_agent;
mod identity;
mod policies;
mod request;
mod secrets;
mod sessions;
mod skills;
mod ssh;
mod ssh_agent;
mod ssh_agent_destinations;
mod users;
mod wallets;
