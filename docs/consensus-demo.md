# Consensus Demo

Demonstrates consensus-based signing with the `tk` CLI. The demo creates a private key, an agent user, and a policy that requires two approvers before any signing operation is allowed. The agent then attempts to sign via `tk ssh git-sign`, which triggers the consensus requirement.

## Prerequisites

- A [Turnkey](https://app.turnkey.com) organization with root API credentials
- Rust toolchain (`cargo`)

## 1. Export root credentials

These are used by the setup, approve, and teardown steps:

```bash
export TURNKEY_ORGANIZATION_ID="<ORG_ID>"
export TURNKEY_API_PUBLIC_KEY="<ROOT_PUBLIC_KEY>"
export TURNKEY_API_PRIVATE_KEY="<ROOT_PRIVATE_KEY>"
```

To override the API base URL (defaults to `https://api.turnkey.com`):

```bash
export TURNKEY_API_BASE_URL="<CUSTOM_URL>"
```

## 2. Setup

Create demo resources (private key, agent user, consensus policy):

```bash
cargo run -p tk --example consensus_demo -- setup
```

This writes artifacts to `target/consensus-demo/`:

- `state.json` contains resource IDs and agent credentials (used by sign and teardown)
- `agent.env` contains agent credentials as shell exports (sourced by the sign script)

## 3. Sign

Attempt a signing operation using the `tk` CLI with agent credentials:

```bash
./scripts/consensus-demo/sign.sh
```

The script sources the agent credentials, fetches the agent's public key via `tk ssh public-key`, then attempts `tk ssh git-sign`. Because the consensus policy requires a second approver, the expected output is:

```text
signing requires consensus approval (fingerprint: <fingerprint>, activity id: <id>)

Approve with:
  cargo run -p tk -- activity approve <fingerprint>
```

## 4. Approve

Switch back to root credentials and approve the pending activity:

```bash
cargo run -p tk -- activity approve <fingerprint>
```

## 5. Teardown

Clean up all demo resources (make sure root credentials are exported, not agent credentials):

```bash
cargo run -p tk --example consensus_demo -- teardown
```

This deletes the demo policy, user, private key, and removes the `target/consensus-demo/` directory.
