# Consensus Demo

This demo walks through a consensus-signing setup using the Turnkey Rust SDK. It creates a private key, an agent user, and a policy that requires two approvers before signing is allowed. The signing step uses the `tk` CLI directly to demonstrate the end-to-end flow.

## Prerequisites

- A [Turnkey](https://app.turnkey.com) organization with root API credentials

## Environment

Export root credentials before running setup or teardown:

```bash
export TURNKEY_ORGANIZATION_ID="<ORG_ID>"
export TURNKEY_API_PUBLIC_KEY="<ROOT_PUBLIC_KEY>"
export TURNKEY_API_PRIVATE_KEY="<ROOT_PRIVATE_KEY>"
```

To override the API base URL (defaults to `https://api.turnkey.com`):

```bash
export TURNKEY_API_BASE_URL="<CUSTOM_URL>"
```

## Setup

```bash
./scripts/consensus-demo/setup.sh
```

This creates:

- An Ed25519 private key for signing
- A demo agent user with its own API key pair
- A consensus policy requiring 2+ approvers for signing with that key

Artifacts are written to `target/consensus-demo/`:

- `state.json`: resource IDs and agent credentials used by the sign and teardown steps
- `agent.env`: agent credentials as shell exports, sourced by the sign script

## Trigger a signing request

```bash
./scripts/consensus-demo/sign.sh
```

This sources the agent credentials, fetches the agent's public key via `tk ssh public-key`, then attempts a Git-signing operation via `tk ssh git-sign`. Because the consensus policy requires a second approver, the expected output is:

```text
signing requires consensus approval (fingerprint: <activity-fingerprint>)
```

## Approve the pending activity

Using the root credentials (not the agent credentials):

```bash
cargo run -p tk -- activity approve <fingerprint>
```

## Teardown

Make sure root credentials are exported (not the agent credentials), then:

```bash
./scripts/consensus-demo/teardown.sh
```

This removes the demo policy, user, private key, and artifact directory.
