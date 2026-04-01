# Consensus Demo

This demo walks through a consensus-signing setup using the Turnkey Rust SDK. It creates a private key, an agent user, and a policy that requires two approvers before signing is allowed.

## Prerequisites

- A Turnkey organization with root API credentials
- For local development: a local Turnkey stack reachable at a known URL (e.g. `http://localhost:8081`)

## Environment

Export root credentials before running setup or teardown:

```bash
export TURNKEY_ORGANIZATION_ID="<ORG_ID>"
export TURNKEY_API_PUBLIC_KEY="<ROOT_PUBLIC_KEY>"
export TURNKEY_API_PRIVATE_KEY="<ROOT_PRIVATE_KEY>"
```

When running against a local stack, also set the base URL (defaults to `https://api.turnkey.com`):

```bash
export TURNKEY_API_BASE_URL="http://localhost:8081"
```

## Setup

```bash
cargo run -p tk --example consensus_demo -- setup
```

This creates:

- An Ed25519 private key for signing
- A demo agent user with its own API key pair
- A consensus policy requiring 2+ approvers for signing with that key

Artifacts are written to `target/consensus-demo/`:

- `state.json`: resource IDs and agent credentials used by the sign and teardown steps
- `agent.env`: the same agent credentials as shell exports, useful if you want to drive the `tk` CLI directly with agent credentials

## Trigger a signing request

```bash
cargo run -p tk --example consensus_demo -- sign
```

This attempts a raw-payload signing request using the demo agent credentials from `state.json`. Because the consensus policy requires a second approver, the expected output is:

```text
Signing requires consensus approval (fingerprint: <activity-fingerprint>)
```

## Approve the pending activity

Using the root credentials (not the agent credentials):

```bash
cargo run -p tk -- activity approve <fingerprint>
```

## Teardown

Make sure root credentials are exported (not the agent credentials), then:

```bash
cargo run -p tk --example consensus_demo -- teardown
```

This removes the demo policy, user, private key, and artifact directory.
