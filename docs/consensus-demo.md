# Consensus Demo

This demo creates a local consensus-signing setup for `tk` without relying on shell scripts.

## Prerequisites

- A local Turnkey stack running and reachable at `http://localhost:8081`
- An organization created in the local dashboard
- Root API credentials for that organization, either:
  - exported as `TURNKEY_API_PUBLIC_KEY` and `TURNKEY_API_PRIVATE_KEY`, or
  - saved in a dashboard-exported JSON file passed via `--credentials`

## Setup

```bash
cargo run -p tk --example consensus_demo -- setup \
  --org-id <ORG_ID> \
  --credentials <root-creds.json>
```

This writes demo artifacts to `target/consensus-demo/`:

- `state.json`: resource IDs for teardown
- `agent.env`: agent credentials you can source into a shell

## Trigger a signing request

```bash
cargo run -p tk --example consensus_demo -- sign
```

The example writes a payload and SSH public key into `target/consensus-demo/`, then attempts a Git-signing operation with the demo agent credentials. The expected result is:

```text
signing requires consensus approval (activity: <activity-id>)
```

At that point, approve the pending activity in the dashboard.

If you want to reproduce the same flow through the CLI directly:

```bash
source target/consensus-demo/agent.env
cargo run -p tk -- ssh public-key > target/consensus-demo/demo-key.pub
cargo run -p tk -- ssh git-sign -Y sign -n git \
  -f target/consensus-demo/demo-key.pub \
  target/consensus-demo/demo-payload.txt
```

## Teardown

```bash
cargo run -p tk --example consensus_demo -- teardown \
  --credentials <root-creds.json>
```

This removes the demo policy, tag, user, private key, and artifact directory.
