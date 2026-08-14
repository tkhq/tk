# Consensus demo

Minimal end-to-end consensus flow using `tk` with **two static config files**:

1. create a consensus policy (human/root context),
2. attempt `tk ssh git-sign` (agent context),
3. parse returned activity ID + fingerprint,
4. approve the pending activity (human/root context).

This demo is production-compatible by default (`https://api.turnkey.com`).
No localhost/internal stack assumptions.

## Prerequisites

- Rust toolchain (`cargo`)
- Existing Turnkey org with:
  - one **human/root** API key
  - one **agent/non-root** API key
  - a shared signing key (`private_key_id`) in that same org

## Config files

Create two TOML files (for example in this directory):

### `human.toml`

```toml
[turnkey]
organization_id = "<ORG_ID>"
api_public_key = "<HUMAN_PUBLIC_KEY>"
api_private_key = "<HUMAN_PRIVATE_KEY>"
private_key_id = "<PRIVATE_KEY_ID_TO_SIGN_WITH>"
api_base_url = "https://api.turnkey.com"
```

### `agent.toml`

```toml
[turnkey]
organization_id = "<ORG_ID>"
api_public_key = "<AGENT_PUBLIC_KEY>"
api_private_key = "<AGENT_PRIVATE_KEY>"
private_key_id = "<PRIVATE_KEY_ID_TO_SIGN_WITH>"
api_base_url = "https://api.turnkey.com"
```

## Run

From repo root:

```bash
cargo run -p tk --example consensus_demo -- \
  --human-config ./tk/examples/consensus_demo/human.toml \
  --agent-config ./tk/examples/consensus_demo/agent.toml
```

## Expected output (shape)

- prints created consensus policy ID
- runs agent `tk ssh git-sign` and prints consensus-needed output
- extracts and prints:
  - `activity id`
  - `fingerprint`
- runs `tk activity approve <fingerprint>` as human

## Known limitations

- Cleanup is manual for now (policy is not deleted automatically).
- The parser relies on current `tk ssh git-sign` consensus output containing
  `activity id: ...` and `fingerprint: ...`.
