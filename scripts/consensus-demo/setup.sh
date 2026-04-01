#!/usr/bin/env bash
set -euo pipefail

# Creates demo resources (private key, agent user, consensus policy) and
# writes agent credentials to target/consensus-demo/.
#
# Required env vars:
#   TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY
#
# Optional:
#   TURNKEY_API_BASE_URL (defaults to https://api.turnkey.com)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
cargo run -p tk --example consensus_demo -- setup "$@"
