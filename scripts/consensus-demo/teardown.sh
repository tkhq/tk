#!/usr/bin/env bash
set -euo pipefail

# Removes demo resources created by setup.sh.
#
# Required env vars (root credentials, not agent credentials):
#   TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY
#
# Optional:
#   TURNKEY_API_BASE_URL (defaults to https://api.turnkey.com)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"
cargo run -p tk --example consensus_demo -- teardown "$@"
