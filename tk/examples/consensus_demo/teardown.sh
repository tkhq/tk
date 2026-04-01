#!/usr/bin/env bash
set -euo pipefail

# Removes demo resources created by setup.sh using the tk CLI.
#
# Required env vars (root credentials, not agent credentials):
#   TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY
#
# Optional:
#   TURNKEY_API_BASE_URL (defaults to https://api.turnkey.com)
#
# Usage:
#   ./teardown.sh [--output-dir <DIR>]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/target/consensus-demo"
TK="cargo run -p tk --quiet --"

while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

STATE_FILE="$OUTPUT_DIR/state.json"

if [[ ! -f "$STATE_FILE" ]]; then
    echo "state.json not found at $OUTPUT_DIR. Nothing to tear down."
    exit 0
fi

POLICY_ID=$(jq -r '.policy_id // empty' "$STATE_FILE")
USER_ID=$(jq -r '.agent_user_id // empty' "$STATE_FILE")
KEY_ID=$(jq -r '.private_key_id // empty' "$STATE_FILE")

if [[ -n "$POLICY_ID" ]]; then
    echo "==> Deleting policy $POLICY_ID..."
    $TK policies delete --policy-id "$POLICY_ID"
fi

if [[ -n "$USER_ID" ]]; then
    echo "==> Deleting user $USER_ID..."
    $TK users delete --user-id "$USER_ID"
fi

if [[ -n "$KEY_ID" ]]; then
    echo "==> Deleting private key $KEY_ID..."
    $TK keys delete --key-id "$KEY_ID" --delete-without-export
fi

rm -rf "$OUTPUT_DIR"

echo "Teardown complete."
