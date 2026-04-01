#!/usr/bin/env bash
set -euo pipefail

# Creates demo resources (private key, agent user, consensus policy) using
# the tk CLI and writes agent credentials for the sign step.
#
# Required env vars:
#   TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY
#
# Optional:
#   TURNKEY_API_BASE_URL (defaults to https://api.turnkey.com)
#
# Usage:
#   ./setup.sh [--output-dir <DIR>]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/target/consensus-demo"
TK="cargo run -p tk --quiet --"
STATE_FILE=""
PRIVATE_KEY_ID=""
USER_ID=""
POLICY_ID=""
AGENT_PUBLIC_KEY=""
AGENT_PRIVATE_KEY=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

STATE_FILE="$OUTPUT_DIR/state.json"

write_state() {
    jq -n \
        --arg organization_id "$TURNKEY_ORGANIZATION_ID" \
        --arg api_url "${TURNKEY_API_BASE_URL:-https://api.turnkey.com}" \
        --arg private_key_id "${PRIVATE_KEY_ID:-}" \
        --arg agent_user_id "${USER_ID:-}" \
        --arg policy_id "${POLICY_ID:-}" \
        --arg agent_api_public_key "${AGENT_PUBLIC_KEY:-}" \
        '
        {
          organization_id: $organization_id,
          api_url: $api_url
        }
        + (if $private_key_id != "" then {private_key_id: $private_key_id} else {} end)
        + (if $agent_user_id != "" then {agent_user_id: $agent_user_id} else {} end)
        + (if $policy_id != "" then {policy_id: $policy_id} else {} end)
        + (if $agent_api_public_key != "" then {agent_api_public_key: $agent_api_public_key} else {} end)
        ' > "$STATE_FILE"
}

cleanup_on_error() {
    local exit_code=$?
    trap - ERR

    echo ""
    echo "Setup failed. Tearing down any created resources..."

    if [[ -f "$STATE_FILE" ]]; then
        "$SCRIPT_DIR/teardown.sh" --output-dir "$OUTPUT_DIR" || true
    fi

    exit "$exit_code"
}

mkdir -p "$OUTPUT_DIR"
write_state
trap cleanup_on_error ERR

SUFFIX=$(date +%s | shasum | head -c 12)

echo "==> Creating Ed25519 private key..."
KEY_JSON=$($TK keys create \
    --name "demo-signer-${SUFFIX}-key" \
    --curve ed25519 \
    --address-format solana)
PRIVATE_KEY_ID=$(echo "$KEY_JSON" | jq -r .privateKeyId)
write_state
echo "    Private key ID: $PRIVATE_KEY_ID"

echo "==> Creating agent user with auto-generated API key..."
USER_JSON=$($TK users create \
    --name "demo-agent-${SUFFIX}" \
    --email "agent-${SUFFIX}@demo.turnkey.com" \
    --api-key-name "agent-key-${SUFFIX}")
USER_ID=$(echo "$USER_JSON" | jq -r .userId)
AGENT_PUBLIC_KEY=$(echo "$USER_JSON" | jq -r .apiPublicKey)
AGENT_PRIVATE_KEY=$(echo "$USER_JSON" | jq -r .apiPrivateKey)
write_state
echo "    User ID: $USER_ID"

echo "==> Creating consensus policy (requires 2+ approvers)..."
POLICY_JSON=$($TK policies create \
    --name "demo-consensus-signing-${SUFFIX}" \
    --effect allow \
    --condition "private_key.id == '${PRIVATE_KEY_ID}' && activity.action == 'SIGN'" \
    --consensus "approvers.count() >= 2" \
    --notes "Requires a second approver for signing with the demo Ed25519 key")
POLICY_ID=$(echo "$POLICY_JSON" | jq -r .policyId)
write_state
echo "    Policy ID: $POLICY_ID"
umask 077
cat > "$OUTPUT_DIR/agent.env" <<ENVEOF
export TURNKEY_ORGANIZATION_ID="$TURNKEY_ORGANIZATION_ID"
export TURNKEY_API_PUBLIC_KEY="$AGENT_PUBLIC_KEY"
export TURNKEY_API_PRIVATE_KEY="$AGENT_PRIVATE_KEY"
export TURNKEY_PRIVATE_KEY_ID="$PRIVATE_KEY_ID"
export TURNKEY_API_BASE_URL="${TURNKEY_API_BASE_URL:-https://api.turnkey.com}"
ENVEOF
trap - ERR

echo ""
echo "Setup complete. Artifacts written to $OUTPUT_DIR"
echo ""
echo "Next step:"
echo "  ./tk/examples/consensus_demo/sign.sh"
