#!/usr/bin/env bash
set -euo pipefail

# Loads agent credentials and attempts to sign a payload using the tk CLI.
# The signing request will be held pending if the consensus policy applies.
#
# Usage:
#   ./sign.sh [--payload "custom message"]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_DIR="$REPO_ROOT/target/consensus-demo"
PAYLOAD="hello world"

while [[ $# -gt 0 ]]; do
    case $1 in
        --payload) PAYLOAD="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ! -f "$DEMO_DIR/agent.env" ]]; then
    echo "agent.env not found at $DEMO_DIR. Run 'cargo run -p tk --example consensus_demo -- setup' first."
    exit 1
fi

echo "==> Loading agent credentials..."
source "$DEMO_DIR/agent.env"

echo "==> Fetching agent public key..."
PUBLIC_KEY=$(cargo run -p tk --quiet -- ssh public-key)
echo "    $PUBLIC_KEY"
echo "$PUBLIC_KEY" > "$DEMO_DIR/demo-key.pub"

echo "==> Writing payload: \"$PAYLOAD\""
echo -n "$PAYLOAD" > "$DEMO_DIR/demo-payload.txt"

echo "==> Signing payload with tk CLI..."
SIGN_OUTPUT=$(cargo run -p tk --quiet -- ssh git-sign -Y sign -n git \
    -f "$DEMO_DIR/demo-key.pub" \
    "$DEMO_DIR/demo-payload.txt" 2>&1) && {
    echo "Signing succeeded."
    echo "$SIGN_OUTPUT"
} || {
    echo "$SIGN_OUTPUT"
    FINGERPRINT=$(echo "$SIGN_OUTPUT" | grep -o 'fingerprint: [^,)]*' | head -1 | sed 's/fingerprint: //')
    if [[ -n "${FINGERPRINT:-}" ]]; then
        echo ""
        echo "Approve with:"
        echo "  cargo run -p tk -- activity approve $FINGERPRINT"
    fi
}
