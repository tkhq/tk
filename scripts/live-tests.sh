#!/usr/bin/env bash
# Live smoke tests for tk against a real Turnkey environment.
#
# Requires TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, and
# TURNKEY_API_PRIVATE_KEY in the environment (CI supplies dev credentials from
# repository secrets); credentials are never arguments, never echoed, never
# written to disk. Every check is read-only against the API or purely local;
# nothing is mutated in the target organization. Optional: TURNKEY_API_BASE_URL
# (defaults to the dev environment), TK_BIN (prebuilt binary),
# TK_LIVE_SECRETS=1 (include `tk secret list`).
set -euo pipefail

: "${TURNKEY_API_BASE_URL:=https://api.dev.turnkey.engineering}"
export TURNKEY_API_BASE_URL

for name in TURNKEY_ORGANIZATION_ID TURNKEY_API_PUBLIC_KEY TURNKEY_API_PRIVATE_KEY; do
  [[ -n "${!name:-}" ]] || {
    echo "missing required environment: $name" >&2
    exit 2
  }
done

cd "$(dirname "$0")/.."
TK="${TK_BIN:-target/debug/tk}"
[[ -x "$TK" ]] || cargo build -p tk

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

failures=0

# check NAME [JSON_PATH EXPECTED]... -- ARGS...: runs tk with
# --message-format=json, requires exit 0 + empty stderr + matching record.
check() {
  local name="$1"
  shift
  local -a expectations=()
  while [[ "$1" != "--" ]]; do
    expectations+=("$1")
    shift
  done
  shift
  local record
  if ! record="$("$TK" --message-format=json "$@" 2>"$workdir/stderr")"; then
    echo "FAIL $name: nonzero exit" >&2
    sed 's/^/  stderr: /' "$workdir/stderr" >&2 || true
    echo "  record: $record" >&2
    failures=$((failures + 1))
    return 0
  fi
  if [[ -s "$workdir/stderr" ]]; then
    echo "FAIL $name: expected empty stderr" >&2
    failures=$((failures + 1))
    return 0
  fi
  if ! RECORD="$record" python3 - "${expectations[@]}" <<'PY'; then
import json, sys, os
record = json.loads(os.environ["RECORD"])
pairs = sys.argv[1:]
for path, expected in zip(pairs[0::2], pairs[1::2]):
    value = record
    for part in path.split("."):
        value = value[part]
    ok = {"<array>": isinstance(value, list), "<present>": value is not None}.get(
        expected, str(value) == expected
    )
    if not ok:
        print(f"  {path}: {value!r} != {expected}", file=sys.stderr)
        sys.exit(1)
PY
    echo "FAIL $name: unexpected record" >&2
    failures=$((failures + 1))
    return 0
  fi
  echo "ok $name"
}

org="$TURNKEY_ORGANIZATION_ID"

# Identity: local readiness, then remote verification of the same identity.
check auth-status \
  command auth.status data.ready True data.credentialSource environment \
  -- auth status
check whoami \
  command auth.whoami data.organizationId "$org" \
  -- whoami

# Read-only inspection across the ported resource surfaces.
check activity-list command activity.list data.items "<array>" -- activity list --limit 5
check user-list command user.list -- user list
check policy-list command policy.list -- policy list
check wallet-list command wallet.list -- wallet list

# Exact-body raw request: the whoami query with a caller-controlled body.
check raw-request \
  command request data.organizationId "$org" \
  -- request --path /public/v1/query/whoami --body "{\"organizationId\":\"$org\"}"

# Local credential generation: protected file, public material only.
key_file="$workdir/generated-key.json"
check api-key-generate \
  command api-key.generate data.publicKey "<present>" \
  -- api-key generate --output "$key_file"
if [[ "$(stat -c %a "$key_file")" != "600" ]]; then
  echo "FAIL api-key-generate: credential file is not mode 0600" >&2
  failures=$((failures + 1))
fi

if [[ "${TK_LIVE_SECRETS:-0}" == "1" ]]; then
  check secret-list command secret.list -- secret list --limit 5
fi

if ((failures)); then
  echo "$failures live check(s) failed" >&2
  exit 1
fi
echo "all live checks passed against $TURNKEY_API_BASE_URL"
