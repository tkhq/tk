# Core Turnkey commands

`tk` provides a unified command surface over the Turnkey public API:
identity selection, exact-body raw requests, activity inspection and recovery,
user/policy/API-key management, wallets, and serialized signing. Each command
emits one record per invocation; pass `--message-format json` for
newline-delimited machine output. Failures are error records with a stable
`code` (see `tk --help`), an optional `httpStatus`, and, for activity
failures, the last observed `activity` identity.

## Identity

Generate a credential file without contacting Turnkey:

```sh
tk api-key generate --output ./agent-key.json
```

The output contains only the public key and destination; the private key is
written to a newly created file with mode 0600 and is never printed. Register
the public key with Turnkey before using it to authenticate.

Save and select an existing registered identity:

```sh
tk login admin --organization-id ORG_UUID --api-key-file ./admin-key.json
tk --profile admin auth status
tk --profile admin whoami --message-format json
```

Login verifies the credential with `whoami` before saving the registry at
`~/.config/turnkey/tk.config.toml` (override with `--config` or `TK_CONFIG`).
Profiles identify users or credentials, so admin and agent profiles can share
one organization. `profile delete` removes a registry entry only; `auth
logout` clears the selection only.

Identity resolution uses exactly one source per invocation:

1. If `--profile` or `TK_PROFILE` names a profile, that profile is used and
   ambient `TURNKEY_*` credentials are ignored.
2. Otherwise a complete `TURNKEY_ORGANIZATION_ID`, `TURNKEY_API_PUBLIC_KEY`,
   `TURNKEY_API_PRIVATE_KEY` environment bundle is used (no HOME or registry
   needed). A partial or empty bundle is an `invalid_input` error rather than
   a fallback.
3. Otherwise the registry's active profile is used. With no active profile the
   command fails with `invalid_input`.

Credential secrets are never accepted as command-line arguments, and no
transport follows redirects: a redirected request would replay the stamp and
body to another host.

## Raw requests

`tk request` signs and submits the exact bytes you provide, with no rewriting
and no retries, so the stamped payload is byte-identical to your input:

```sh
tk request --path /public/v1/query/whoami --body "$BODY"
tk request --path /public/v1/submit/create_wallet --body-file intent.json
tk request --path /public/v1/query/whoami --body "$BODY" --stamp-only
```

The body must be a JSON object whose `organizationId` matches the selected
organization. `--stamp-only` produces the URL, stamp header, and body without
sending. An ambiguous submission outcome is reported as `submission_unknown`
with the activity identity to inspect, and is never retried implicitly.

## Activities

```sh
tk activity list --limit 50 [--cursor ACTIVITY_ID]
tk activity get ACTIVITY_ID
tk activity approve ACTIVITY_ID
tk activity reject ACTIVITY_ID
tk activity wait ACTIVITY_ID --timeout 60
```

Approve/reject fetch the activity's fingerprint by ID and submit one vote.
Inspecting a rejected activity is a successful inspection. `wait` fails with
`api_error` when the activity ends rejected or failed, and with `wait_timeout`
when time runs out; both carry the last observed activity so the wait can be
resumed with the same ID. Server errors, throttling, and transport failures
during a poll do not end the wait; the next poll runs until the deadline.

## Users, policies, and API keys

Create/update/register commands require exactly one of `--input-json JSON` or
`--input-file PATH` (`-` for stdin), containing the **parameters object**
without organization ID, timestamp, or activity envelope. Inputs are parsed
before credential resolution; unsupported fields, malformed JSON, invalid
resource UUIDs, and empty create batches are rejected locally as
`invalid_input`.

Policy expressions pass through unchanged. Policy creation uses `effect`,
`condition`, `consensus`, `notes`; updates use `policyEffect`,
`policyCondition`, `policyConsensus`, `policyNotes`. A create field in an
update is an error rather than a silently dropped field.

See `tk user|policy|api-key --help` for the full sub-command list.

## Wallets and signing

`tk wallet list|get|create|update`, `tk wallet account list|create`, and
`tk sign payload|transaction` follow the same structured-input rules.
`wallet account list --wallet-id ID [--limit 50] [--cursor ACCOUNT_ID]` returns
one page and a `nextCursor` candidate, like `activity list`. Signing
requires explicit encoding and hash-function (or transaction type) inputs.
`sign transaction` signs an already serialized transaction; it does not
broadcast. Pending activities (consensus needed) exit zero with status
`pending` and the activity identity for later `tk activity wait`.
