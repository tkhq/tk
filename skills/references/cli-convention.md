# CLI convention

How every workflow in this package calls `tk` and reads what comes back. Load
this once per task; the workflows assume it.

## Contents

- [Invocation](#invocation)
- [Records](#records)
- [Pending work](#pending-work)
- [Error codes](#error-codes)
- [Placeholders](#placeholders)
- [Secrets in transcripts](#secrets-in-transcripts)

## Invocation

Pass `--message-format json` on every command an agent runs. It prints one
JSON object per line on stdout, disables prompts, and fails fast when input is
missing. Select the identity explicitly with `--profile NAME` unless the
process runs with the `TURNKEY_ORGANIZATION_ID`, `TURNKEY_API_PUBLIC_KEY`, and
`TURNKEY_API_PRIVATE_KEY` environment bundle. See
[authentication](../../docs/authentication.md) for how the identity is
resolved.

Commands that mutate take the request's parameters object as
`--input-json JSON` or `--input-file PATH` (`-` for stdin), never an activity
envelope. Where a flag form exists (`user create --user-name`,
`user tag create --name`, `policy create --name`), prefer it; the JSON form is
the escape hatch for fields the flags do not cover.

Exit codes: `0` success (including a pending activity), `1` runtime error, `2`
usage error.

## Records

Branch on `reason` first. Three record families exist.

### `command_result`

Every `activity`, `user`, `policy`, `api-key`, `wallet`, `sign`, `secret`,
`session`, `profile`, `login`, `whoami`, `auth`, and `request` command prints
this shape:

| Field | Meaning |
|---|---|
| `schemaVersion` | `1` |
| `reason` | `command_result` |
| `command` | dotted command name, for example `user.create`, `secret.env`, `auth.whoami` |
| `status` | `completed`, `pending`, `rejected`, `failed`, or `unknown`; a record without an activity is `completed` |
| `data` | the command's payload; for API-backed commands it preserves the API response shape |
| `activity` | present when the command submitted or observed an activity: `{"id", "status"}` with the raw `ACTIVITY_STATUS_*` value |

Created resource ids live under `data.activity.result`, for example
`data.activity.result.createUsersResult.userIds[0]`,
`createUserTagResult.userTagId`, `createPolicyResult.policyId`, and
`createApiKeysResult.apiKeyIds[0]`. Queries return the API response under
`data`: `data.users`, `data.userTags`, `data.policies`, `data.apiKeys`,
`data.secrets`, and for `activity list` the page under `data.items` with
`data.nextCursor`.

### SSH and GPG outcomes

`tk ssh` and `tk gpg` commands print a record whose `reason` names the outcome
(`ssh_key_registered`, `agent_started`, `gpg_key_created`, and so on) with the
payload fields at the top level, not under `data`. Git invokes `tk` as its
signing program through a shim that bypasses JSON entirely; its output is
Git's contract.

### Error records

Any command can print an error record instead, with exit code `1` or `2`:

| Field | Meaning |
|---|---|
| `reason` | `command_error`, or `missing_required_input` when a value was absent in non-interactive mode |
| `code` | the stable classification below |
| `httpStatus` | present for HTTP failures |
| `details` | recovery data: the last observed `activity` `{id, status}`, `pending` exports, or session expiry fields |
| `message` | the full error chain, for humans |

Error records carry no `schemaVersion`, `data`, or `activity`.

## Pending work

Exit zero does not mean a mutation completed. When a policy requires more
approvals the record has `status: "pending"` and `activity.id`. Save the id.
Resume by id, never by resubmitting:

<!-- example: convention.resume -->
```sh
tk --message-format json activity get --id ACTIVITY_ID
tk --message-format json activity wait --id ACTIVITY_ID --timeout 60
```

`wait` exits `1` with `code: "wait_timeout"` and `details.activity` when the
window closes; run it again with the same id. It exits `1` with
`code: "api_error"` and `details.activity` when the activity ended rejected or
failed.

Two commands are documented as idempotent and are rerun rather than resumed:
`secret export` (and `secret env`, which is a batch of exports) picks up its
own pending export when rerun by the same credential from the same home, and
`session provision` reports `alreadyRegistered: true` instead of registering a
key twice. Every other mutation is resumed with `activity wait`.

## Error codes

| `code` | Meaning | Next action |
|---|---|---|
| `missing_required_input` | a value was absent in non-interactive mode | pass the named flag |
| `usage_error` | argument parsing failed | fix the flags; exit code `2` |
| `invalid_input` | semantic validation failed locally | fix the input; nothing was sent |
| `unauthorized` | HTTP 401 or 403 | wrong credential, or a policy denied the request; inspect with `policy evaluations` when an activity id exists |
| `not_found` | HTTP 404, or a lookup that resolved to nothing | check the id or name and the organization |
| `api_error` | other non-success HTTP status, or a failed or rejected activity | read `message`; a rejected activity is final |
| `approval_required` | `secret env` found exports that need approval | approve `details.pending[].activityId`, rerun the same command |
| `network_error` | the request never reached the server | retry |
| `network_uncertain` | transport failed after sending; delivery unknown | inspect activities before retrying a mutation |
| `submission_unknown` | a mutation was sent but its outcome was not observed | `activity list`, find it, then `activity wait` |
| `wait_timeout` | `activity wait` ran out of time | rerun `activity wait` with the same id |
| `session_expiring` | the profile's key ends within `--warn-before` | request a new session |
| `command_error` | anything else | read `message` |

## Placeholders

Examples use bare upper-case placeholders for values the reader supplies.
Every workflow example in this package is parsed against the real command
definitions in `cargo test`, with these substitutions:

| Placeholder | Stands for |
|---|---|
| `ORG_UUID`, `USER_ID`, `TAG_ID`, `POLICY_ID`, `SECRET_ID`, `WALLET_ID`, `API_KEY_ID`, `PRIVATE_KEY_ID`, `ACCOUNT_ID` | a UUID of that resource |
| `AGENT_USER_ID`, `BROKER_USER_ID`, `HUMAN_USER_ID`, `PROVISIONER_USER_ID` | the UUID of a user in that role |
| `AGENT_TAG`, `BROKER_TAG`, `HUMAN_APPROVER_TAG`, `PROVISIONER_TAG` | the UUID of that user tag |
| `ACTIVITY_ID` | an activity UUID |
| `PUBLIC_KEY`, `02…` | a compressed P-256 public key, 66 hex characters starting `02` or `03` |
| `SSH_FINGERPRINT`, `FINGERPRINT` | an opaque key fingerprint |
| `$NAME` | a shell variable set by an earlier step, named in that step |

Values that belong to the user (a name, a lifetime, a path) appear as
literals such as `agent`, `7d`, or `./policy.json`.

## Secrets in transcripts

Private keys, secret values, and the contents of
`~/.config/turnkey/tk/` never appear in a transcript, a command argument, or a
chat message. Secret values enter `tk` through `--from-file` or a pipe from a
producer, and leave it through `--out` or a pipe into the consuming process.
Verify a secret operation by exit code and metadata, not by printing the value.
Loading a workflow grants no permission to export a secret, delete a
resource, or act outside the requested organization.
