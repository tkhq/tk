# Encrypted Secrets transfers

`tk secret` moves Secrets between local files and Turnkey's enclaves without
ever printing plaintext in ordinary output. All cryptographic envelopes are v1
enclave messages: signed by Turnkey's quorum key and bound to your
organization. Unbound (v0) envelopes are rejected.

Failures are error records from the shared taxonomy (see `tk --help`). Two
codes matter for recovery: `submission_unknown` (a request was sent but its
outcome could not be observed) and `wait_timeout` (the activity exists but has
not finished). Both carry a `details` object with the state file path, the
proposal fingerprint, and the last observed activity identity so an agent can
resume without guessing.

## Listing metadata

```sh
tk secret list --limit 50 [--cursor SECRET_ID]
```

Only metadata (ID, name, static properties, creation time) is decoded and
returned; payload fields are stripped by construction.

## Import

```sh
tk secret import --name api-token --input-file ./token.bin
tk secret import --name api-token --input-file - < ./token.bin
```

Import initializes the transfer (`INIT_IMPORT_SECRETS`), verifies the returned
enclave target bundle against the production quorum key and your organization,
encrypts the secret bytes locally (HPKE), and submits only ciphertext.
`--static-properties-file` attaches a JSON object of nonsecret, policy-visible
string properties. If initialization needs approvals, the command exits zero
with status `pending`, the activity identity, and a `nextStep`; after approval,
repeat the import with `--init-activity-id ID` and the original input file.
The initialization intent, organization, and activity identity are re-verified
before any bytes are encrypted. A rejected initialization or import is an
`api_error` whose `details.phase` says which step was denied. Inputs are capped
at 1 MiB.

## Export and resume

```sh
tk secret export SECRET_ID --output ./secret.bin --state-file ./export.state [--timeout 60]
tk secret resume --state-file ./export.state [--timeout 60]
```

Export generates fresh recipient key material, persists a recovery state file
(0600, exclusive) **before** submitting the `EXPORT_SECRETS` proposal, and
then recovers the result purely by observation: pending approvals, timeouts,
and uncertain submission outcomes never cause a resubmission. A definitive
client rejection (HTTP 4xx) of the submission removes the state file, because
no activity exists to recover. `resume` continues from the state file: it
verifies the original organization, API endpoint, and credential identity,
finds the activity by fingerprint when the submission outcome was unknown, and
refuses corrupted state (the persisted proposal must match its fingerprint and
its own context). `--timeout` is in seconds.

The decrypted output is written to a new file (0600, exclusive, fsynced);
existing destinations are never overwritten. If a crash left an output file
behind, it is reused only when its protected contents are byte identical to
the authenticated export. Recovery key material is scrubbed from the state
file only after the output is durable. Output and state destinations must be
regular files with mode 0600 and a single link; symlinks and stdout are
rejected.

Export and resume hold an advisory lock (`<state-file>.lock`) while they run.
The kernel releases it when the process exits, so a crash never leaves a stale
lock; a second process is told the state is locked and which file holds it.
