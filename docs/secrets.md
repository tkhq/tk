# Secrets

Import, list, and export UTF-8 secret values. One trailing newline is
stripped on import.

Follow [authentication](./authentication.md) first.

```bash
# From stdin, from a file, or prompted with input hidden.
echo -n "$API_TOKEN" | tk secret import --name api-token
tk secret import --name db-password --from-file ./password.txt
tk secret import --name ssh-passphrase

# Values.
tk secret export --name api-token
tk secret export --id SECRET_ID
```

Scripting:

```bash
API_TOKEN=$(tk secret export --name api-token)
tk secret export --name db-password --out ./password.txt   # new file, mode 0600
tk secret export --name api-token --message-format json | jq -r .data.value
```

## Listing

```bash
# Metadata only; values are never listed.
tk secret list
tk secret list --limit 100 --cursor SECRET_ID
# Only secrets carrying every property given.
tk secret list --property env=prod --property team=payments
# Only secrets whose name starts with the prefix; combines with --property.
tk secret list --name-prefix service/
```

## Rotation

Secrets are immutable and names are unique, so rotating a value is a delete
followed by an import under the same name:

```bash
tk secret delete --name api-token
echo -n "$NEW_API_TOKEN" | tk secret import --name api-token --property env=prod
```

`delete` accepts `--name` or `--id`. A pending deletion (consensus needed)
exits zero with `status: pending`; wait on the activity before importing the
replacement, since the name is taken until the deletion completes.

## Environment for a process

`tk secret env` exports every secret that matches a name prefix and static
properties, and prints one dotenv line per secret. The variable name is the
part of the secret name after the last `/`.

```bash
tk secret import --name service/API_TOKEN --property consensus=unilateral
tk secret import --name service/DB_URL --property consensus=unilateral
```

The process that needs them runs, at startup:

<!-- shared: secret-env-startup -->
```bash
tk --profile agent --message-format json secret env --name-prefix service/ --property consensus=unilateral
```

In human mode the same command prints `API_TOKEN=...` and `DB_URL=...`, one
per line. Values are written bare when they contain only letters, digits, and
`_./:+=@,-`, and single-quoted otherwise. A value containing a newline, NUL, or
single quote is refused. `--message-format json` returns the same values under
`data.env` plus the selected secrets under `data.exported`.

Each secret is one export activity. If any of them needs approval the command
prints nothing, exits 1 with code `approval_required`, and lists the pending
activities under `details.pending`; approve them and run the same command
again. Hermes Agent, for example, runs it as its `secrets.command`:

```yaml
secrets:
  command: /usr/local/bin/tk --profile agent secret env --name-prefix service/ --property consensus=unilateral
```

## Policy-visible metadata

```bash
# Properties are bound to the secret forever.
echo -n "$TOKEN" | tk secret import --name api-token --property env=prod --property team=payments

# Context is attached to one export request only.
tk secret export --name api-token --context purpose=deploy --context ticket=OPS-123
```

## Consensus

```bash
# Submitter: status pending, activity ID printed, nothing written yet.
tk secret export --name prod-signing-key

# Approver.
tk --profile approver activity approve --id ACTIVITY_ID

# Submitter: the same command now prints the value.
tk secret export --name prod-signing-key
```

Only the submitting credential on the submitting machine can complete the
export. A rejected export fails with `api_error`; running the command again
starts a new one.

Abandon a pending export by rejecting its activity, or leave it: the pending
state is swept after 8 hours and the activity expires after 24.

```bash
tk --profile approver activity reject --id ACTIVITY_ID
```

## Skills

- [managing-secrets](../skills/managing-secrets/SKILL.md): import, startup environment, pending exports, and rotation as one procedure.
- [monitoring-activities](../skills/monitoring-activities/SKILL.md): approving a pending export or deletion.
- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): running `secret env` as the agent's startup step.
- [provisioning-agent-identity](../skills/provisioning-agent-identity/SKILL.md): export policies per approval column and the cross-agent denial check.
- [inspecting-agents](../skills/inspecting-agents/SKILL.md): listing secrets and their properties.
