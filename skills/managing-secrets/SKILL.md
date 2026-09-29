---
name: managing-secrets
description: Import, export, rotate, and inject Turnkey Secrets with tk, including secret env as a process's startup environment and finishing an approval-gated export. Use to store a value an agent will read, give a process its environment, complete a pending export, or replace a value; not for wallet or private-key export.
---

# Managing secrets

Result: named, property-tagged secrets that the right agent reads at startup
with one command, with approval-gated values handled by rerunning that same
command after a human approves.

## Reference

- [secrets](../../docs/secrets.md): `secret` command records, `secret env` quoting, and pending-export state.

## Rules

- Values never enter the transcript. Import from `--from-file` or a pipe;
  export to `--out` or into the consuming process. Verify by exit code and
  metadata.
- Every secret carries exactly one `consensus` property, `unilateral` or
  `approval`, and is named `<scope>/<VAR>` so `secret env` can build an
  environment. Properties are immutable and policy-visible; never put a
  secret value in one.
- Export and `env` are rerun, not resumed: the same credential from the same
  home directory picks up its own pending export.
- Access is granted by policy on the property, not by name prefix. The
  prefix selects; the policy authorizes.

## Instructions

Inputs: the root profile (`admin`), the agent's profile (`agent`), the scope
prefix (`service/`), and for each value its file and approval level. The
export policies from [policy-patterns.md](../references/policy-patterns.md)
must already exist.

1. **Import a value.** Root, from a file the agent must not read:

   <!-- example: secrets.import -->
   ```sh
   tk --profile admin --message-format json secret import --name service/API_TOKEN --property consensus=unilateral --from-file ./api-token.txt
   tk --profile admin --message-format json secret import --name service/DEPLOY_KEY --property consensus=approval --from-file ./deploy-key.txt
   ```

   Each record is `command: "secret.import"` with `data.secretId`,
   `data.name`, and `data.activity`. Import is not idempotent; a `pending`
   import is waited on, never repeated. Add further `--property` flags for
   isolation scopes the policies select.

2. **List metadata.** Any identity.

   <!-- example: secrets.list -->
   ```sh
   tk --profile agent --message-format json secret list --limit 100
   ```

   `data.secrets[]` carries `secretId`, `name`, `staticProperties[]`
   (`key`, `value`), and `createdAtUnixMs`; `data.nextCursor` pages. Values
   are never listed.

3. **Build the agent's environment.** The agent's process, at startup:

   <!-- shared: secret-env-startup -->
   <!-- example: secrets.env -->
   ```sh
   tk --profile agent --message-format json secret env --name-prefix service/ --property consensus=unilateral
   ```

   Exit `0`: `data.env` maps each `VAR` to its value and `data.exported[]`
   names the secrets; in human mode the same command prints dotenv lines
   for the process to source. The property filter excludes approval-gated
   secrets silently. Without the filter, any approval-gated secret in the
   selection makes the command exit `1` with `code: "approval_required"`
   and `details.pending[]` (`name`, `secretId`, `activityId`), and prints no
   values at all.

4. **Finish an approval-gated read.** Submitter runs the export; a human
   approves; the submitter reruns the identical command:

   <!-- example: secrets.export-approved -->
   ```sh
   tk --profile agent --message-format json secret export --name service/DEPLOY_KEY --out ./deploy-key
   tk --profile approver --message-format json activity approve --id ACTIVITY_ID
   tk --profile agent --message-format json secret export --name service/DEPLOY_KEY --out ./deploy-key
   ```

   The first run returns `status: "pending"`, `activity.id`, and
   `data.nextStep`; nothing is written. The rerun returns `completed` with
   `data.out`. `--out` refuses an existing path. Rerunning while the approval
   is outstanding returns the same `pending` activity, not a second one.

5. **Rotate a value.** Root. Secrets are immutable and names are unique, so
   a rotation is a delete followed by an import under the same name with the
   same properties. The name is unavailable between the two.

   <!-- example: secrets.rotate -->
   ```sh
   tk --profile admin --message-format json secret delete --name service/API_TOKEN
   tk --profile admin --message-format json secret import --name service/API_TOKEN --property consensus=unilateral --from-file ./api-token-new.txt
   ```

   Wait for a `pending` deletion before importing. The new secret has a new
   id. Deleting does not revoke a value already exported; rotate the
   credential at its provider first when access is being reduced.

6. **Hand off.** Report each secret's id, name, and properties, the pending
   activity ids still awaiting approval, and the exact `secret env` command
   the process runs. Stop.

## Runtime examples

The process, not the agent in conversation, runs step 3 and sources its
output. Hermes Agent, for example, takes the command as `secrets.command`;
a systemd unit, for example, runs it in `ExecStartPre` and writes to an
`EnvironmentFile`. Approval-gated secrets stay out of startup paths that
cannot wait.

## Verified by

| Examples | Test |
|---|---|
| secrets.import, secrets.list, secrets.env, secrets.rotate | secrets::managing_secrets_env_and_rotation |
| secrets.export-approved | secrets::secret_export_with_consensus_finishes_by_rerunning_the_command |
| secrets.env | secrets::secret_env_exports_matching_secrets_as_dotenv |

## Troubleshooting

- `secret env` exits `1` with `approval_required`: an `approval` secret is
  in the selection. Either add `--property consensus=unilateral` for the
  startup path, or approve each `details.pending[].activityId` and rerun.
- `secret export` fails with `unauthorized` 403: no export policy selects
  this user for this secret's properties. Inspect
  `tk --profile admin --message-format json policy evaluations --activity-id ACTIVITY_ID`
  when the error carries an activity; otherwise compare the user's tags
  with the policy consensus. Do not switch to root.
- `secret export` fails with `api_error` and `details.activity`: the export
  was rejected or failed; local state is cleared and the next run starts a
  new export.
- `secret import` fails with `api_error` 400: the name is taken. A pending
  deletion holds the name until it completes.
- `secret env` fails with `invalid_input` "no secrets match": the prefix or
  property selects nothing in this organization. Check `secret list`.
- `secret export` from a different machine or profile returns a new
  `pending`: pending state belongs to the credential and home that started
  it. Finish from the original.

## Related Skills

- [managing-policies](../managing-policies/SKILL.md): the export policies
  that make step 3 succeed.
- [monitoring-activities](../monitoring-activities/SKILL.md): approve a
  pending export or deletion.
- [managing-identities](../managing-identities/SKILL.md): the agent user and
  profile that runs `secret env`.
