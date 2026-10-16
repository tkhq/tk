---
name: managing-secrets
description: Grant agents Turnkey Secrets exports and import, export, rotate, and inject secrets with tk, including the export policies per approval column, scope isolation between agents, secret env as a process's startup environment, and finishing an approval-gated export. Use to let an agent read a value, store one, give a process its environment, complete a pending export, or replace a value; not for wallet or private-key export.
---

# Managing secrets

Result: named, property-tagged secrets that the right agent reads at startup
with one command, with approval-gated values handled by rerunning that same
command after a human approves, and an acceptance test proving the export
policies from the agent's own credential.

## Reference

- [secrets](../../docs/secrets.md): `secret` command records, `secret env` quoting, and pending-export state.
- [resources](../../docs/resources.md): `policy create` flags and records.
- [activities](../../docs/activities.md): `activity approve` on a pending export and `policy evaluations` for a denial.

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
- Every acceptance check runs with `--profile agent`. A root success proves
  nothing, because a satisfied root quorum bypasses policies.

## Instructions

Inputs: the root profile (`admin`), an agent identity from
[provisioning-agent-identity](../provisioning-agent-identity/SKILL.md) or
[provisioning-session-agent](../provisioning-session-agent/SKILL.md) (its
profile `agent` and `AGENT_TAG`), `HUMAN_APPROVER_TAG` from
[bootstrapping-organization](../bootstrapping-organization/SKILL.md), the
export column chosen from
[approval-models.md](../references/approval-models.md), the scope prefix
(`service/`), and for each value its file and approval level.

1. **Allow agents to export.** Root. From
   [policy-patterns.md](../references/policy-patterns.md) create
   `agents-export-unilateral` for the unilateral column,
   `agents-export-with-approval` for the human column, or both when the
   organization holds both kinds of secrets. Skip a policy that already
   exists with the same name; the tag makes it shared by every agent.

2. **Import a value.** Root, from a file the agent must not read:

   <!-- example: secrets.import -->
   ```sh
   tk --profile admin --message-format json secret import --name service/API_TOKEN --property consensus=unilateral --from-file ./api-token.txt
   tk --profile admin --message-format json secret import --name service/DEPLOY_KEY --property consensus=approval --from-file ./deploy-key.txt
   ```

   Each record is `command: "secret.import"` with `data.secretId`,
   `data.name`, and `data.activity`. Import is not idempotent; a `pending`
   import is waited on, never repeated. Add further `--property` flags for
   isolation scopes the policies select.

3. **List metadata.** Any identity.

   <!-- example: secrets.list -->
   ```sh
   tk --profile agent --message-format json secret list --limit 100
   ```

   `data.secrets[]` carries `secretId`, `name`, `staticProperties[]`
   (`key`, `value`), and `createdAtUnixMs`; `data.nextCursor` pages. Values
   are never listed.

4. **Accept from the agent credential.** With one secret of each level
   imported:

   <!-- example: secrets.acceptance -->
   ```sh
   tk --profile agent --message-format json secret export --name service/API_TOKEN --out ./api-token
   tk --profile agent --message-format json secret export --name service/DEPLOY_KEY --out ./deploy-key
   ```

   The unilateral export returns `completed` with `data.out`. The approval
   export returns `pending` with `activity.id` and stays pending until a
   non-root `human-approver` votes; finish it as in step 6. Any other outcome
   is a policy defect; do not proceed on it.

5. **Build the agent's environment.** The agent's process, at startup:

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

6. **Finish an approval-gated read.** Submitter runs the export; a human
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

7. **Isolate agents from each other**, when more than one exists, as in
   [policy-patterns.md](../references/policy-patterns.md#isolation-boundaries),
   with `BILLING_AGENT_TAG` set to the billing agent's tag id from
   `user tag create`:

   <!-- example: secrets.isolation -->
   ```sh
   tk --profile admin --message-format json policy create --name billing-agent-export --effect allow \
     --consensus "approvers.any(user, user.tags.contains('${BILLING_AGENT_TAG}'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == 'unilateral' && secret.static_properties['scope'] == 'billing'"
   tk --profile billing --message-format json secret export --name ops/TOKEN
   tk --profile billing --message-format json secret env --name-prefix ops/
   ```

   Both commands as the other agent fail with `unauthorized` 403.

8. **Rotate a value.** Root. Secrets are immutable and names are unique, so
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

9. **Hand off.** Report the export policy ids and the approval column in
   force, each secret's id, name, and properties, the acceptance results from
   step 4, the pending activity ids still awaiting approval, and the exact
   `secret env` command the process runs. Stop.

## Runtime examples

The process, not the agent in conversation, runs step 5 and sources its
output. Hermes Agent, for example, takes the command as `secrets.command`;
a systemd unit, for example, runs it in `ExecStartPre` and writes to an
`EnvironmentFile`. Approval-gated secrets stay out of startup paths that
cannot wait.

## Verified by

| Examples | Test |
|---|---|
| secrets.import, secrets.list, secrets.env, secrets.rotate | secrets::managing_secrets_env_and_rotation |
| secrets.acceptance | secrets::managing_secrets_agent_export_acceptance |
| secrets.export-approved | secrets::secret_export_with_consensus_finishes_by_rerunning_the_command |
| secrets.isolation | secrets::managing_secrets_isolation_denies_cross_agent_export |
| secrets.env | secrets::secret_env_exports_matching_secrets_as_dotenv |

## Troubleshooting

- `secret env` exits `1` with `approval_required`: an `approval` secret is
  in the selection. Either add `--property consensus=unilateral` for the
  startup path, or approve each `details.pending[].activityId` and rerun.
- `secret export` fails with `unauthorized` 403: no export policy selects
  this user for this secret's properties. Check the secret carries the
  `consensus` property and the policy's `AGENT_TAG` is the id, not the name.
  Inspect
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
- The approval export returns `completed` without a human vote: the
  approver is root, or the secret carries `consensus=unilateral`. Fix the
  property or the approver; root approval proves nothing.
- `secret env` fails with `unauthorized` 403: the prefix selected a secret
  outside this agent's scope. Narrow the prefix or fix the `scope` property.
- `secret export` from a different machine or profile returns a new
  `pending`: pending state belongs to the credential and home that started
  it. Finish from the original.

## Related Skills

- [managing-policies](../managing-policies/SKILL.md): debug a denied export
  with `policy evaluations` or adjust the export set.
- [monitoring-activities](../monitoring-activities/SKILL.md): approve a
  pending export or deletion.
- [provisioning-agent-identity](../provisioning-agent-identity/SKILL.md): the
  agent user and profile that runs `secret env`.
- [managing-identities](../managing-identities/SKILL.md): rotate the agent's
  credential later.
