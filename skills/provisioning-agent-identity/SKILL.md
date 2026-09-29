---
name: provisioning-agent-identity
description: Provision a non-root Turnkey agent user on one never-expiring, policy-scoped API key with tk, and fence it with the export policies and credential DENY. Use when an agent needs a permanent credential and the policies that bound it; not for wallets and not for expiring session keys, which provisioning-session-agent covers.
---

# Provisioning an agent identity

Result: a tagged non-root user whose single API key never expires, whose
private half exists only on the agent host, and whose reach is exactly the
export policies for the chosen approval column plus a DENY on its own
credentials. Acceptance is proven from the agent's credential, never root's.

## Reference

- [resources](../../docs/resources.md): `user create` flags, `api-key` records, `policy create` flags.
- [secrets](../../docs/secrets.md): `secret export` and `secret env` records and pending state.
- [authentication](../../docs/authentication.md): `profile create`, `login`, and `whoami` records and the credential file location.
- [activities](../../docs/activities.md): `activity approve` on the pending export and the `policy evaluations` record for a denial.

## Rules

- Principal separation: root creates the user and policies and then stops.
  The agent never runs as root, and root never runs the agent's workload.
- The private key is generated on the agent host by `profile create`. Only
  `data.publicKey` travels to root; a key generated on root's machine and
  copied over is not this route.
- `agents-no-credentials` is mandatory. Self-targeted credential changes
  default-allow, so without the DENY the agent can register itself another
  permanent key.
- Policies select tags and secret properties, not names or ids. Adding a
  secret is one import with the right properties; adding an agent is one
  tagged `user create`.
- Every acceptance check runs with `--profile agent`. A root success proves
  nothing, because a satisfied root quorum bypasses policies.

## Instructions

Inputs: the root profile (`admin`), `AGENT_TAG` and `HUMAN_APPROVER_TAG` from
[bootstrapping-organization](../bootstrapping-organization/SKILL.md), the
export column chosen from
[approval-models.md](../references/approval-models.md), and the host the agent
runs on. There is no minting row here: the one key never expires.

1. **Generate the credential on the agent host.** On that host, with no
   profile yet:

   <!-- example: agent-identity.profile-create -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name agent
   ```

   Save `data.publicKey` as `PUBLIC_KEY`. The record shape and the file it
   writes are described in
   [managing-identities](../managing-identities/SKILL.md).

2. **Create the tagged user.** Root, with the public key from step 1 and
   no `--expires-in`:

   <!-- example: agent-identity.user-create -->
   ```sh
   tk --profile admin --message-format json user create --user-name agent --tag-name agent --public-key PUBLIC_KEY
   ```

   Save `data.activity.result.createUsersResult.userIds[0]` as
   `AGENT_USER_ID`. `pending` means a policy gates user creation; wait on the
   activity before step 3.

3. **Apply the policy set for the export column.** Root. From
   [policy-patterns.md](../references/policy-patterns.md) create
   `agents-export-unilateral` for the unilateral column,
   `agents-export-with-approval` for the human column, or both when the
   organization holds both kinds of secrets, and always the DENY:

   <!-- shared: agents-no-credentials -->
   <!-- example: agent-identity.no-credentials -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-no-credentials --effect deny \
     --consensus "approvers.any(user, user.tags.contains('AGENT_TAG'))" \
     --condition "activity.resource == 'CREDENTIAL'"
   ```

   Each record is `command: "policy.create"` with
   `data.activity.result.createPolicyResult.policyId`. Skip a policy that
   already exists with the same name; the tags make it shared by every agent.

4. **Log in and verify on the agent host.**

   <!-- example: agent-identity.login -->
   ```sh
   tk --message-format json login --profile-name agent
   tk --profile agent --message-format json whoami
   ```

   Proceed when `whoami` returns `data.userId` equal to `AGENT_USER_ID`.

5. **Acceptance test from the agent credential.** With one
   `consensus=unilateral` secret and one `consensus=approval` secret imported
   by root as in [managing-secrets](../managing-secrets/SKILL.md):

   <!-- example: agent-identity.acceptance -->
   ```sh
   tk --profile agent --message-format json secret export --name service/API_TOKEN --out ./api-token
   tk --profile agent --message-format json secret export --name service/DEPLOY_KEY --out ./deploy-key
   tk --profile approver --message-format json activity approve --id ACTIVITY_ID
   tk --profile agent --message-format json secret export --name service/DEPLOY_KEY --out ./deploy-key
   tk --profile agent --message-format json api-key register --input-json '{"userId":"AGENT_USER_ID","apiKeys":[{"apiKeyName":"escape","publicKey":"PUBLIC_KEY","curveType":"API_KEY_CURVE_P256"}]}'
   tk --profile agent --message-format json api-key list --user-id AGENT_USER_ID
   ```

   Expected, in order:

   | Command | Expect |
   |---|---|
   | unilateral export | `completed` with `data.out` |
   | approval export | `pending` with `activity.id`, and pending until a non-root `human-approver` votes |
   | rerun after the approval | `completed` |
   | self-registration | `code: "unauthorized"` and `httpStatus: 403` |
   | key list | exactly one key, its `credential.publicKey` equal to `PUBLIC_KEY` and `expiresAt` `null` |

   Any other outcome is a policy defect; do not proceed on it.

6. **Isolate agents from each other**, when more than one exists. A shared
   `agent` tag gives every agent the same secrets. Give each boundary its
   own tag and a `scope` property on its secrets, and write one export
   policy per tag-and-scope pair instead of the shared one:

   <!-- example: agent-identity.isolation -->
   ```sh
   tk --profile admin --message-format json policy create --name billing-agent-export --effect allow \
     --consensus "approvers.any(user, user.tags.contains('BILLING_AGENT_TAG'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == 'unilateral' && secret.static_properties['scope'] == 'billing'"
   tk --profile billing --message-format json secret export --name ops/TOKEN
   tk --profile billing --message-format json secret env --name-prefix ops/
   ```

   Add the cross-agent check to the acceptance test: both commands as the
   other agent fail with `unauthorized` 403, `secret env` included, because
   `--name-prefix` selects and only the policy authorizes.

7. **Hand off.** Report `AGENT_USER_ID`, the profile name and host, the
   policy ids created, the acceptance results from step 5, and the approval
   column in force. The agent's startup command is the `secret env` line
   from [managing-secrets](../managing-secrets/SKILL.md). Stop.

## Verified by

| Examples | Test |
|---|---|
| agent-identity.profile-create, agent-identity.user-create, agent-identity.no-credentials, agent-identity.login, agent-identity.acceptance | api_keys::provisioning_agent_identity_long_lived_route |
| agent-identity.isolation | api_keys::provisioning_agent_identity_isolation_denies_cross_agent_export |

## Troubleshooting

- `user create` fails with `not_found` for `--tag-name agent`: the tags
  from bootstrapping do not exist in this organization. Create them first;
  do not substitute `--tag` with a guessed id.
- `login` fails with `unauthorized` 401 or 403: the create activity is pending or
  rejected, or `PUBLIC_KEY` was mistyped. Compare
  `tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID`
  with `data.publicKey` from step 1.
- The unilateral export fails with `unauthorized` 403: no export policy
  selects this tag for this property. Check the secret carries
  `consensus=unilateral` and the policy's `AGENT_TAG` is the id, not the
  name; `policy evaluations --activity-id ACTIVITY_ID` shows the clause when an activity
  exists.
- The approval export returns `completed` without a human vote: the
  approver is root, or the secret carries `consensus=unilateral`. Fix the
  property or the approver; root approval proves nothing.
- The self-registration in step 5 returns `completed` or `pending`: the DENY
  is missing or names the wrong tag. First create `agents-no-credentials` and
  verify it by rerunning the self-registration. Only then list the agent's
  keys with `tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID`,
  delete every unauthorized key with `api-key delete` as root, and rotate the
  runtime credential. Deleting first leaves a window to register another key.
- `secret env` fails with `approval_required`: the selection includes an
  `approval` secret. Startup paths add `--property consensus=unilateral`.
- `secret env` fails with `unauthorized` 403: the prefix selected a secret
  outside this agent's scope. Narrow the prefix or fix the `scope` property.

## Related Skills

- [managing-identities](../managing-identities/SKILL.md): rotate or revoke
  the agent's key later.
- [managing-policies](../managing-policies/SKILL.md): debug a denial with
  `policy evaluations` or adjust the export set.
- [managing-secrets](../managing-secrets/SKILL.md): import the secrets the
  acceptance test reads and the startup `secret env`.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): the
  expiring-key alternative when a permanent credential is not acceptable.
- [monitoring-activities](../monitoring-activities/SKILL.md): approve the
  pending export in step 5.
