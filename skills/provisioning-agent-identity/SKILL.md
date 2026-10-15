---
name: provisioning-agent-identity
description: Provision a non-root, tagged Turnkey agent user on one never-expiring API key generated on the agent host, fenced by the credential DENY, and prove the identity from the agent's own credential. Use when an agent needs a permanent credential before any capability is granted; not for secrets, signing, or SSH access, which their own workflows add, and not for expiring session keys (provisioning-session-agent).
---

# Provisioning an agent identity

Result: a tagged non-root user whose single API key never expires, whose
private half exists only on the agent host, and which cannot change its own
credentials. The identity grants no capability: exports, signing, and SSH
access are each added by their own workflow. Acceptance is proven from the
agent's credential, never root's.

## Reference

- [resources](../../docs/resources.md): `user tag`, `user create`, `api-key` records, and `policy create` flags.
- [authentication](../../docs/authentication.md): `profile create`, `login`, and `whoami` records and the credential file location.
- [activities](../../docs/activities.md): `activity wait` on a pending user creation.

## Rules

- Principal separation: root creates the tag, the user, and the DENY and then
  stops. The agent never runs as root, and root never runs the agent's
  workload.
- The private key is generated on the agent host by `profile create`. Only
  `data.publicKey` travels to root; a key generated on root's machine and
  copied over is not this route.
- `agents-no-credentials` is mandatory. Self-targeted credential changes
  default-allow, so without the DENY the agent can register itself another
  permanent key.
- Policies select the tag, not names or ids. Adding an agent is one tagged
  `user create`; the DENY already covers it.
- Every acceptance check runs with `--profile agent`. A root success proves
  nothing, because a satisfied root quorum bypasses policies.

## Instructions

Inputs: the root profile (`admin`) and the host the agent runs on. There is
no minting row here: the one key never expires.

1. **Ensure the agent tag.** Root. List the tags and create `agent` only
   when no tag carries that name:

   <!-- example: agent-identity.tag -->
   ```sh
   tk --profile admin --message-format json user tag list
   tk --profile admin --message-format json user tag create --name agent
   ```

   Set `AGENT_TAG` to the id of the tag named `agent`, from the list or from
   `data.activity.result.createUserTagResult.userTagId`.
   [bootstrapping-organization](../bootstrapping-organization/SKILL.md)
   creates the same tag; never create a second one.

2. **Generate the credential on the agent host.** On that host, with no
   profile yet:

   <!-- example: agent-identity.profile-create -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name agent
   ```

   Save `data.publicKey` as `PUBLIC_KEY`. The record shape and the file it
   writes are described in
   [managing-identities](../managing-identities/SKILL.md).

3. **Create the tagged user.** Root, with the public key from step 2 and
   no `--expires-in`:

   <!-- example: agent-identity.user-create -->
   ```sh
   tk --profile admin --message-format json user create --user-name agent --tag-name agent --public-key PUBLIC_KEY
   ```

   Set `AGENT_USER_ID` to `data.activity.result.createUsersResult.userIds[0]`.
   `pending` means a policy gates user creation; wait on the activity before
   step 4.

4. **Deny credential changes.** Root, once per organization; the tag makes it
   shared by every agent:

   <!-- shared: agents-no-credentials -->
   <!-- example: agent-identity.no-credentials -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-no-credentials --effect deny \
     --consensus "approvers.any(user, user.tags.contains('${AGENT_TAG}'))" \
     --condition "activity.resource == 'CREDENTIAL'"
   ```

   The record is `command: "policy.create"` with
   `data.activity.result.createPolicyResult.policyId`. Skip it when a policy
   with this name already exists.

5. **Log in and verify on the agent host.**

   <!-- example: agent-identity.login -->
   ```sh
   tk --message-format json login --profile-name agent
   tk --profile agent --message-format json whoami
   ```

   Proceed when `whoami` returns `data.userId` equal to `AGENT_USER_ID`.

6. **Acceptance test from the agent credential.**

   <!-- example: agent-identity.acceptance -->
   ```sh
   tk --profile agent --message-format json api-key register --input-json '{"userId":"AGENT_USER_ID","apiKeys":[{"apiKeyName":"escape","publicKey":"PUBLIC_KEY","curveType":"API_KEY_CURVE_P256"}]}'
   tk --profile agent --message-format json api-key list --user-id AGENT_USER_ID
   ```

   Expected, in order:

   | Command | Expect |
   |---|---|
   | self-registration | `code: "unauthorized"` and `httpStatus: 403` |
   | key list | exactly one key, its `credential.publicKey` equal to `PUBLIC_KEY` and `expiresAt` `null` |

   Any other outcome is a policy defect; do not proceed on it.

7. **Hand off.** Report `AGENT_USER_ID`, `AGENT_TAG`, the profile name and
   host, the DENY's policy id, and the acceptance results from step 6. Stop.

## Verified by

| Examples | Test |
|---|---|
| agent-identity.tag, agent-identity.profile-create, agent-identity.user-create, agent-identity.no-credentials, agent-identity.login, agent-identity.acceptance | api_keys::provisioning_agent_identity_long_lived_route |

## Troubleshooting

- `user tag create` fails with `api_error` and a 400: a tag named `agent`
  already exists. Read its id from the list in step 1.
- `user create` fails with `not_found` for `--tag-name agent`: step 1 did not
  run in this organization. Create the tag first; do not substitute `--tag`
  with a guessed id.
- `login` fails with `unauthorized` 401 or 403: the create activity is pending or
  rejected, or `PUBLIC_KEY` was mistyped. Compare
  `tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID`
  with the error's `details.publicKey`.
- The self-registration in step 6 returns `completed` or `pending`: the DENY
  is missing or names the wrong tag, such as the `''` an unset `AGENT_TAG`
  leaves. First create `agents-no-credentials` and
  verify it by rerunning the self-registration. Only then list the agent's
  keys with `tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID`,
  delete every unauthorized key with `api-key delete` as root, and rotate the
  runtime credential. Deleting first leaves a window to register another key.

## Related Skills

- [managing-identities](../managing-identities/SKILL.md): rotate or revoke
  the agent's key later.
- [managing-secrets](../managing-secrets/SKILL.md): grant this agent
  exports and give its process a startup environment.
- [signing-git-commits](../signing-git-commits/SKILL.md): grant this agent
  a scoped signing key for its commits.
- [using-ssh](../using-ssh/SKILL.md): grant this agent a Turnkey-held SSH
  key.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): the
  expiring-key alternative when a permanent credential is not acceptable.
