---
name: revoking-agent-keys
description: Revoke a Turnkey agent's API key before it expires with tk through a non-root revoker user scoped to an explicit set of agent users. Use when you want to revoke a key after a scoped task is complete or when a credential may have leaked; not for routine key rotation or for deleting a whole user.
---

# Revoking agent keys

Expiry is the main control on an agent's key. Turnkey does not know when a
task ends, so nothing revokes a key on its own; `api-key delete` revokes it
at once. Revoke through a scoped revoker user, never with root: root signs
only to create the revoker and its policy.

## Reference

- [resources](../../docs/resources.md): `user`, `user tag`, `api-key`, and `policy create` records and flags.
- [authentication](../../docs/authentication.md): `profile create` and `whoami` records.
- [activities](../../docs/activities.md): `activity get` and `policy evaluations` on a refused or pending delete.

## Rules

- Deleting a local key file revokes nothing. Only `api-key delete` does.
- Turnkey keeps one permanent credential per user. Deleting a user's last
  non-expiring key fails with `api_error` 400. A session agent keeps its
  anchor key, so deleting its session key succeeds. To cut a user off
  entirely, delete the user with
  [managing-identities](../managing-identities/SKILL.md).
- Policy sees `activity.params.user_id` and `activity.params.api_key_ids` on
  `ACTIVITY_TYPE_DELETE_API_KEYS`, not the target's tags. The revoker ALLOW
  lists every target user id; resolve each with `user get` before writing it.
  Never list a root-quorum user.
- The revoker carries only the `revoker` tag. Deleting a key is a
  `CREDENTIAL` activity, so the credential DENY on the `agent`, `broker`, or
  `provisioner` tag overrides the revoker ALLOW.
- A leaked revoker credential can delete keys on the listed users and do
  nothing else: no signing, minting, or export.

## Instructions

Inputs: the root profile (`admin`), `AGENT_USER_ID` for each agent user to
cover (one quoted entry each in the `in [...]` list), and the host that runs
the revoker.

1. **Create the revoker's profile and tag.** On the revoker host, generate
   its credential and send `data.publicKey` (`PUBLIC_KEY`) to root:

   <!-- example: revoking.profile-create -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name revoker
   ```

   Root creates the tag and sets `REVOKER_TAG` to
   `data.activity.result.createUserTagResult.userTagId`:

   <!-- example: revoking.tag-create -->
   ```sh
   tk --profile admin --message-format json user tag create --name revoker
   ```

2. **Create the revoker user.** Root.

   <!-- example: revoking.user-create -->
   ```sh
   tk --profile admin --message-format json user create --user-name revoker --tag-name revoker --public-key PUBLIC_KEY
   ```

   Set `REVOKER_USER_ID` to `data.activity.result.createUsersResult.userIds[0]`.

3. **Allow deletion on the listed agents.** Root. Show each id from
   `user get` first:

   <!-- example: revoking.policy -->
   ```sh
   tk --profile admin --message-format json user get --id AGENT_USER_ID
   tk --profile admin --message-format json policy create --name revoker-delete-agent-keys --effect allow \
     --consensus "approvers.any(user, user.tags.contains('${REVOKER_TAG}'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_DELETE_API_KEYS' && activity.params.user_id in ['${AGENT_USER_ID}']"
   ```

   A new agent user is added to this list, as to the provisioner's mint
   ALLOW.

4. **Revoke.** Revoker host. List first and
   pick the key to cut off; on a session agent it is the key with a non-null
   `expiresAt`:

   <!-- example: revoking.delete -->
   ```sh
   tk --profile revoker --message-format json api-key list --user-id AGENT_USER_ID
   tk --profile revoker --message-format json api-key delete --user-id AGENT_USER_ID --id API_KEY_ID
   ```

   Proceed when `data.activity.result.deleteApiKeysResult.apiKeyIds` names
   `API_KEY_ID`. The deleted key now fails `whoami` with `unauthorized`; a
   sidecar holding it stops signing.

5. **Hand off.** Report `REVOKER_USER_ID`, the policy id, the covered agent
   user ids, and each deleted key id. A revoked session agent resumes only
   after a new key is provisioned. Stop.

## Verified by

| Examples | Test |
|---|---|
| revoking.profile-create, revoking.tag-create, revoking.user-create, revoking.policy, revoking.delete | api_keys::revoking_agent_keys_scoped_revoker_deletes_listed_session_key |
| revoking.policy, revoking.delete | api_keys::revoking_agent_keys_credential_deny_blocks_tagged_revoker |

## Troubleshooting

- `api-key delete` fails `unauthorized` 403: the target user is not in the
  ALLOW's list, or the revoker also carries a tag with the credential DENY.
  Check with `policy evaluations` when an activity id exists. Do not widen
  the condition to every user; do not fall back to root.
- `api-key delete` fails `api_error` 400 "missing valid credential": the key
  is the user's last permanent credential. Register a replacement first, or
  delete the user.
- `whoami` with the deleted key still succeeds: the delete is pending or ran
  against another key id. `activity get` the delete and compare ids.

## Related Skills

- [managing-identities](../managing-identities/SKILL.md): rotate a key
  without losing access, or delete the whole user.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): mint
  the next session key after a revocation.
- [managing-policies](../managing-policies/SKILL.md): debug a denied
  revocation.
- [inspecting-agents](../inspecting-agents/SKILL.md): list which agents hold
  keys and when each expires.
