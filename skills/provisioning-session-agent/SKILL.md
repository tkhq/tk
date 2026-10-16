---
name: provisioning-session-agent
description: Provision or renew a non-root Turnkey agent's expiring API keys through a separate provisioner. Use when setting up session credentials or recovering an expired session; not for wallet provisioning.
---

# Provisioning a session agent

Result: a tagged non-root agent on expiring API keys, a tagged provisioner that
may register keys on that agent and nothing else, the minting row's policies,
and a renewal loop the agent host runs by itself. Pick the branch first: **first
provisioning** runs steps 1 to 5; **renewal** runs step 5 only; **recovery** runs
one branch of step 6. A renewal never repeats bootstrap, replaces a policy, or
recreates the agent. Inputs: the root profile (`admin`), `AGENT_TAG`,
`PROVISIONER_TAG`, and `HUMAN_APPROVER_TAG` set to the tag ids from
bootstrapping, the minting row chosen from
[approval-models.md](../references/approval-models.md), the agent host, and the provisioner host.

## Reference

- [sessions](../../docs/sessions.md): `session request`, `provision`, `activate`, and `status` records and errors.
- [resources](../../docs/resources.md): `user create` flags, `api-key` records, `policy create` flags.
- [authentication](../../docs/authentication.md): `profile create`, `login`, and `whoami` records and the credential file location.
- [activities](../../docs/activities.md): `activity approve` and `activity get` on a pending mint.

## Rules

- Two principals, two credential stores: different users, different
  profiles, different homes. A provisioner that can read the agent's key
  file is the agent.
- The agent generates every keypair. Only `data.publicKey` and `data.userId` cross to
  the provisioner. Neither is secret, but the handoff is authenticated and integrity-checked,
  and the provisioner accepts a key only for the organization, agent user id, and lifetime it expects.
- Policy sees `activity.params.user_id` and each key's `expiration_seconds`, not the target's tags.
  The mint ALLOW pins both the target set and the lifetime cap; keep the cap at or above the
  `--expires-in` the renewal loop passes. The approver reads `data.userId`, `data.publicKey`, and
  `data.expiresIn` from the `session provision` record. Every id in the mint ALLOW's `in [...]` list is resolved
  with `user get` and shown before the policy is written; a root-quorum id there mints keys on root.
- `session status` defaults to `--warn-before 48h`; pass a window shorter than the lifetime.
- Deleting a local key file revokes nothing; `api-key delete` by a scoped revoker does
  ([revoking-agent-keys](../revoking-agent-keys/SKILL.md)).
- Persist `AGENT_USER_ID`: after expiry `session request` reports `userId: null`.

## Instructions

1. **Create the agent's profile.** Agent host, as the agent's OS user. The
   private key is generated here and stays here; send `data.publicKey`
   (`PUBLIC_KEY`) to root.

   <!-- example: session.profile-create -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name agent
   ```

2. **Create the agent user with its first expiring key.** Root. The anchor
   key meets Turnkey's one-permanent-credential rule; its private half is
   discarded on the spot.

   <!-- example: session.user-create -->
   ```sh
   tk --profile admin --message-format json user create --user-name agent --tag-name agent --public-key PUBLIC_KEY --expires-in 7d --anchor-key
   ```

   Set `AGENT_USER_ID` to `data.activity.result.createUsersResult.userIds[0]` and persist it.

3. **Create the provisioner and the minting row's policies.** Root. The
   provisioner's key comes from step 1's command run on the provisioner
   host as `--profile-name provisioner`:

   <!-- example: session.provisioner-create -->
   ```sh
   tk --profile admin --message-format json user create --user-name provisioner --tag-name provisioner --public-key PROVISIONER_PUBLIC_KEY
   ```

   Set `PROVISIONER_USER_ID` to its id. Apply the minting row's set from
   [policy-patterns.md](../references/policy-patterns.md):

   | Policy | Shape |
   |---|---|
   | `provisioners-mint-agent-keys` | pinned to `AGENT_USER_ID` and a lifetime cap; drop the `HUMAN_APPROVER_TAG` clause in the unilateral-minting row |
   | `provisioners-nothing-else` | as written |
   | `provisioners-no-self-keys` | one per provisioner |
   | `agents-no-credentials` | as written |

   The two that carry ids:

   <!-- shared: provisioners-mint-agent-keys -->
   <!-- example: session.policy-mint -->
   ```sh
   tk --profile admin --message-format json policy create --name provisioners-mint-agent-keys --effect allow \
     --consensus "approvers.any(user, user.tags.contains('${PROVISIONER_TAG}')) && approvers.any(user, user.tags.contains('${HUMAN_APPROVER_TAG}'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id in ['${AGENT_USER_ID}'] && activity.params.api_keys.all(k, k.expiration_seconds <= 604800)"
   ```

   <!-- shared: provisioners-no-self-keys -->
   <!-- example: session.policy-self-deny -->
   ```sh
   tk --profile admin --message-format json policy create --name provisioners-no-self-keys --effect deny \
     --consensus "approvers.any(user, user.tags.contains('${PROVISIONER_TAG}'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id == '${PROVISIONER_USER_ID}'"
   ```

   Adding an agent later edits the `in [...]` list. Before the edit, resolve every id in the
   final list with `tk --profile admin --message-format json user get --id USER_ID`, confirm each is
   the intended non-root user carrying `AGENT_TAG` (or `BROKER_TAG`), show the final target set,
   and stop on any mismatch: a root-quorum user's id there lets the provisioner mint a key on root.
   Step 5 run by the real users is the acceptance.

4. **Log in as the agent.** Agent host; `data.identity.userId` must equal
   `AGENT_USER_ID`.

   <!-- example: session.login -->
   ```sh
   tk --message-format json login --profile-name agent
   ```

5. **Renew.** The loop the agent host runs on a timer. Agent host first:

   <!-- example: session.status -->
   ```sh
   tk --message-format json session status --profile-name agent --warn-before 1h
   ```

   Exit `0` with `data.secondsLeft`: done. Exit `1` `session_expiring`: go on.

   <!-- example: session.request -->
   ```sh
   tk --message-format json session request --profile-name agent
   ```

   Save `data.publicKey` and `data.userId`; the request is remembered per
   profile until `activate` consumes it. Provisioner host:

   <!-- example: session.provision -->
   ```sh
   tk --profile provisioner --message-format json session provision --user-id AGENT_USER_ID --public-key PUBLIC_KEY --expires-in 7d
   ```

   Human-minting rows: `status: "pending"`; the human checks `data.userId`, `data.publicKey`,
   and `data.expiresIn`, then runs `tk --profile approver --message-format json activity approve --id ACTIVITY_ID`;
   the provisioner's rerun returns `completed` with `alreadyRegistered: true`. Unilateral
   row: the first run completes with `data.apiKeyId`. Agent host:

   <!-- example: session.activate -->
   ```sh
   tk --message-format json session activate --profile-name agent
   tk --profile agent --message-format json whoami
   ```

   `activate` verifies the new key with `whoami` before repointing the profile and removes the
   previous key file only if `tk` stored it (`data.previousKeyFileRemoved`); the old key stays valid until it expires.

6. **Recover.** Pick the branch that matches the observed state.
   - *Expired before renewal*: `whoami` fails `unauthorized`; `session request` still succeeds
     but reports `userId: null`. Pass the persisted `AGENT_USER_ID` to `session provision`.
     `activate` works as soon as the key is registered, because `activate` authenticates with the new key.
   - *Rejected mint or stale request*: the agent's request stays pending locally; after a
     rejection the provisioner's rerun finds no registered key and submits a new activity for
     the same public key. Have the human approve that activity, or on the agent host run
     `tk --message-format json session request --profile-name agent --replace` to discard
     the keypair (its generated file is removed) and redo step 5.
   - *Concurrent renewal*: one writer per profile. A second `session request` while one is
     pending fails `invalid_input` naming the pending public key; never `--replace` from a second process.

7. **Hand off.** Report `AGENT_USER_ID`, `AGENT_TAG`, and the agent's profile name and host;
   `PROVISIONER_USER_ID`, `PROVISIONER_TAG`, and the provisioner's profile name and host; the
   minting row in force; each policy's name and id; the current key's `data.expiresAt` from
   `session status`; the step-5 results from the real users, which are the acceptance; any mint
   activity id still awaiting approval; and the exact step-5 commands each host runs and the agent
   host's timer interval. The capability workflows start from this identity:
   [managing-secrets](../managing-secrets/SKILL.md) for exports,
   [signing-git-commits](../signing-git-commits/SKILL.md) for commit signing,
   and [using-ssh](../using-ssh/SKILL.md) for SSH. Stop.

## Verified by

| Examples | Test |
|---|---|
| session.profile-create, session.user-create, session.provisioner-create, session.policy-mint, session.policy-self-deny, session.login, session.status, session.request, session.provision, session.activate | sessions::provisioning_session_agent_human_mint_human_export |
| session.provision, session.activate | sessions::provisioning_session_agent_human_mint_unilateral_export |
| session.provision, session.activate | sessions::provisioning_session_agent_unilateral_mint_human_export |
| session.provision, session.activate | sessions::provisioning_session_agent_unilateral_mint_unilateral_export |
| session.policy-mint, session.policy-self-deny, session.provision | sessions::provisioning_session_agent_provisioner_cannot_self_mint |
| session.policy-mint | sessions::provisioning_session_agent_unpinned_allow_leaves_self_mint_pending |
| session.policy-mint, session.provision | sessions::provisioning_session_agent_mint_allow_caps_key_lifetime |
| session.request, session.provision, session.activate | sessions::provisioning_session_agent_recovers_after_expiry |
| session.status, session.request, session.activate | sessions::session_loop_rotates_an_agent_profile_and_reports_status |

## Troubleshooting

- `session request` fails `invalid_input` "already pending": activate it, or
  `--replace` if that key was never registered. "Unknown profile": do step 1.
- `session activate` fails `unauthorized`: the key is not registered yet.
  `activity get` the provision activity, approve or wait, rerun `activate`;
  the profile is unchanged until it succeeds.
- `session status` exits `1` `session_expiring`: run step 5; firing every
  run means the window exceeds the lifetime.
- `session provision` fails `unauthorized` 403: no ALLOW selects this
  provisioner for this target, `--expires-in` exceeds the mint ALLOW's
  lifetime cap, or the self DENY fired. Inspect with
  `policy evaluations` when an activity id exists. Do not widen the
  condition to every user; do not use root.

## Related Skills

- [bootstrapping-organization](../bootstrapping-organization/SKILL.md): the tags and approval model this assumes.
- [provisioning-agent-identity](../provisioning-agent-identity/SKILL.md): the long-lived alternative when nobody can approve renewals.
- [monitoring-activities](../monitoring-activities/SKILL.md): approve, reject, or wait on a pending mint.
- [sidecar-patterns](../sidecar-patterns/SKILL.md): where the renewal loop runs and how its alert reaches an operator.
- [revoking-agent-keys](../revoking-agent-keys/SKILL.md): cut off a session key before it expires.
