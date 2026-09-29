---
name: inspecting-agents
description: Answer operational questions about an organization's Turnkey agents with tk list filters, explicit pagination, and jq: what is pending and for how long, who voted, which users carry a tag, which keys each agent holds and when they expire, which secrets carry which properties, which policies mention a tag or user, who minted a key. Use for audits and "what is the state of X" questions; not for changing anything.
---

# Inspecting agents

Result: a read-only report that answers each question with the command that
produced it and the field the answer came from. Nothing is created, voted
on, or deleted.

Each question below is one `tk` list narrowed by its filter flags plus a
`jq` projection; `jq` selects only where no flag exists (the tag-id search
over policies, the public-key join that attributes a mint). Each answer
states its provenance: the command, the pages read, and the field.

## Reference

- [resources](../../docs/resources.md): `user list` tag filtering, `user tag` records, `api-key list` owner selection and expiry modes, and `policy` records.
- [activities](../../docs/activities.md): `activity list` filtering and paging, and `activity get`.
- [secrets](../../docs/secrets.md): `secret list` filtering.

## Rules

- Read only. Approving, rejecting, or waiting on what you find belongs to
  [monitoring-activities](../monitoring-activities/SKILL.md).
- Page to the end before answering "none". `activity list` pages with
  `--limit` and `--cursor`; a page is the last one when `data.nextCursor` is
  `null`. A filtered `secret list` pages the same way; see
  [secrets](../../docs/secrets.md). `user list`,
  `user tag list`, `policy list`, and `api-key list` return everything in one
  response.
- `user list --tag` takes a tag name or id. Policy text carries tag ids, not
  names, so step 7 resolves the name once with `user tag list`.
- `expiresAt` on an API key is a Unix-millisecond string, or `null` for a
  key that never expires. On the session route the anchor is the only
  permanent key an agent should hold; on the long-lived route the one
  runtime key is permanent.
- Who minted a key is a join, never a guess: the key's
  `credential.publicKey` against the `publicKey` inside an activity's
  `intent` (`createApiKeysIntentV2.apiKeys[]` or
  `createUsersIntentV4.users[].apiKeys[]`). When no activity in the pages
  you traversed matches, the answer is "unknown". Do not infer a minter from
  voters on other activities.
- A textual search of policy `consensus` and `condition` for a tag id or
  user id is a candidate list, not a parsed dependency graph. Read each
  candidate before claiming it governs the tag or user.

## Instructions

Inputs: any profile in the organization (`admin` below), and the tag names
or ids the question is about. Every command below prints one JSON record;
`jq` selects from it.

1. **Resolve tag ids.**

   <!-- example: inspecting.tags -->
   ```sh
   tk --profile admin --message-format json user tag list | jq -r '.data.userTags[] | "\(.tagId) \(.tagName)"'
   AGENT_TAG=$(tk --profile admin --message-format json user tag list | jq -r '.data.userTags[] | select(.tagName == "agent") | .tagId')
   ```

   `data.userTags[]` carries `tagId`, `tagName`, and `userIds`. Step 7 uses
   `$AGENT_TAG`; step 2 takes the name directly. A name that matches nothing
   leaves the variable empty; stop and report that, do not fall back to a
   substring match.

2. **Which users carry a tag.**

   <!-- example: inspecting.tagged-users -->
   ```sh
   tk --profile admin --message-format json user list --tag agent | jq '.data.users[] | {userId, userName}'
   ```

   The list is complete in one response.

3. **Which keys an agent holds and when they expire.**

   <!-- example: inspecting.keys -->
   ```sh
   tk --profile admin --message-format json api-key list --user-id AGENT_USER_ID | jq '.data.apiKeys[] | {apiKeyId, apiKeyName, publicKey: .credential.publicKey, expiresAt}'
   tk --profile admin --message-format json api-key list --all-users --long-lived | jq -r '.data.apiKeys[] | "\(.userId) \(.apiKeyId)"'
   tk --profile admin --message-format json api-key list --all-users --expiring-within 24h | jq -r '.data.apiKeys[] | "\(.userId) \(.apiKeyId) \(.expiresAt)"'
   ```

   The first command reads one user from step 2. The second lists every
   permanent key by owner: a session-route agent should own exactly one, its
   anchor; more than one is a finding. The third lists keys that expire
   within the window; see [resources](../../docs/resources.md) for the
   expiry modes.

4. **What is pending and for how long.**

   <!-- example: inspecting.pending -->
   ```sh
   tk --profile admin --message-format json activity list --status pending --limit 50 | jq --arg now "$(date +%s)" '.data.items[] | {id, type, status, ageSeconds: (($now | tonumber) - (.createdAt.seconds | tonumber))}'
   ```

   `data.items[]` is one page, newest first; `createdAt.seconds` is a
   Unix-second string. Continue with the cursor until it prints `null`:

   <!-- example: inspecting.next-page -->
   ```sh
   NEXT_ACTIVITY_ID=$(tk --profile admin --message-format json activity list --status pending --limit 50 | jq -r '.data.nextCursor')
   tk --profile admin --message-format json activity list --status pending --limit 50 --cursor $NEXT_ACTIVITY_ID | jq -r '.data.nextCursor'
   ```

   Concatenate the pages. A pending activity appears on exactly one page.

5. **Who voted on an activity.**

   <!-- example: inspecting.votes -->
   ```sh
   tk --profile admin --message-format json activity get ACTIVITY_ID | jq '.data.activity.votes[] | {userId, selection}'
   ```

   `selection` is `VOTE_SELECTION_APPROVED` or `VOTE_SELECTION_REJECTED`.
   The submitter's own approval is the first vote; the missing approver is
   whoever the policy consensus names and this list does not.

6. **Which secrets carry which properties.**

   <!-- example: inspecting.secrets -->
   ```sh
   tk --profile admin --message-format json secret list --property env=prod | jq '.data.secrets[] | {name, properties: (.staticProperties | map("\(.key)=\(.value)"))}'
   tk --profile admin --message-format json secret list --name-prefix service/ --property env=prod | jq -r '.data.secrets[].name'
   ```

   `staticProperties[]` is `key` and `value`; values of the secrets
   themselves are never listed.

7. **Which policies mention a tag or user.** Take the agent's `userId` from
   step 2 into `$AGENT_USER_ID`; signing grants name the user, not the tag:

   <!-- example: inspecting.policies -->
   ```sh
   tk --profile admin --message-format json policy list | jq --arg tag "$AGENT_TAG" --arg user "$AGENT_USER_ID" '.data.policies[] | select((.consensus // "") + (.condition // "") | contains($tag) or contains($user)) | {policyId, policyName, effect}'
   ```

   These are candidates. Read each one's `consensus` and `condition` to say
   whether the tag or user is an approver, a target, or both. An empty
   `$AGENT_TAG` or `$AGENT_USER_ID` matches every policy; set both first.

8. **Who minted a key.** Take the key's `credential.publicKey` from step 3
   into `$KEY_PUBLIC_KEY`, then join it against each page of the activities
   that can mint one:

   <!-- example: inspecting.minted-by -->
   ```sh
   tk --profile admin --message-format json activity list --type 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' --type 'ACTIVITY_TYPE_CREATE_USERS_V4' --limit 50 | jq --arg pk "$KEY_PUBLIC_KEY" '.data.items[] | select(any(.intent.createApiKeysIntentV2.apiKeys[]?, .intent.createUsersIntentV4.users[]?.apiKeys[]?; .publicKey == $pk)) | {id, type, status, minted: .createdAt.seconds, voters: [.votes[].userId]}'
   ```

   Page as in step 4, keeping both `--type` flags on every page; add
   `--since 7d` when the key is known to be recent. One match gives the
   activity and its voters, the first of which submitted it. No match across
   every page is "unknown". Empty output on the first page alone proves
   nothing.

9. **Hand off.** One line per question: the answer, the command, the pages
   read (`1 of 1`, `3 of 3`), and the field it came from. Pending ids,
   permanent-key findings, and "unknown" minters are listed explicitly.
   Stop.

## Verified by

| Examples | Test |
|---|---|
| inspecting.tags, inspecting.tagged-users, inspecting.keys, inspecting.pending, inspecting.next-page, inspecting.votes, inspecting.secrets, inspecting.policies, inspecting.minted-by | users::inspecting_agents_jq_recipes_answer_live_records |

## Troubleshooting

- `jq: command not found`: install `jq`; every recipe here projects fields
  from the JSON record with it. Nothing in `tk` depends on it.
- `user list --tag`, `user get`, or `api-key list` fails with `not_found`:
  the tag name or user id belongs to another organization or was mistyped.
  Check `--profile` and the id from step 2.
- Step 1 leaves `$AGENT_TAG` empty: the tag name is different in this
  organization. Read the full `user tag list` output and pick the id by
  hand; do not guess from a similar name.
- A page has zero items but the previous page had a cursor: the previous
  page was exactly `--limit` long. That empty page is the end.
- `activity list --status pending` shows nothing but a command reported
  `pending`: the vote may have landed since. `activity get ACTIVITY_ID`
  shows the current status of that one activity.
- Step 8 finds no match: widen the traversal to every page, and drop
  `--since` if you added it, before saying "unknown"; an activity older than
  the pages read is not evidence of anything.

## Related Skills

- [monitoring-activities](../monitoring-activities/SKILL.md): approve, reject,
  or wait on what step 4 found.
- [managing-identities](../managing-identities/SKILL.md): rotate or revoke a
  key that step 3 flagged.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): the
  expiring keys and anchor that step 3 reads.
- [managing-policies](../managing-policies/SKILL.md): read or change the
  policies step 7 listed.
