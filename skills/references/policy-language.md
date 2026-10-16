# Policy language for `tk` workflows

The subset of Turnkey's policy language these workflows write: who may act
(`consensus`) and on what (`condition`), for users, credentials, policies,
secrets, and the raw-payload signing that SSH and OpenPGP use. Chain-specific
namespaces (`eth.tx`, `solana.tx`, and the rest) are out of scope here.

## Contents

- [Evaluation](#evaluation)
- [Grammar](#grammar)
- [Consensus keywords](#consensus-keywords)
- [Condition keywords](#condition-keywords)
- [Activity types used here](#activity-types-used-here)
- [Defaults that surprise](#defaults-that-surprise)

## Evaluation

A policy has an `effect` (`EFFECT_ALLOW` or `EFFECT_DENY`), an optional
`condition` evaluated against the activity, and an optional `consensus`
evaluated against the approvers. An omitted expression is true. For a non-root
submitter, an activity is allowed only if some ALLOW matches and no DENY
matches. A satisfied root quorum bypasses policies, which is why every agent
and provisioner is a non-root user and every policy is tested from a non-root
credential.

The submitter's own vote counts toward `consensus`. When `consensus` also
names a second party, the activity enters `ACTIVITY_STATUS_CONSENSUS_NEEDED`
and `tk` reports `status: "pending"`; each further approval is one
`tk activity approve`. When no clause of `consensus` is satisfiable by the
submitter, the ALLOW never fires at submission and the request is denied
rather than left pending.

## Grammar

| Operation | Operators | Example |
|---|---|---|
| logical | `&&`, `\|\|` | `a && b` |
| comparison | `==`, `!=`, `<`, `>`, `<=`, `>=` | `activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'` |
| membership | `in` | `activity.resource in ['USER', 'POLICY']` |
| negation | `!` | `!(activity.kind in ['SIGN_RAW_PAYLOAD'])` |
| field access | `x.field`, `x['key']` | `secret.static_properties['consensus']` |
| list functions | `any(item, pred)`, `all(item, pred)`, `contains(v)`, `filter(item, pred)`, `count()` | `approvers.filter(user, user.tags.contains('${TAG_ID}')).count() >= 2` |

`!` binds tighter than `&&` and `||`, so wrap what it negates in
parentheses: `!(x in [...])`, not `!x in [...]`. Strings use single quotes. Ids compare as strings. Property values are
strings end to end: write `secret.static_properties['consensus'] == 'approval'`,
never a bare boolean.

## Consensus keywords

| Keyword | Type | Fields |
|---|---|---|
| `approvers` | list of users who have approved | `id`, `tags` (list of tag UUIDs), `email`, `alias` |
| `credentials` | list of credentials used to approve | `id`, `user_id`, `type`, `public_key` |

`user.tags` holds tag UUIDs. Tag names are never policy-visible.

## Condition keywords

| Keyword | Fields used here |
|---|---|
| `activity` | `type` (full `ACTIVITY_TYPE_*` name), `resource` (`USER`, `CREDENTIAL`, `POLICY`, `SECRET`, `PRIVATE_KEY`, `WALLET`, `ORGANIZATION`, and others), `action` (`CREATE`, `UPDATE`, `DELETE`, `EXPORT`, `IMPORT`, `SIGN`), `params` |
| `activity.params` | for `ACTIVITY_TYPE_CREATE_API_KEYS_V2`: `user_id` of the target user, as a string, and `api_keys`, one entry per key with `expiration_seconds` (integer); for `ACTIVITY_TYPE_DELETE_API_KEYS`: `user_id` and `api_key_ids` (list of strings). The target's tags are not exposed |
| `secret` | `static_properties['KEY']` on `ACTIVITY_TYPE_EXPORT_SECRETS` only; deletion does not load properties |
| `wallet` | `id` |
| `private_key` | `id`, `tags` |
| `wallet_account` | `address` |

All signing, including the raw-payload signatures behind `tk ssh` and
`tk gpg`, is resource `PRIVATE_KEY` with `action == 'SIGN'`.

## Activity types used here

| Command | `activity.type` | `activity.resource` |
|---|---|---|
| `tk user create` | `ACTIVITY_TYPE_CREATE_USERS_V4` | `USER` |
| `tk user update` | `ACTIVITY_TYPE_UPDATE_USER` | `USER` |
| `tk user delete` | `ACTIVITY_TYPE_DELETE_USERS` | `USER` |
| `tk user tag create` | `ACTIVITY_TYPE_CREATE_USER_TAG` | `USER` |
| `tk api-key register`, `tk session provision` | `ACTIVITY_TYPE_CREATE_API_KEYS_V2` | `CREDENTIAL` |
| `tk api-key delete` | `ACTIVITY_TYPE_DELETE_API_KEYS` | `CREDENTIAL` |
| `tk policy create` | `ACTIVITY_TYPE_CREATE_POLICY_V3` | `POLICY` |
| `tk policy update` | `ACTIVITY_TYPE_UPDATE_POLICY_V2` | `POLICY` |
| `tk policy delete` | `ACTIVITY_TYPE_DELETE_POLICY`, `ACTIVITY_TYPE_DELETE_POLICIES` | `POLICY` |
| `tk secret import` | `ACTIVITY_TYPE_IMPORT_SECRETS` | `SECRET` |
| `tk secret export`, `tk secret env` | `ACTIVITY_TYPE_EXPORT_SECRETS` | `SECRET` |
| `tk secret delete` | `ACTIVITY_TYPE_DELETE_SECRETS` | `SECRET` |
| `tk ssh agent`, `tk gpg sign`, `tk sign payload` | `ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2` | `PRIVATE_KEY` |

## Defaults that surprise

- **Self-targeted credential changes default-allow.** When no policy decides,
  a user may create or delete its own API keys and authenticators. An ALLOW
  scoped to other targets does not close this; only a DENY on
  `activity.resource == 'CREDENTIAL'` for the agent tag does. Provisioners
  need the same DENY outside their exact target set.
- **A key without expiration has the largest lifetime.** A missing
  `expiration_seconds` reads as the maximum, so
  `activity.params.api_keys.all(k, k.expiration_seconds <= 604800)` also
  rejects keys that never expire. Use `all` in an ALLOW and `any` with `>` in
  a DENY; one request can register several keys.
- **Sessions cannot be minted for another user.** Read/write session
  activities always target the proposer. Cross-user expiring credentials use
  `CREATE_API_KEYS_V2`, which is what `tk session provision` submits.
- **Every user needs one persistent authenticator.** A user whose only
  credentials are expiring API keys is rejected. `--anchor-key` on
  `tk user create` registers a never-expiring key whose private half is discarded.
- **No short-circuiting across resource types.** A condition that reads
  `wallet.id` errors when the activity targets a private key. Write one policy
  per resource type.
