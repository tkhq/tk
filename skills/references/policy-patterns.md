# Policy patterns for agents

Fleet policies here reference **user tags** and **secret static properties**,
so adding an agent is a user create plus a tag and adding a secret is one
import. Per-agent resources — signing keys — and the other places that must
name ids are noted where they appear. Read
[policy-language.md](policy-language.md) for the grammar and
[approval-models.md](approval-models.md) to choose which of these to apply.

## Contents

- [Tags and properties](#tags-and-properties)
- [Consensus shapes](#consensus-shapes)
- [Agent export policies](#agent-export-policies)
- [Credential containment](#credential-containment)
- [Provisioner policies](#provisioner-policies)
- [Signing-key policies](#signing-key-policies)
- [Isolation boundaries](#isolation-boundaries)
- [Anti-patterns](#anti-patterns)

## Tags and properties

Three disjoint user tags, created once:

| Tag | Holders |
|---|---|
| `agent` | non-root users that act unattended |
| `provisioner` | non-root users that propose expiring keys for agents |
| `human-approver` | the people who approve `allow-once` activities |

A user carries at most one of these. A root user may hold `human-approver`;
its approval then also satisfies the root quorum, so test consensus with a
non-root approver.

Secrets carry a `consensus` static property and are named `<scope>/<VAR>`:

| Property | Meaning |
|---|---|
| `consensus=unilateral` | an `agent` may export it alone |
| `consensus=approval` | export also needs a `human-approver` vote |

Properties are immutable. Changing a secret's level is a delete plus a
re-import under the same name; see the secrets workflow.

## Consensus shapes

| Pattern | `consensus` |
|---|---|
| allow-always | `approvers.any(user, user.tags.contains('AGENT_TAG'))`; a [signing-key policy](#signing-key-policies) names `user.id` instead |
| allow-once | `approvers.any(user, user.tags.contains('AGENT_TAG')) && approvers.any(user, user.tags.contains('HUMAN_APPROVER_TAG'))` |

Approval is per activity. The agent's submission counts as its own vote; the
human approves once, from the console, the mobile app, or
`tk activity approve`.

## Agent export policies

<!-- example: policy-patterns.agents-export-unilateral -->
```sh
tk --profile admin --message-format json policy create --name agents-export-unilateral --effect allow \
  --consensus "approvers.any(user, user.tags.contains('AGENT_TAG'))" \
  --condition "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == 'unilateral'"
```

<!-- example: policy-patterns.agents-export-with-approval -->
```sh
tk --profile admin --message-format json policy create --name agents-export-with-approval --effect allow \
  --consensus "approvers.any(user, user.tags.contains('AGENT_TAG')) && approvers.any(user, user.tags.contains('HUMAN_APPROVER_TAG'))" \
  --condition "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == 'approval'"
```

## Credential containment

Without this DENY an agent holding a seven-day key could register itself a
permanent one, because self-targeted credential changes default-allow.

<!-- shared: agents-no-credentials -->
<!-- example: policy-patterns.agents-no-credentials -->
```sh
tk --profile admin --message-format json policy create --name agents-no-credentials --effect deny \
  --consensus "approvers.any(user, user.tags.contains('AGENT_TAG'))" \
  --condition "activity.resource == 'CREDENTIAL'"
```

## Provisioner policies

A provisioner may do one thing: register expiring keys on an explicit set of
agent users. The target set is the one place an id list is unavoidable,
because the target's tags are not policy-visible.

<!-- shared: provisioners-mint-agent-keys -->
<!-- example: policy-patterns.provisioners-mint-agent-keys -->
```sh
tk --profile admin --message-format json policy create --name provisioners-mint-agent-keys --effect allow \
  --consensus "approvers.any(user, user.tags.contains('PROVISIONER_TAG')) && approvers.any(user, user.tags.contains('HUMAN_APPROVER_TAG'))" \
  --condition "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id in ['AGENT_USER_ID']"
```

Drop the `HUMAN_APPROVER_TAG` clause for the unilateral minting row of the
approval matrix; then a trusted provisioner service, not a policy, enforces
the lifetime.

<!-- example: policy-patterns.provisioners-nothing-else -->
```sh
tk --profile admin --message-format json policy create --name provisioners-nothing-else --effect deny \
  --consensus "approvers.any(user, user.tags.contains('PROVISIONER_TAG'))" \
  --condition "activity.type != 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'"
```

<!-- shared: provisioners-no-self-keys -->
<!-- example: policy-patterns.provisioners-no-self-keys -->
```sh
tk --profile admin --message-format json policy create --name provisioners-no-self-keys --effect deny \
  --consensus "approvers.any(user, user.tags.contains('PROVISIONER_TAG'))" \
  --condition "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id == 'PROVISIONER_USER_ID'"
```

Containment is the pair: the pinned ALLOW leaves a key proposed on another
provisioner or a root user with no matching policy, and the self DENY closes
the one target the default-allow fallback would otherwise rescue. Create one
self DENY per provisioner user. The language has no negation, so a single
"not in the set" DENY cannot be written.

## Signing-key policies

An agent that pushes over SSH or signs commits holds no key material. The
SSH key is a Turnkey private key served by `tk ssh agent`; the OpenPGP key is a
wallet account signed through `tk gpg`. Scope by the exact resource, and name
the one user that serves the key in the consensus: a tag consensus would let
every tagged agent sign with it. A fleet gets one key and one policy per
agent. These are allow-always by necessity: Git and SSH wait for a signature
synchronously, so an approval-gated variant needs a different design.

<!-- shared: agents-sign-ssh -->
<!-- example: policy-patterns.agents-sign-ssh -->
```sh
tk --profile admin --message-format json policy create --name agents-sign-ssh --effect allow \
  --consensus "approvers.any(user, user.id == 'AGENT_USER_ID')" \
  --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && private_key.id == 'PRIVATE_KEY_ID'"
```

<!-- shared: agents-sign-gpg -->
<!-- example: policy-patterns.agents-sign-gpg -->
```sh
tk --profile admin --message-format json policy create --name agents-sign-gpg --effect allow \
  --consensus "approvers.any(user, user.id == 'AGENT_USER_ID')" \
  --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == 'WALLET_ID'"
```

A signing broker that serves the key over a socket to a credential-free
application is its own principal: a broker user named in this ALLOW, a
`broker` tag with the credential DENY above, no export ALLOW, and no `agent`
ALLOW on its wallet.

<!-- shared: brokers-sign-gpg -->
<!-- example: policy-patterns.brokers-sign-gpg -->
```sh
tk --profile admin --message-format json policy create --name brokers-sign-gpg --effect allow \
  --consensus "approvers.any(user, user.id == 'BROKER_USER_ID')" \
  --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == 'WALLET_ID'"
```

## Isolation boundaries

An approval level alone grants every `agent` the same access. When two agents
must not read each other's secrets, give each its own tag and its own scope
property, and write the export policies per pair:
`user.tags.contains('BILLING_AGENT_TAG')` with
`secret.static_properties['scope'] == 'billing'`. The `--name-prefix` of
`tk secret env` is selection, not authorization. Add a
cross-agent denial to the acceptance test of any multi-agent organization.

## Anti-patterns

<!-- negative-example -->
```json
{
  "policyName": "agents-sign-anything",
  "effect": "EFFECT_ALLOW",
  "consensus": "approvers.any(user, user.id == 'AGENT_USER_ID')",
  "condition": "activity.action == 'SIGN'"
}
```

No resource scope: the agent may sign with every key in the organization.

<!-- negative-example -->
```json
{
  "policyName": "agents-anything",
  "effect": "EFFECT_ALLOW",
  "consensus": "approvers.any(user, user.tags.contains('AGENT_TAG'))"
}
```

No condition: the agent may create users, change policies, and delete
wallets.

<!-- negative-example -->
```json
{
  "policyName": "provisioners-mint-any-key",
  "effect": "EFFECT_ALLOW",
  "consensus": "approvers.any(user, user.tags.contains('PROVISIONER_TAG')) && approvers.any(user, user.tags.contains('HUMAN_APPROVER_TAG'))",
  "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'"
}
```

<!-- negative-example -->
```json
{
  "policyName": "provisioners-no-self-keys",
  "effect": "EFFECT_DENY",
  "consensus": "approvers.any(user, user.tags.contains('PROVISIONER_TAG'))",
  "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id == 'PROVISIONER_USER_ID'"
}
```

A self DENY beside a broad ALLOW on `ACTIVITY_TYPE_CREATE_API_KEYS_V2`: the
provisioner may still mint for another provisioner or a root user, and a human
sees only a pending request. Pin the ALLOW to the agent target set.
