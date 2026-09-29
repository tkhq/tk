# Resources

Manage users, policies, API keys, and wallets. Create and update commands
take the request's parameters object as `--input-json JSON` or
`--input-file PATH` (`-` for stdin), without organization ID or activity
envelope.

Follow [authentication](./authentication.md) first.

## Users

```bash
tk user list
# Keep only the users carrying a tag, named by tag name or tag id.
tk user list --tag agents
tk user get USER_ID
tk user create --input-json '{"users": [{
  "userName": "agent",
  "apiKeys": [{"apiKeyName": "agent-key", "publicKey": "02…", "curveType": "API_KEY_CURVE_P256"}],
  "authenticators": [], "oauthProviders": [], "userTags": []
}]}'
tk user update --input-file ./user-update.json
tk user delete USER_ID

tk user tag list
tk user tag create --input-json '{"userTagName": "agents", "userIds": []}'
tk user tag update --input-file ./tag-update.json
tk user tag delete TAG_ID
```

Flags cover the single-user case; `--tag-name` must match exactly one tag:

```bash
tk user tag create --name agents
tk user create --user-name agent --tag-name agents --public-key 02… --expires-in 7d --anchor-key
```

Turnkey requires every user to hold one long-lived credential, so a user meant
to live on expiring keys needs `--anchor-key`: it registers a never-expiring key
whose private half is generated locally and discarded.

## Policies

```bash
tk policy list
tk policy get POLICY_ID
tk policy create --input-file - <<'EOF'
{
  "policyName": "agents-sign-only",
  "effect": "EFFECT_ALLOW",
  "condition": "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == 'WALLET_ID'",
  "consensus": "approvers.any(user, user.id == 'USER_ID')",
  "notes": "the agent user may sign with one wallet"
}
EOF
tk policy create-batch --input-file ./policies.json
tk policy update --input-json '{"policyId": "POLICY_ID", "policyNotes": "revised"}'
tk policy delete POLICY_ID

# See how policies evaluated an activity.
tk policy evaluations ACTIVITY_ID
```

Flags cover the single-policy case:

```bash
tk policy create --name agents-export --effect allow \
  --consensus "approvers.any(user, user.tags.contains('TAG_ID'))" \
  --condition "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS'"
```

Updates use `policyEffect`, `policyCondition`, `policyConsensus`, and
`policyNotes`.

## API keys

```bash
# Exactly one owner selector: this user's keys, or every user's keys.
tk api-key list --user-id USER_ID
tk api-key list --all-users
# One expiry mode at a time. Keys whose expiresAt is at most 7 days ahead, including already-expired keys.
tk api-key list --user-id USER_ID --expiring-within 7d
# Keys whose expiresAt has passed.
tk api-key list --all-users --expired
# Keys with no expiry.
tk api-key list --user-id USER_ID --long-lived
tk api-key register --input-json '{
  "userId": "USER_ID",
  "apiKeys": [{"apiKeyName": "ci", "publicKey": "02…", "curveType": "API_KEY_CURVE_P256"}]
}'
tk api-key delete --user-id USER_ID API_KEY_ID
```

## Wallets

```bash
tk wallet list
tk wallet get WALLET_ID
tk wallet create --input-file - <<'EOF'
{"walletName": "treasury", "accounts": [{
  "curve": "CURVE_SECP256K1",
  "pathFormat": "PATH_FORMAT_BIP32",
  "path": "m/44'/60'/0'/0/0",
  "addressFormat": "ADDRESS_FORMAT_ETHEREUM"
}]}
EOF
tk wallet update --input-json '{"walletId": "WALLET_ID", "walletName": "ops"}'

tk wallet account list --wallet-id WALLET_ID --limit 50
tk wallet account list --wallet-id WALLET_ID --cursor ACCOUNT_ID
tk wallet account create --input-file ./accounts.json
```

A command that needs approval exits zero with status `pending` and an
activity ID; see [activities](./activities.md).

## Skills

- [bootstrapping-organization](../skills/bootstrapping-organization/SKILL.md): the three tags and the tagged approver.
- [managing-identities](../skills/managing-identities/SKILL.md): users, tags, key rotation, and revocation as one procedure.
- [managing-policies](../skills/managing-policies/SKILL.md): writing, testing, and debugging policies.
- [provisioning-agent-identity](../skills/provisioning-agent-identity/SKILL.md): the long-lived agent user and the export policies that fence it.
- [inspecting-agents](../skills/inspecting-agents/SKILL.md): answering who carries a tag and which keys each user holds.
- [provisioning-session-agent](../skills/provisioning-session-agent/SKILL.md): the agent, provisioner, and containment policies for expiring keys.
- [using-ssh](../skills/using-ssh/SKILL.md): the allow-always policy scoped to the Ed25519 key an agent serves over SSH.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the empty wallet and the allow-always policies scoped to a signing wallet or private key.
- [deploying-signing-broker](../skills/deploying-signing-broker/SKILL.md): the broker user's scoped signing ALLOW and the broker tag's credential DENY.
