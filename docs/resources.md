# Resources

Manage users, policies, API keys, wallets, and private keys. Create and
update commands take the request's parameters object as `--input-json JSON`
or `--input-file PATH` (`-` for stdin), without organization ID or activity
envelope.

Follow [authentication](./authentication.md) first.

## Users

```bash
tk user list
# Keep only the users carrying a tag, named by tag name or tag id.
tk user list --tag agents
tk user get --id USER_ID
tk user create --input-json '{"users": [{
  "userName": "agent",
  "apiKeys": [{"apiKeyName": "agent-key", "publicKey": "02…", "curveType": "API_KEY_CURVE_P256"}],
  "authenticators": [], "oauthProviders": [], "userTags": []
}]}'
tk user update --input-file ./user-update.json
tk user delete --id USER_ID

tk user tag list
tk user tag create --input-json '{"userTagName": "agents", "userIds": []}'
tk user tag update --input-file ./tag-update.json
tk user tag delete --id TAG_ID
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
tk policy get --id POLICY_ID
tk policy create --input-file - <<EOF
{
  "policyName": "agents-sign-only",
  "effect": "EFFECT_ALLOW",
  "condition": "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == '${WALLET_ID}'",
  "consensus": "approvers.any(user, user.id == '${USER_ID}')",
  "notes": "the agent user may sign with one wallet"
}
EOF
tk policy create-batch --input-file ./policies.json
tk policy update --input-json '{"policyId": "POLICY_ID", "policyNotes": "revised"}'
tk policy delete --id POLICY_ID

# See how policies evaluated an activity.
tk policy evaluations --activity-id ACTIVITY_ID
```

Flags cover the single-policy case:

```bash
tk policy create --name agents-export --effect allow \
  --consensus "approvers.any(user, user.tags.contains('${TAG_ID}'))" \
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
tk api-key delete --user-id USER_ID --id API_KEY_ID
```

## Wallets

```bash
tk wallet list
tk wallet get --id WALLET_ID
# Create a wallet with one Ethereum and one Solana account; the curve is inferred and the path
# is the conventional one for the format. Without --account the wallet has no accounts.
tk wallet create --name treasury --account ethereum --account solana
# Raw parameters, for anything the flags cannot express.
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
# Add the next unused conventional account for the format; the curve is inferred.
tk wallet account create --wallet-id WALLET_ID --address-format ethereum
# Pin the path instead of predicting it.
tk wallet account create --wallet-id WALLET_ID --address-format ethereum --path "m/44'/60'/5'/0/0"
tk wallet account create --input-file ./accounts.json
```

Without `--path`, `wallet account create` lists the wallet's accounts and picks
the lowest index whose conventional path no account of the same address format
uses. The conventional paths are `m/44'/60'/N'/0/0` for `ethereum`,
`m/44'/118'/N'/0/0` for `cosmos`, `m/44'/501'/N'/0'` for `solana`, and `m/N'`
for `compressed` and `uncompressed`. Other formats need `--path`. The curve is inferred as `CURVE_SECP256K1` for
`ethereum`, `cosmos`, and `uncompressed`, `CURVE_ED25519` for `solana`, and
needs `--curve` otherwise. The lookup and the creation are two requests, so concurrent creations can pick the
same path. Enum flags take the API names, such as `ADDRESS_FORMAT_ETHEREUM`,
case-insensitively and with or without the prefix. Flags and
`--input-json`/`--input-file` are mutually exclusive.

A command that needs approval exits zero with status `pending` and an
activity ID; see [activities](./activities.md).

## Private keys

```bash
tk private-key list
tk private-key get --id PRIVATE_KEY_ID
# Create one key from flags.
tk private-key create --name treasury --curve secp256k1 --address-format ethereum
# Create several keys from one parameters object.
tk private-key create --input-json '{"privateKeys": [{"privateKeyName": "ops", "curve": "CURVE_ED25519"}]}'
```

## Skills

- [bootstrapping-organization](../skills/bootstrapping-organization/SKILL.md): the three tags and the tagged approver.
- [managing-identities](../skills/managing-identities/SKILL.md): users, tags, key rotation, and revocation as one procedure.
- [managing-policies](../skills/managing-policies/SKILL.md): writing, testing, and debugging policies.
- [provisioning-agent-identity](../skills/provisioning-agent-identity/SKILL.md): the tagged long-lived agent user and the credential DENY that fences it.
- [managing-secrets](../skills/managing-secrets/SKILL.md): the export policies per approval column and per isolation scope.
- [inspecting-agents](../skills/inspecting-agents/SKILL.md): answering who carries a tag and which keys each user holds.
- [revoking-agent-keys](../skills/revoking-agent-keys/SKILL.md): deleting an agent's key early through a scoped revoker user.
- [provisioning-session-agent](../skills/provisioning-session-agent/SKILL.md): the agent, provisioner, and containment policies for expiring keys.
- [using-ssh](../skills/using-ssh/SKILL.md): the allow-always policy scoped to the Ed25519 key an agent serves over SSH.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the empty wallet and the allow-always policies scoped to a signing wallet or private key.
- [deploying-signing-broker](../skills/deploying-signing-broker/SKILL.md): the broker user's scoped signing ALLOW and the broker tag's credential DENY.
