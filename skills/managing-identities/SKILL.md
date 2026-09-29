---
name: managing-identities
description: Create, tag, rotate, and revoke Turnkey users and API keys with tk, and manage the local profiles that hold their credentials. Use to add a non-root user, attach a tag, register or delete an API key, switch a profile to a new key, or remove a user; not for expiring session keys, which have their own workflow.
---

# Managing identities

Users, tags, registered API keys, and the local profiles that hold private
keys are one workflow because a rotation touches all four. Flag forms come
first; `--input-json` is the escape hatch for fields the flags do not cover.

## Reference

- [resources](../../docs/resources.md): `user`, `user tag`, and `api-key` records and JSON parameter shapes.
- [authentication](../../docs/authentication.md): profiles and credential files.

## Rules

- Register public keys only. A private key is generated where it will be
  used and never crosses a transcript or a command argument.
- A constrained user stays non-root. Root quorum membership is a separate
  organization setting; never grant it to make a denial go away.
- Preserve access until the replacement is verified: rotate by registering,
  verifying with `whoami`, then deleting the old key.
- Deleting a local profile forgets a file path. It revokes nothing.

## Instructions

Inputs: the acting root profile (`admin`), the target user's name or id, and
for a new key the machine that will hold it.

### Create a user

1. **Generate the credential where the user will run.** On that machine,
   with no profile yet:

   <!-- example: identities.profile-create -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name agent
   ```

   Save `data.publicKey` as `PUBLIC_KEY`. The file path is in
   `data.profile.api_key_file`.

2. **Create the user with its tag and key.** Root.

   <!-- example: identities.user-create -->
   ```sh
   tk --profile admin --message-format json user create --user-name agent --tag-name agent --public-key PUBLIC_KEY
   ```

   `--tag-name` resolves against the organization's tags and must match
   exactly one; pass `--tag TAG_ID` when names are ambiguous. Add
   `--expires-in 7d` for an expiring key and `--anchor-key` when every key
   the user will hold expires. Save
   `data.activity.result.createUsersResult.userIds[0]` as `USER_ID`.

3. **Verify from the new profile.** On the user's machine:

   <!-- example: identities.login -->
   ```sh
   tk --message-format json login --profile-name agent
   ```

   Proceed when `data.identity.userId` equals `USER_ID`.

### Rotate an API key

1. **Generate the replacement on the user's machine**, without changing the
   profile yet:

   <!-- example: identities.generate -->
   ```sh
   tk --message-format json api-key generate --output ./next-key.json
   ```

   Save `data.publicKey` as `PUBLIC_KEY`. The record never contains the
   private key.

2. **Register it.** Root.

   <!-- example: identities.register -->
   ```sh
   tk --profile admin --message-format json api-key register --input-json '{"userId":"USER_ID","apiKeys":[{"apiKeyName":"agent-next","publicKey":"PUBLIC_KEY","curveType":"API_KEY_CURVE_P256"}]}'
   ```

   Save `data.activity.result.createApiKeysResult.apiKeyIds[0]`. A
   `pending` status means a policy gates credential creation; wait on the
   activity before switching.

3. **Switch the profile and verify.** On the user's machine:

   <!-- example: identities.switch -->
   ```sh
   tk --message-format json profile set --profile-name agent --api-key-file ./next-key.json
   tk --profile agent --message-format json whoami
   ```

   `profile set` reports `data.publicKey` and `data.previousApiKeyFile`.
   Proceed only when `whoami` succeeds with the expected `userId`; if it
   fails with `unauthorized`, point the profile back at
   `data.previousApiKeyFile` and inspect the registration activity.

4. **Revoke the old key.** Root. List first to find the id of the key that is
   not `PUBLIC_KEY`:

   <!-- example: identities.revoke-key -->
   ```sh
   tk --profile admin --message-format json api-key list --user-id USER_ID
   tk --profile admin --message-format json api-key delete --user-id USER_ID --id API_KEY_ID
   ```

   `data.apiKeys[].credential.publicKey` identifies each key;
   `expiresAt` is a Unix-millisecond string or `null`. After deletion the old
   key fails with `unauthorized`; the old file may be removed locally.

### Revoke a user

For a compromised or retired non-root user, confirm the identity, then
delete the user; key deletion alone leaves any other credential valid.

<!-- example: identities.revoke-user -->
```sh
tk --profile admin --message-format json user get --id USER_ID
tk --profile admin --message-format json user delete --id USER_ID
```

Proceed only when `data.user.userName` and `data.user.userTags` match the
intended user and the user is not a root quorum member. Deletion is final.

## Verified by

| Examples | Test |
|---|---|
| identities.profile-create, identities.user-create, identities.login | users::user_create_from_flags_resolves_tag_names_and_registers_anchor_and_expiring_keys |
| identities.generate, identities.register, identities.switch, identities.revoke-key, identities.revoke-user | api_keys::managing_identities_rotate_and_revoke |

## Troubleshooting

- `user create` fails with `not_found` for `--tag-name`: the tag does not
  exist in this organization. Create it with
  `tk --profile admin --message-format json user tag create --name agent` or
  pass `--tag TAG_ID`.
- `user create` fails with `invalid_input` naming two tags: the name is
  ambiguous; pass `--tag TAG_ID`.
- `user create` with only `--expires-in` fails with `api_error` 400: every
  user needs one persistent credential. Add `--anchor-key`.
- `login` fails with `unauthorized` right after `user create`: the create
  activity is still pending or was rejected. Inspect it with
  `tk --profile admin --message-format json activity get --id ACTIVITY_ID`.
- `api-key delete` fails with `unauthorized` when run as the user itself: a
  credential DENY is in force, which is intended. Run it as root.
- `whoami` fails after `profile set`: the registration has not completed.
  Restore `data.previousApiKeyFile` with another `profile set` and wait on
  the activity.

## Related Skills

- [managing-policies](../managing-policies/SKILL.md): scope what the new user
  may do; a user with no matching ALLOW can only read.
- [monitoring-activities](../monitoring-activities/SKILL.md): when a create,
  register, or delete returns `pending`.
- [bootstrapping-organization](../bootstrapping-organization/SKILL.md): when
  the tags do not exist yet.
