---
name: bootstrapping-organization
description: Prepare an existing Turnkey organization for agents with tk: install the binary, save and verify a root profile, create the agent, provisioner, and human-approver tags, and pick an approval model. Use once per organization before provisioning any agent; not for creating the organization itself or for adding a later agent.
---

# Bootstrapping an organization

Result: a verified root profile on the operator's machine, three disjoint
user tags, a tagged human approver, and a recorded approval-model choice.
The organization itself is created in the Turnkey dashboard at
https://app.turnkey.com; nothing here creates an agent.

## Reference

- [authentication](../../docs/authentication.md): profiles, `login`, and the environment bundle.
- [resources](../../docs/resources.md): `user`, `user tag`, and `policy` command records.

## Rules

- The root credential is the operator's. It never becomes an agent's runtime
  credential and never leaves the operator's machine.
- Tags are disjoint: a user carries at most one of `agent`, `provisioner`,
  `human-approver`.
- Pick the approval model before any policy is written; the choice decides
  which policy set the later workflows apply.
- Every `tk` command takes `--message-format json`; branch on `reason` and
  `status` as [cli-convention.md](../references/cli-convention.md) describes.

## Instructions

Inputs from the user: the name of the root profile (`admin` below) and
which human approves. The organization id comes from step 1.

1. **Open the organization in the dashboard.** Operator, at
   https://app.turnkey.com. Sign in, create an organization if there is none,
   and copy the Organization ID from the dashboard; it is `ORG_UUID` below.

2. **Install `tk`.** Operator, on their machine. The installer fetches the
   latest release:

   <!-- example: bootstrap.install -->
   ```sh
   curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
   tk --version
   ```

3. **Save the root profile.** Operator. Either path leaves a credential file
   under `~/.config/turnkey/tk/api-keys/`; the private key is never printed.

   With an existing root API key file in `{"public_key","private_key","curve"}`
   form:

   <!-- example: bootstrap.profile-create-existing -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name admin --api-key-file ./root-key.json
   ```

   Without one, let `tk` generate the credential, then register it: in the
   dashboard at https://app.turnkey.com open the root user, add an API key,
   and paste the printed `data.publicKey` (curve P-256). Continue once the
   key shows on the user:

   <!-- example: bootstrap.profile-create-fresh -->
   ```sh
   tk --message-format json --organization-id ORG_UUID profile create --profile-name admin
   ```

   Proceed when `command` is `profile.create`. `data.nextStep` names the
   registration step.

4. **Verify and select the profile.**

   <!-- example: bootstrap.login -->
   ```sh
   tk --message-format json login --profile-name admin
   tk --profile admin --message-format json whoami
   ```

   Proceed when `login` returns `command: "auth.login"` with
   `data.identity.organizationId` equal to the organization and `whoami`
   returns the same `userId`. Save `data.identity.userId` as
   `HUMAN_USER_ID` if this root user is the approver. `unauthorized` means the
   public key is not on the root user yet; add it in the dashboard and rerun
   `login`.

5. **Create the three tags.** Root.

   <!-- example: bootstrap.tags -->
   ```sh
   tk --profile admin --message-format json user tag create --name agent
   tk --profile admin --message-format json user tag create --name provisioner
   tk --profile admin --message-format json user tag create --name human-approver
   ```

   Each record is `command: "user.tag.create"`; save
   `data.activity.result.createUserTagResult.userTagId` as `AGENT_TAG`,
   `PROVISIONER_TAG`, and `HUMAN_APPROVER_TAG`. A `pending` status means a
   policy already gates tag creation; wait on the activity before the next
   step.

6. **Tag the human approver.** Root. The approver is a user who will vote
   with `tk activity approve`, the console, or the mobile app.

   <!-- example: bootstrap.tag-human -->
   ```sh
   tk --profile admin --message-format json user update --input-json '{"userId":"HUMAN_USER_ID","userTagIds":["HUMAN_APPROVER_TAG"]}'
   ```

   `userTagIds` replaces the user's tag set. Confirm with
   `tk --profile admin --message-format json user get HUMAN_USER_ID`, whose
   `data.user.userTags` lists the tag id. A root approver also satisfies the
   root quorum, so consensus behavior is tested later with a non-root
   approver.

7. **Choose the approval model.** Read
   [approval-models.md](../references/approval-models.md) with the user and
   record the cell: whether exports need a human, and whether minting does.
   Do not create policies here; the provisioning workflows apply the policy
   set for the chosen cell.

8. **Hand off.** Report the organization id, the profile name, the root
   user id, the three tag ids, the approver's user id, and the chosen cell.
   Stop.

## Verified by

| Examples | Test |
|---|---|
| bootstrap.profile-create-existing, bootstrap.login, bootstrap.tags, bootstrap.tag-human | identity::bootstrapping_organization_root_tags_and_approval_model |
| bootstrap.profile-create-fresh | identity::profile_create_generates_a_credential_that_logs_in_once_registered |

`bootstrap.install` is a manual prerequisite; the suite runs the built binary.

## Troubleshooting

- `login` fails with `unauthorized` (401 or 403): the profile's public key is not
  registered on a user in that organization. Add it to the root user at
  https://app.turnkey.com, then rerun the same `login`.
- `login` fails with `invalid_input` naming `profile set`: the profile was
  saved with a different organization or endpoint. Run the `tk profile set`
  command the message names, then `login` again.
- `user tag create` fails with `api_error` and a 400: a tag with that name
  already exists. Read the id from `tk --profile admin --message-format json user tag list`.
- `user update` returns `status: "pending"`: an existing policy gates user
  updates. Resume with `tk activity wait ACTIVITY_ID --timeout 60`; do not
  resubmit.
- Any command fails with `invalid_input` about the environment bundle: a
  partial `TURNKEY_*` bundle is set in the shell. Unset it or pass
  `--profile admin`.

## Related Skills

- [managing-identities](../managing-identities/SKILL.md): create the agent
  and provisioner users this organization is now ready for.
- [managing-policies](../managing-policies/SKILL.md): apply the policy set
  for the chosen approval cell.
- [monitoring-activities](../monitoring-activities/SKILL.md): when a step
  above returns `pending`.
