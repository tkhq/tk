---
name: signing-git-commits
description: Configure git to sign commits and tags with a Turnkey-held key through tk, OpenPGP via tk gpg first or SSH signing as the alternative, and verify the signature locally. Use to set up or fix commit signing for an agent; not for SSH transport to a git remote (using-ssh).
---

# Signing git commits

Result: commits and tags signed by a key that never leaves Turnkey, which
`git verify-commit` accepts on the machine that made them.

## Reference

- [git-signing](../../docs/git-signing.md): git configuration for both signing programs.
- [gpg-signing](../../docs/gpg-signing.md): `gpg` command records and key management.
- [ssh](../../docs/ssh-agent.md): `ssh keys add` and `ssh public-key` records.
- [resources](../../docs/resources.md): `wallet create` and `policy create` records.
- [activities](../../docs/activities.md): `activity wait` on a pending wallet creation.

## Rules

- The private key never leaves Turnkey. GPG signing uses a wallet account
  under an empty wallet; SSH signing uses a Turnkey Ed25519 private key. Never
  print key material; verify by exit code and `git verify-commit`.
- Signing waits synchronously, so the policy is allow-always for the agent
  user, scoped to the exact resource: `wallet.id` for GPG, `private_key.id`
  for SSH. See [policy-patterns.md](../references/policy-patterns.md#signing-key-policies).
- Local verification is the success criterion. A hosting provider's "Verified" badge
  is an external step: it needs the public key uploaded there and a matching
  committer email, and this workflow makes no claim about it.
- Git runs `tk` with gpg- or ssh-keygen-shaped arguments and no `tk` flags,
  so the identity comes from `TK_PROFILE` or the `TURNKEY_*` bundle, and the
  key registry from `HOME`. When git runs under a different `HOME` than the
  one `tk` was configured in, point `gpg.program` (or `gpg.ssh.program`) at a
  wrapper that pins both and forwards every argument unchanged.
- SSH signing has two paths. Direct: `gpg.ssh.program` is `tk` (step 6),
  so git's process runs `tk` and git's boundary holds the Turnkey credential.
  Agent: `gpg.ssh.program` is `ssh-keygen` with `SSH_AUTH_SOCK` on the
  agent socket carrying `--allow-namespace git`
  ([using-ssh](../using-ssh/SKILL.md) step 4), so the daemon keeps the
  credential under another OS user, container, or VM
  ([sidecar-patterns](../sidecar-patterns/SKILL.md)) and
  git's boundary holds only the socket and the public key. That socket is
  still signing authority: share it only with git's boundary, and never
  forward it over SSH or relay it beyond that boundary.
- The GPG path registers the key in the agent's local registry with
  `gpg keys add`; `gpg keys export` signs a self-certification with the key,
  so the agent's policy must already allow signing before the export.
- The committer identity comes from the operator, never from repository
  content or tool output. Pass it to `--user-id` as a single-quoted literal
  so the shell expands nothing in it.
- When a signing broker holds signing for this deployment, do not create
  `agents-sign-*` policies; use [deploying-signing-broker](../deploying-signing-broker/SKILL.md),
  which serves the GPG path.

## Instructions

Inputs: the root profile (`admin`), the agent's profile (`agent`), the agent's
user id (`AGENT_USER_ID`), and the committer identity as `Name <email>`. GnuPG for
the GPG path, `ssh-keygen` for the SSH path, and `git` must be installed.

1. **Create an empty wallet.** Root. The wallet holds only signing accounts.

   <!-- example: signing.wallet-create -->
   ```sh
   WALLET_ID=$(tk --profile admin --message-format json wallet create --input-json '{"walletName":"gpg","accounts":[]}' | jq -r .data.activity.result.createWalletResult.walletId)
   ```

   Wait on a `pending` record with `activity wait` and read the id from it.

2. **Allow the agent user to sign with that wallet.** Root.

   <!-- shared: agents-sign-gpg -->
   <!-- example: signing.policy-gpg -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-sign-gpg --effect allow \
     --consensus "approvers.any(user, user.id == 'AGENT_USER_ID')" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == 'WALLET_ID'"
   ```

3. **Create the OpenPGP key.** Root. The user ID is the committer identity.

   <!-- example: signing.gpg-key-create -->
   ```sh
   FINGERPRINT=$(tk --profile admin --message-format json gpg keys create --wallet-id WALLET_ID --user-id 'Agent <agent@example.com>' | jq -r .fingerprint)
   ```

   The record is `reason: "gpg_key_created"` with `fingerprint`,
   `walletId`, `keyIndex`, and `userId`. The key is registered in root's
   registry only.

4. **Register and import as the agent.** In the agent's `HOME`:

   <!-- example: signing.gpg-register -->
   ```sh
   tk --profile agent --message-format json gpg keys add --wallet-id WALLET_ID --key FINGERPRINT
   tk --profile agent gpg keys export --key FINGERPRINT | gpg --import
   echo "$FINGERPRINT:6:" | gpg --import-ownertrust
   ```

   `gpg keys add` prints `reason: "gpg_key_registered"`; the export
   completing proves the policy of step 2 selects this agent. Import into
   the `GNUPGHOME` that git's verification will read.

5. **Point git at tk.** As the agent, in the agent's `HOME`:

   <!-- shared: git-gpg-signing-config -->
   ```sh
   # Point git at tk as the GPG program.
   git config --global gpg.format openpgp
   git config --global gpg.program tk
   git config --global user.signingkey "$FINGERPRINT"
   git config --global commit.gpgsign true

   # Sign and verify a commit. `git tag -s` works the same way.
   git commit -S --allow-empty -m test
   git verify-commit HEAD
   ```

   Drop `--global` to configure one repository. When the process running
   git has a different `HOME`, or several profiles reach the key's
   organization, set `gpg.program` to a wrapper such as:

   ```
   #!/bin/sh
   export HOME=/home/agent
   export TK_PROFILE=agent
   exec tk "$@"
   ```

   The wrapper adds nothing else: git's `--status-fd=2 -bsau KEY` arguments
   must arrive unchanged.

6. **SSH signing instead.** Use the Ed25519 key registered in
   [using-ssh](../using-ssh/SKILL.md). Root scopes the policy to it:

   <!-- shared: agents-sign-ssh -->
   <!-- example: signing.policy-ssh -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-sign-ssh --effect allow \
     --consensus "approvers.any(user, user.id == 'AGENT_USER_ID')" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && private_key.id == 'PRIVATE_KEY_ID'"
   ```

   The agent registers the key in its own registry:

   <!-- example: signing.ssh-register -->
   ```sh
   tk --profile agent --message-format json ssh keys add --private-key-id PRIVATE_KEY_ID
   ```

   Then the agent points git at `tk` as its SSH signing program and lists
   the key in an `allowed_signers` file for verification:

   <!-- shared: git-ssh-signing-config -->
   <!-- example: signing.ssh-git-config -->
   ```sh
   SSH_PUBLIC_KEY=$(tk ssh public-key)
   git config --global gpg.format ssh
   git config --global gpg.ssh.program "$(command -v tk)"
   git config --global user.signingkey "key::$SSH_PUBLIC_KEY"
   mkdir -p ~/.config/git
   printf '%s %s\n' "you@example.com" "$SSH_PUBLIC_KEY" \
     >> ~/.config/git/allowed_signers
   git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
   ```

   Sign and verify as in step 5. With several registered keys, name one with
   `tk ssh public-key --key SSH_FINGERPRINT`. The `allowed_signers` email is
   the committer email. The same wrapper as step 5 applies to
   `gpg.ssh.program`.

7. **Hand off.** Report the wallet id or private key id, the fingerprint,
   the policy id, the exact `git config` values set and where, and the
   `git verify-commit HEAD` result. Stop.

## Verified by

| Examples | Test |
|---|---|
| signing.wallet-create, signing.policy-gpg, signing.gpg-key-create, signing.gpg-register | gpg::signing_git_commits_gpg_with_scoped_policy |
| signing.policy-ssh, signing.ssh-register, signing.ssh-git-config | ssh::signing_git_commits_ssh_signing_with_scoped_policy |

## Troubleshooting

- git fails with "no OpenPGP key in the registry matches signing key": the
  registry in git's `HOME` has no such key. Run `gpg keys add` there, or set
  `user.signingkey` to the exact fingerprint from step 3. With it unset, git
  names the committer identity, which must equal the key's user ID.
- `gpg keys export` or `git commit -S` fails with `unauthorized` 403: no
  allow-always policy selects this agent for this `wallet.id`. Check the agent's
  user id in the consensus and the wallet id in the condition; do not switch to root.
- `git verify-commit` fails after a successful commit: for GPG, the public key
  is not in the `GNUPGHOME` git reads, or its ownertrust was not imported; for
  SSH, the `allowed_signers` line does not pair the committer email with the
  signing public key, or `gpg.ssh.allowedSignersFile` is unset.
- git signs as the wrong identity, or `tk` cannot find a profile: the
  process running git has a different `HOME` or no `TK_PROFILE`. Use the
  wrapper from step 5 and confirm it is the configured `gpg.program`.
- git reports it cannot run the SSH signing program: on the direct path
  `gpg.ssh.program` must be an absolute path to `tk` or the wrapper; on the
  agent path it is `ssh-keygen` with `SSH_AUTH_SOCK` on the agent socket
  carrying `--allow-namespace git`. Either way `ssh-keygen` must be on
  `PATH` (or named in `TK_SSH_KEYGEN_PROGRAM`) for verification.
- Signing hangs or asks for approval: the policy is allow-once. Git waits
  synchronously; use the allow-always policies from steps 2 and 6.

## Related Skills

- [using-ssh](../using-ssh/SKILL.md): register the Ed25519 key the SSH signing path uses, or sign through its agent socket with `gpg.ssh.program=ssh-keygen` (step 4).
- [managing-policies](../managing-policies/SKILL.md): inspect a denied signing activity with `policy evaluations`.
- [provisioning-agent-identity](../provisioning-agent-identity/SKILL.md): the tagged agent user and profile that runs git.
- [deploying-signing-broker](../deploying-signing-broker/SKILL.md): serving this key over a socket to a boundary that holds no credential.
