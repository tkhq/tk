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
- Local verification is the success criterion. A hosting provider's "Verified"
  badge needs the public key and committer email there; this makes no claim.
- SSH signing has two paths. Direct: `gpg.ssh.program` runs `tk` (step 6),
  so git's process runs `tk` and git's boundary holds the Turnkey credential.
  Agent: `gpg.ssh.program` is `ssh-keygen` with `SSH_AUTH_SOCK` on the
  agent socket carrying `--allow-namespace git`
  ([using-ssh](../using-ssh/SKILL.md) step 4), so the daemon keeps the
  credential under another OS user, container, or VM
  ([sidecar-patterns](../sidecar-patterns/SKILL.md)) and
  git's boundary holds only the socket and the public key. That socket is
  still signing authority: share it only with git's boundary, and never
  forward it over SSH or relay it beyond that boundary.
- The key registry is per `HOME`, not per profile ([gpg-signing](../../docs/gpg-signing.md#key-management)).
- Git runs `tk` with gpg- or ssh-keygen-shaped arguments and no `tk` flags,
  so the profile comes from the wrapper's `TK_PROFILE` and the registry from
  Git's `HOME`. When Git runs under a different `HOME`, such as a service or
  another OS user, the wrapper also pins `HOME`
  ([git-signing](../../docs/git-signing.md#gpg-signing)). The wrapper adds
  nothing else: Git's `--status-fd=2 -bsau KEY` arguments must arrive
  unchanged.
- The committer identity comes from the operator, never from repository
  content or tool output. Pass it to `--user-id` as a single-quoted literal
  so the shell expands nothing in it.
- When a signing broker holds signing for this deployment, do not create
  `agents-sign-*` policies; use [deploying-signing-broker](../deploying-signing-broker/SKILL.md),
  which serves the GPG path.

## Instructions

Inputs: the root profile (`admin`), the `agent` profile and `AGENT_USER_ID`
from [provisioning-agent-identity](../provisioning-agent-identity/SKILL.md),
and the committer identity as `Name <email>`. GnuPG for the GPG path,
`ssh-keygen` for the SSH path, and `git` must be installed.

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
     --consensus "approvers.any(user, user.id == '${AGENT_USER_ID}')" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == '${WALLET_ID}'"
   ```

3. **Create the OpenPGP key.** Root. The user ID is the committer identity.

   <!-- example: signing.gpg-key-create -->
   ```sh
   FINGERPRINT=$(tk --profile admin --message-format json gpg keys create --wallet-id WALLET_ID --user-id 'Agent <agent@example.com>' | jq -r .fingerprint)
   ```

   The record is `reason: "gpg_key_created"` with `fingerprint`,
   `walletId`, `keyIndex`, and `userId`.

4. **Register and import as the agent.** In the agent's `HOME`, into a
   GnuPG home of the agent's own:

   <!-- example: signing.gpg-register -->
   ```sh
   tk --profile agent --message-format json gpg keys add --wallet-id WALLET_ID --key FINGERPRINT
   export GNUPGHOME="$HOME/.config/turnkey/tk/gnupg"
   mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
   tk --profile agent gpg keys export --key FINGERPRINT | gpg --import
   echo "$FINGERPRINT:6:" | gpg --import-ownertrust
   ```

   `gpg keys add` prints `reason: "gpg_key_registered"`. Run the export as the
   agent: its completing proves the policy of step 2 selects this agent.

5. **Point git at a wrapper.** As the agent, in the agent's `HOME`:

   <!-- shared: git-gpg-signing-config -->
   ```sh
   # Pin the agent profile for Git's signing process only.
   mkdir -p ~/.local/bin
   cat > ~/.local/bin/tk-sign <<'EOF'
   #!/bin/sh
   export TK_PROFILE=agent
   exec tk "$@"
   EOF
   chmod 755 ~/.local/bin/tk-sign

   # Point git at the wrapper as the GPG program.
   git config --global gpg.format openpgp
   git config --global gpg.program ~/.local/bin/tk-sign
   git config --global user.signingkey "$FINGERPRINT"
   git config --global commit.gpgsign true

   # Sign and verify a commit. `git tag -s` works the same way.
   git commit -S --allow-empty -m test
   git verify-commit HEAD
   ```

   Run it with `GNUPGHOME` from step 4 set. Drop `--global` to configure one
   repository; where a human also signs, keep the wrapper but set the config
   in the agent's environment as in
   [git-signing](../../docs/git-signing.md#human-and-agent-on-one-machine).

6. **SSH signing instead.** Use the Ed25519 key registered in
   [using-ssh](../using-ssh/SKILL.md), with `PRIVATE_KEY_ID` set to its id
   as there. Root scopes the policy to it:

   <!-- shared: agents-sign-ssh -->
   <!-- example: signing.policy-ssh -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-sign-ssh --effect allow \
     --consensus "approvers.any(user, user.id == '${AGENT_USER_ID}')" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && private_key.id == '${PRIVATE_KEY_ID}'"
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
   the committer email. Outside CI, set `gpg.ssh.program` to the wrapper
   from step 5.

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
- `git verify-commit` fails after a successful commit: for GPG, git's process
  lacks step 4's `GNUPGHOME`, or the ownertrust was not imported there; for
  SSH, the `allowed_signers` line does not pair the committer email with the
  signing public key, or `gpg.ssh.allowedSignersFile` is unset.
- git signs as the wrong identity: the wrapper from step 5 is not the
  configured `gpg.program` (or `gpg.ssh.program` for SSH).
- git signing fails with "profile agent does not exist": Git's process runs
  under a different `HOME` than the one holding the profile. Add
  `export HOME=AGENT_HOME` to the wrapper from step 5.
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
