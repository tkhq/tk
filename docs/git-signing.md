# Git signing

`tk` signs Git commits and tags as Git's SSH signing program, backed by a
Turnkey Ed25519 key, or as its GPG program, backed by a Turnkey OpenPGP key.

Follow [authentication](./authentication.md) first.

## SSH signing

Register the key as in [SSH](./ssh-agent.md#keys), then point Git at `tk`:

<!-- shared: git-ssh-signing-config -->
```bash
SSH_PUBLIC_KEY=$(tk ssh public-key)
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(command -v tk)"
git config --global user.signingkey "key::$SSH_PUBLIC_KEY"
mkdir -p ~/.config/git
printf '%s %s\n' "you@example.com" "$SSH_PUBLIC_KEY" \
  >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

With several registered keys, select one for the current repository:

```bash
git config user.signingkey \
  "key::$(tk ssh public-key --key SSH_FINGERPRINT)"
```

```bash
# Sign and verify a commit.
git commit -S --allow-empty -m test
git verify-commit HEAD

# Override the ssh-keygen used for verification if needed.
export TK_SSH_KEYGEN_PROGRAM=/path/to/ssh-keygen
```

Outside CI, point `gpg.ssh.program` at a wrapper as in [GPG signing](#gpg-signing).

For CI:

```bash
# TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, and
# TURNKEY_API_PRIVATE_KEY must already be set.
export TURNKEY_SSH_KEY_ID=PRIVATE_KEY_ID
tk ssh keys add --private-key-id "$TURNKEY_SSH_KEY_ID"
git config user.signingkey \
  "key::$(tk ssh public-key --key "$TURNKEY_SSH_KEY_ID")"
```

## GPG signing

Create and import the key as in [GPG signing](./gpg-signing.md), which leaves
its fingerprint in `$FINGERPRINT`, then point Git at a wrapper around `tk`:

<!-- shared: git-gpg-signing-config -->
```bash
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

Git passes `tk` no flags, so the profile comes from the wrapper. Under a
different `HOME` than the one holding the key registry, add
`export HOME=AGENT_HOME` to the wrapper. In CI, where every `tk` call runs as
one identity, `gpg.program tk` with `TK_PROFILE` or the `TURNKEY_*` bundle in
the environment is enough. To sign from a process that holds no Turnkey
credential, set `TK_GPG_AGENT_SOCK` as in
[GPG agent](./gpg-signing.md#gpg-agent); Git needs no other change.

## Co-author trailer

Run this after either signing setup:

```bash
# Add `Co-authored-by: Turnkey <noreply@turnkey.com>` to every commit message.
git config --global hook.turnkey-co-author.event commit-msg
git config --global hook.turnkey-co-author.command "$(command -v tk) git co-author"

# Prints `turnkey-co-author` when the Git on `PATH` runs the hook.
git hook list commit-msg
```

Git older than 2.54, including the `/usr/bin/git` that ships with macOS,
ignores the hook without an error, and its `git hook list` fails with
`unknown subcommand`. Put a newer Git first on the `PATH` of every process
that commits, including an agent runtime that builds its own `PATH`.

## Human and agent on one machine

When a human signs with their own key under the same OS user and `HOME` as an
agent, create the wrapper from [GPG signing](#gpg-signing) but skip its
`git config --global` lines, which replace the signing setup of every process
under that `HOME`, and give the agent's process the configuration instead:

```bash
# Set these in the agent process's environment only.
export GIT_CONFIG_COUNT=8
export GIT_CONFIG_KEY_0=gpg.format       GIT_CONFIG_VALUE_0=openpgp
export GIT_CONFIG_KEY_1=gpg.program      GIT_CONFIG_VALUE_1="$HOME/.local/bin/tk-sign"
export GIT_CONFIG_KEY_2=user.signingkey  GIT_CONFIG_VALUE_2="$FINGERPRINT"
export GIT_CONFIG_KEY_3=commit.gpgsign   GIT_CONFIG_VALUE_3=true
export GIT_CONFIG_KEY_4=user.name        GIT_CONFIG_VALUE_4=Agent
export GIT_CONFIG_KEY_5=user.email       GIT_CONFIG_VALUE_5=agent@example.com
export GIT_CONFIG_KEY_6=hook.turnkey-co-author.event   GIT_CONFIG_VALUE_6=commit-msg
export GIT_CONFIG_KEY_7=hook.turnkey-co-author.command GIT_CONFIG_VALUE_7="$(command -v tk) git co-author"
# Verify against a GnuPG home of the agent's own, not the human's keyring.
export GNUPGHOME="$HOME/.config/turnkey/tk/gnupg"
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
```

Import the key into that GnuPG home as in [GPG signing](./gpg-signing.md).
Git applies the `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n` pairs above every
config file and only in processes that inherit them, so the human's
`gpg.program`, `user.signingkey`, identity, and keyring stay as they are. Set
them where the agent runtime defines its environment: for example, the `env`
map in Claude Code's `~/.claude/settings.json`, Codex's `shell_environment_policy`
`set` table in `~/.codex/config.toml`, the equivalent setting in another
agent runtime, or a CI job's `env`. Such a map does not expand `$HOME`,
`$FINGERPRINT`, or `$(command -v tk)`, so write literal values there. A
sandbox can block signing, which calls Turnkey: for example, Codex's
`workspace-write` sandbox has no network access by default, so set
`network_access = true` under `[sandbox_workspace_write]` or approve the
escalation.

## Skills

- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the GPG-first procedure, scoped policies, and the signing wrapper.
- [deploying-signing-broker](../skills/deploying-signing-broker/SKILL.md): configuring Git in the application container to sign through the broker's socket.
