# SSH

Use Turnkey Ed25519 private keys for SSH through a background agent.

Follow [authentication](./authentication.md) first.

## Keys

```bash
# Create an Ed25519 private key in Turnkey and register it locally.
tk ssh keys create --name agent-ssh
tk ssh keys list

# Print a public key, for authorized_keys or GitHub.
tk ssh public-key
tk ssh public-key --key SSH_FINGERPRINT

# Forget a key. The Turnkey private key is unchanged.
tk ssh keys remove SSH_FINGERPRINT
```

## Agent

```bash
tk ssh agent start
export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock

ssh-add -L
ssh user@host
tk ssh agent status

tk ssh agent stop
```

Limit the keys served:

```bash
# Serve selected keys.
tk ssh agent start --key SSH_FINGERPRINT --key ANOTHER_SSH_FINGERPRINT

# Serve keys belonging to one profile's organization.
tk ssh agent start --profile agent
```

```bash
# Move the socket and pid file off their defaults under ~/.config/turnkey/.
# `status` and `stop` take the same two flags.
tk ssh agent start --socket /run/agent/ssh.sock --pid-file /run/agent/ssh.pid

# Open the socket to a supplemental group.
tk ssh agent start --socket /run/agent/ssh.sock --pid-file /run/agent/ssh.pid --socket-mode 660
```

## Destination constraints

```bash
# Sign only for the hosts in a known_hosts file, plus `git` SSHSIG payloads.
ssh-keyscan github.com > ~/.config/turnkey/ssh-allowed-hosts
tk ssh agent start --allowed-hosts-file ~/.config/turnkey/ssh-allowed-hosts --allow-namespace git
```

The agent signs SSH user authentication only after an OpenSSH 8.9+ client binds
the connection to a listed host key with `session-bind@openssh.com`, and a
hostbound request must name that same key. A connection bound as a forwarding
hop, or whose bind fails verification, gets no signatures. An unbound connection
never gets user authentication, but it can get `SSHSIG` signatures in the
allowed namespaces. A client older than OpenSSH 8.9 sends no bind, so a hop
forwarded by one looks unbound: it can get those `SSHSIG` signatures and can
bind itself to a listed host for user authentication. Turnkey policies never see
the destination host, so this is the place to pin it.

Restart after adding or removing keys:

```bash
tk ssh agent stop
tk ssh agent start
```

To sign Git commits with a registered key, see
[git signing](./git-signing.md).

## Skills

- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): serving keys from a socket under the agent's `HOME` beside the renewal loop.
- [using-ssh](../skills/using-ssh/SKILL.md): creating and registering the key, serving it as a non-root agent, and verifying a signature through the socket.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the SSH signing alternative built on a registered key.
