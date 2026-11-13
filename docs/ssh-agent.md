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
tk ssh keys remove --key SSH_FINGERPRINT
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

Restart after adding or removing keys:

```bash
tk ssh agent stop
tk ssh agent start
```

To sign Git commits with a registered key, see
[git signing](./git-signing.md).

## Destination constraints

```bash
# Record the host keys of the servers the agent may sign for.
ssh-keyscan github.com > ~/.config/turnkey/ssh-allowed-hosts

# Sign SSH connections only to those host keys, and nothing else.
tk ssh agent start --allowed-hosts-file ~/.config/turnkey/ssh-allowed-hosts

# Also sign Git commits and tags, which Git with `gpg.format=ssh` and
# `gpg.ssh.program=ssh-keygen` signs through `ssh-keygen -Y sign -n git`.
tk ssh agent start --allowed-hosts-file ~/.config/turnkey/ssh-allowed-hosts --allow-namespace git

# Or, if you forward or relay the login socket, keep `--allow-namespace` off it
# and sign Git from a second daemon on its own socket.
tk ssh agent start --allowed-hosts-file ~/.config/turnkey/ssh-allowed-hosts
tk ssh agent start --allowed-hosts-file ~/.config/turnkey/ssh-allowed-hosts --allow-namespace git --socket ~/.config/turnkey/ssh-git.sock
```

The agent signs an SSH connection only after an OpenSSH 8.9+ client binds it
with `session-bind@openssh.com` to a host key in the file, so it refuses older
clients and every hop of an agent that such a client forwards. OpenSSH's own
agent never signs `ssh-keygen -Y sign` with a destination-constrained key, so
`--allow-namespace` is a tk extension: the agent signs one only on a connection
with no bind, which rules out every hop that an 8.9+ client forwards, and signs
nothing on a connection whose bind failed. A socket relay, such as `ssh -R`,
`socat`, or a forward from a pre-8.9 client, sends no bind, so the agent cannot
tell a relayed request from local use: anything that can reach an
`--allow-namespace` socket can sign Git commits and tags. Share it only with
the one boundary that should, such as another OS user or one container or VM
through a mount, and never forward it over SSH or relay it beyond that
boundary. It matches host keys only; the hostnames in the file are reported,
never matched.

## Typed logins

```bash
# Print GitHub's host key fingerprints, read from https://api.github.com/meta.
tk ssh github-host-keys

# Sign SSH logins through Turnkey's SSH userauth activity.
tk ssh agent start --userauth typed
```

By default (`--userauth raw`) the agent signs each login as a raw payload,
so Turnkey policy cannot see which server it is for. With `--userauth typed`,
the agent sends Turnkey the login request together with the
`session-bind@openssh.com` message that an OpenSSH 8.9+ client sends first.
Turnkey checks the server's host key signature over the session ID, checks
that the login is for the same session, and only then evaluates policy with
`activity.params.username`, `service`, `host_key_fingerprint`,
`host_key_algorithm`, and `host_bound`. Turnkey verifies Ed25519 and ECDSA
P-256 host keys; a server that presents another host key type (such as RSA)
cannot be used in typed mode.

In typed mode the agent refuses a login that has no matching bind (clients
older than OpenSSH 8.9, or a socket relay such as `socat`) and any login on a
connection that a client forwarded with `ssh -A`. It never falls back to raw
signing. `ssh-keygen -Y sign` requests still sign as raw payloads, and other
data is refused.

A policy that limits the key to GitHub is `agents-ssh-github` in
[policy-patterns.md](../skills/references/policy-patterns.md). It is only as
strong as the key's other grants: an ALLOW for
`ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2` on the same key can sign a login for any
host, so remove raw-payload grants on SSH keys. Turnkey enforces the host;
GitHub enforces which repositories the key opens, through the account or
deploy key it is registered on. `--allowed-hosts-file` still works with typed
mode as an early local refusal.

## Skills

- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): serving keys from a socket under the agent's `HOME` beside the renewal loop.
- [using-ssh](../skills/using-ssh/SKILL.md): creating and registering the key, serving it as a non-root agent, and verifying a signature through the socket.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): the SSH signing alternative built on a registered key.
