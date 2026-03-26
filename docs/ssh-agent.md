# SSH agent

Run `tk` as an SSH agent to authenticate with your Turnkey Ed25519 wallet key.

Ensure you have run `tk init` first (see the [quick start](../README.md#quick-start)).

## Daemon mode (recommended)

```bash
tk ssh-agent start
eval $(tk ssh-agent status)

ssh-add -L
ssh user@host
```

To stop the agent:

```bash
tk ssh-agent stop
```

## Foreground mode

For debugging or custom socket paths:

```bash
tk ssh-agent --socket /tmp/auth.sock
```

In another terminal:

```bash
export SSH_AUTH_SOCK=/tmp/auth.sock
ssh-add -L
ssh user@host
```
