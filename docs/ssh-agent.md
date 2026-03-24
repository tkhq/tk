# SSH agent

Run `tk` as a background SSH agent when you want plain `ssh` to authenticate with your Turnkey Ed25519 key.

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

```bash
tk ssh-agent start
```

```bash
export SSH_AUTH_SOCK=~/.config/turnkey/tk/ssh-agent.sock

ssh-add -L
ssh user@host
tk ssh-agent status
```

When you are done:

```bash
tk ssh-agent stop
```

`ssh-add -L` should print the Turnkey-backed OpenSSH public key while `ssh user@host` uses the agent socket for signing.
