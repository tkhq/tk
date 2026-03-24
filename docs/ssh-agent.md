# SSH agent

Run `tk` as a foreground SSH agent when you want plain `ssh` to authenticate with your Turnkey Ed25519 key.

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

Use two terminals:

Terminal 1:

```bash
tk ssh-agent --socket /tmp/auth.sock
```

Terminal 2:

```bash
export SSH_AUTH_SOCK=/tmp/auth.sock

ssh-add -L
ssh user@host
```

`ssh-add -L` should print the Turnkey-backed OpenSSH public key while `ssh user@host` uses the agent socket for signing.
