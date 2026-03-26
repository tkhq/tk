# SSH agent

Run `tk` as a background SSH agent when you want plain `ssh` to authenticate with your Turnkey Ed25519 key.

## Prerequisites

Run `tk init` to set up your credentials and wallet. See the [quick start](../README.md#quick-start) section of the repository readme.

## Usage

Start the agent:

```bash
tk ssh-agent start
```

Point your shell at the agent socket and verify:

```bash
export SSH_AUTH_SOCK=~/.config/turnkey/tk/ssh-agent.sock

ssh-add -L
ssh user@host
```

Check agent status:

```bash
tk ssh-agent status
```

Stop the agent:

```bash
tk ssh-agent stop
```

`ssh-add -L` should print the Turnkey-backed OpenSSH public key while `ssh user@host` uses the agent socket for signing.
