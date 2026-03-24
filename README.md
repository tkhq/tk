# `tk`

Experimental Turnkey auth workspace centered on the `tk` CLI.

`tk` is focused on general agent authorization, attribution, and credential management with Turnkey backed keys.

- Git SSH signing with a Turnkey private key
- An SSH agent that signs SSH requests with a Turnkey private key

> Warning: `tk` is experimental and has not been audited.

## Workspace layout

- `tk/`: CLI crate and end-user command docs
- `auth/`: shared auth library used by the CLI

## Installation

From the root of this repo:

```bash
cargo install -p tk
```

The installed binary is named `tk`.

## Commands

```bash
tk config
tk public-key
tk git-sign
tk ssh-agent
```

## Configuration

`tk` resolves configuration in this order:

1. Environment variables
2. Global config file
3. Built in defaults

The default global config file path is:

```bash
~/.config/turnkey/tk.toml
```

Set `TURNKEY_TK_CONFIG_PATH` to override the config file location.

You can inspect or update config with:

```bash
tk config list
tk config get turnkey.organizationId
tk config set turnkey.organizationId "<org-id>"
tk config set turnkey.apiPublicKey "<api-public-key>"
tk config set turnkey.apiPrivateKey "<api-private-key>"
tk config set turnkey.privateKeyId "<ed25519-private-key-id>"
tk config set turnkey.apiBaseUrl "https://api.turnkey.com"
```

`tk config list` prints the fully resolved effective configuration, so environment-variable overrides appear in its output. Secret values such as `turnkey.apiPrivateKey` are redacted in both `config list` and `config get`.

### Environment Overrides

```bash
export TURNKEY_ORGANIZATION_ID="<org-id>"
export TURNKEY_API_PUBLIC_KEY="<api-public-key>"
export TURNKEY_API_PRIVATE_KEY="<api-private-key>"
export TURNKEY_PRIVATE_KEY_ID="<ed25519-private-key-id>"
export TURNKEY_API_BASE_URL="https://api.turnkey.com" # optional
```

These environment variables override values stored in the global config file. This can be helpful for CI.

## Guides

- [Git signing](./docs/git-signing.md)
- [SSH agent](./docs/ssh-agent.md)
