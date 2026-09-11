# `tk`

Experimental Turnkey auth workspace centered on the `tk` CLI.

`tk` is focused on general agent authorization, attribution, and credential management with Turnkey backed keys.

- [Git signing](./docs/git-signing.md)
- [SSH agent](./docs/ssh-agent.md)

> Warning: `tk` is experimental and has not been audited.

## Workspace layout

- `tk/`: CLI crate and end-user command docs
- `auth/`: shared auth library used by the CLI

## Installation

Install the latest release binary (Linux glibc and macOS, x86_64 and arm64):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
```

The installer verifies the release checksum and places `tk` in
`$HOME/.local/bin` (override with `TK_INSTALL_DIR`). Or build from the root of
this repo with `cargo install --path tk`. See [releasing](./docs/releasing.md)
for how binaries are published.

## Commands

```bash
tk config
tk ssh public-key
tk ssh git-sign
tk ssh agent
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
