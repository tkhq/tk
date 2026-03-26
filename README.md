# `tk`

Turnkey auth CLI for SSH and Git workflows backed by Turnkey wallets.

- Git SSH signing with a Turnkey wallet key
- SSH agent that signs requests with a Turnkey wallet key
- Interactive setup with automatic wallet creation

> Warning: `tk` is experimental and has not been audited.

## Workspace layout

- `tk/`: CLI crate and end-user command docs
- `auth/`: shared auth library used by the CLI

## Installation

From the root of this repo:

```bash
cargo install --path tk
```

The installed binary is named `tk`.

## Quick start

```bash
export TURNKEY_API_PRIVATE_KEY="<hex-private-key>"
tk init \
  --organization-id <org-id> \
  --api-public-key <hex-public-key>

tk whoami
tk public-key
```

`tk init` validates your credentials, finds (or creates) a wallet with an Ed25519 account, and saves the signing config to the config file.

## Commands

```
tk init          Initialize credentials and wallet setup
tk whoami        Display authenticated identity
tk config        Inspect and update configuration
tk public-key    Print the SSH public key
tk git-sign      Git SSH signer interface
tk ssh-agent     Manage the SSH agent daemon
```

### SSH agent

```bash
tk ssh-agent start
tk ssh-agent status
tk ssh-agent stop
```

## Configuration

`tk` resolves configuration in this order:

1. Environment variables
2. Global config file
3. Built-in defaults

Set `TURNKEY_TK_CONFIG_PATH` to override the config file location.

```bash
tk config list
tk config get turnkey.organizationId
tk config set turnkey.apiBaseUrl "https://api.turnkey.com"
```

Secret values such as `turnkey.apiPrivateKey` are redacted in `config list` and `config get`. The `signingAddress` and `signingPublicKey` fields are set automatically by `tk init`.

### Environment variables

```bash
export TURNKEY_ORGANIZATION_ID="<org-id>"
export TURNKEY_API_PUBLIC_KEY="<api-public-key>"
export TURNKEY_API_PRIVATE_KEY="<api-private-key>"
export TURNKEY_API_BASE_URL="https://api.turnkey.com"  # optional
```

These override values stored in the config file. Useful for CI.

## Development

### Pre-commit hooks

```bash
git config core.hooksPath .github/hooks
```

### CI

The GitHub Actions workflow runs on every push and PR to main:

- `cargo fmt --check`
- `cargo build` (lint rules enforced via `[workspace.lints]` in Cargo.toml)
- `cargo test`
- Security audit via `cargo-audit`

## Guides

- [Git signing](./docs/git-signing.md)
- [SSH agent](./docs/ssh-agent.md)
