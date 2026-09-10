# Profile identity for SSH commands

Status: proposed. Base: `zeke/tk-secrets-port` (#26).

## Summary

`tk ssh agent`, `tk ssh git-sign`, `tk ssh public-key`, and the `tk -Y` git
passthrough still read the old `tk.toml` file through `turnkey_auth::config`.
Every other command resolves its identity from the profile registry or the
`TURNKEY_*` environment bundle. This PR moves the SSH commands onto the same
resolution, deletes `tk config` and the `tk.toml` loader, and rewrites the
README around profiles. It also restores the Async I/O Policy in `AGENTS.md`.

After this PR there is one way to configure `tk`:

1. `--profile NAME` or `TK_PROFILE` selects a saved profile. It always wins.
2. Otherwise a complete `TURNKEY_ORGANIZATION_ID`, `TURNKEY_API_PUBLIC_KEY`,
   `TURNKEY_API_PRIVATE_KEY` bundle is used. `TURNKEY_PRIVATE_KEY_ID` names the
   SSH signing key on this path. A partial or empty bundle is `invalid_input`.
3. Otherwise the registry's active profile is used.

## Goals

- SSH commands and API commands resolve identity through one code path.
- A profile can carry the Ed25519 signing key ID that SSH commands need.
- `tk.toml`, `TURNKEY_TK_CONFIG_PATH`, and `tk config` are gone.
- The README, `docs/git-signing.md`, and `docs/ssh-agent.md` describe the
  profile workflow end to end, including CI with the environment bundle.
- `AGENTS.md` states the Async I/O Policy again.

## Non-goals

- Migrating existing `tk.toml` files. `tk` is alpha; users run `tk login`.
- Changing the SSH wire format, the agent protocol, or signing behavior.
- Prompting. All inputs stay flags, environment, or the registry.

## Design

### Identity moves into `turnkey_auth`

The registry, profile schema, `FileLock`, `secure_create`, environment bundle
handling, and `resolve()` move from `tk/src/auth.rs` to a new
`auth/src/identity.rs` module. The `turnkey_auth` crate needs them because the
SSH agent, git signer, and public key code live there. `tk/src/auth.rs` keeps
the `login`, `auth`, and `profile` commands and their output types, and uses
`turnkey_auth::identity` for everything else.

The resolved identity type (`turnkey_auth::identity::Identity`, replacing
`ResolvedAuth`) gains one field:

```rust
pub struct Identity {
    pub organization_id: String,
    pub api_base_url: String,
    pub stamper: TurnkeyP256ApiKey,
    /// The Ed25519 private key that SSH commands sign with, when configured.
    pub ssh_signing_key_id: Option<String>,
    source: &'static str,
    profile: Option<String>,
}
```

On the profile path `ssh_signing_key_id` comes from the profile. On the
environment path it comes from `TURNKEY_PRIVATE_KEY_ID`, which is optional and
does not make the bundle partial when absent. `--organization-id` and
`--api-base-url` keep overriding both paths.

`IdentityOptions` (the current `AuthOptions`: `--config`, `--profile`,
`--organization-id`, `--api-base-url`) also moves to `turnkey_auth::identity`
so the daemon can rebuild it. The flags stay global on the `tk` command.

### `TurnkeySigner` takes an `Identity`

`TurnkeySigner::new(identity: Identity)` replaces `TurnkeySigner::new(Config)`.
Signing paths call `required_signing_key_id()`, which returns
`InvalidInput("no SSH signing key configured; run tk profile set NAME
--ssh-signing-key-id ID, or set TURNKEY_PRIVATE_KEY_ID")` when the field is
`None`. `get_public_key` has the same requirement.

`auth/src/config.rs` is deleted along with `Config`, `ResolvedConfig`,
`ConfigKey`, `RedactedConfig`, `global_config_path`, and the
`TURNKEY_TK_CONFIG_PATH` variable. `DEFAULT_CONFIG_DIR_DISPLAY` becomes
`~/.config/turnkey`.

### SSH commands resolve like API commands

`tk ssh public-key`, `tk ssh git-sign`, and `tk ssh agent start|status|stop`
receive the parsed `IdentityOptions` and call `identity::resolve`. The
existing `commands::ssh::run(ctx, args)` gains an `options: &IdentityOptions`
parameter. Resolution happens before any socket or file work so a missing
identity fails fast with `invalid_input`.

**Agent daemon.** `tk ssh agent start` resolves the identity once, then
forwards the selection to the background process so both see the same
profile: it passes `--profile NAME` when one was selected, and `--config PATH`
when set. The internal `internal-run` subcommand resolves again at startup and
exits nonzero with the error on stderr before binding the socket if resolution
fails. Environment bundle credentials are inherited by the child process as
they are today.

Socket and pid files move from `~/.config/turnkey/tk/` to `~/.config/turnkey/`,
next to the registry: `~/.config/turnkey/ssh-agent.sock` and
`~/.config/turnkey/ssh-agent.pid`. `--socket` and `--pid-file` keep working.

**Git passthrough.** Git invokes `tk -Y ...` with ssh-keygen style arguments
and cannot pass tk flags. The passthrough resolves with default options, so it
honors `TK_PROFILE`, then the environment bundle, then the active profile. The
git signing doc shows both ways to pin a profile: `tk profile use NAME`, or
`TK_PROFILE=NAME` in the environment git runs in. Its error output stays on
stderr as today.

### Profiles carry the signing key

The `Profile` schema already has `ssh_signing_key_id: Option<String>`. Two
commands set it:

- `tk login NAME --organization-id ID --api-key-file FILE [--ssh-signing-key-id ID]`
- `tk profile set NAME [--ssh-signing-key-id ID] [--organization-id ID] [--api-base-url URL]`

`profile set` takes the registry lock, requires at least one flag, validates
the URL with the existing endpoint parser, and rewrites the profile atomically.
`profile show` and `profile list` include `ssh_signing_key_id`. `auth status`
gains `"sshSigningKeyId": string | null`. Signing key IDs are opaque strings
(Turnkey private key IDs are UUIDs, but the field is passed through unchanged).

Outcome records: `profile.set` returns `{"name", "profile"}` with the redacted
profile as `profile show` does.

### `tk config` is removed

`tk/src/commands/config.rs`, the `Config` outcome variants
(`ConfigValue`, `ConfigValueSet`, `ConfigListed`), `tk/tests/config_command.rs`,
and the `Config file` section of `after_help` are deleted. The `Outcome` enum
keeps only the SSH variants. `tk config` becomes an unknown command
(`usage_error`, exit 2).

### Errors

All new failures are typed and flow through the existing taxonomy:

| Situation | Code | Message names the fix |
|---|---|---|
| No signing key on the resolved identity | `invalid_input` | `tk profile set NAME --ssh-signing-key-id ID` or `TURNKEY_PRIVATE_KEY_ID` |
| `profile set` with no flags | `usage_error` (clap `ArgGroup` required) | |
| `profile set` on an unknown profile | `invalid_input` | existing `profile NAME does not exist` |
| Daemon startup resolution failure | `invalid_input` or `command_error` | the child's stderr line is surfaced by `start` as the error chain |

### Documentation

- **README**: replace the Commands and Configuration sections. Commands:
  `tk login`, `tk auth`, `tk profile`, `tk api-key generate`, `tk ssh ...`,
  plus a pointer to `docs/unified-cli.md` for API commands and
  `docs/secrets.md`. Configuration: the three step resolution above, the
  registry path and `TK_CONFIG`, a profile walkthrough (`api-key generate`,
  register the public key, `login` with `--ssh-signing-key-id`), the
  environment bundle for CI, and a note that `tk.toml` is no longer read.
- **docs/git-signing.md** and **docs/ssh-agent.md**: point at the new README
  section, use `tk ssh public-key`, show `TK_PROFILE` for the passthrough, and
  the new socket path.
- **docs/unified-cli.md**: drop the sentence that says `tk config` and the SSH
  commands use `tk.toml`; add `profile set` and the login flag.
- **AGENTS.md**: restore the section below verbatim under `## Rust Workflow`
  or as its own heading:

  ```markdown
  ## Async I/O Policy

  All I/O in this repository should be Tokio async, including filesystem access.

  - Prefer `tokio::fs` over `std::fs`.
  - Prefer `tokio::io` traits and helpers over blocking std I/O.
  - Avoid blocking I/O inside async code paths.
  - If blocking work is unavoidable, isolate it explicitly with
    `tokio::task::spawn_blocking` and keep that usage narrow.
  ```

  The secrets module's synchronous fsync and rename sequence is the one
  documented exception; its comment already says why.

## Testing

Unit tests in `turnkey_auth::identity` cover: profile with and without a
signing key, env bundle with and without `TURNKEY_PRIVATE_KEY_ID`, explicit
profile ignoring the env bundle, and `--organization-id` override. `TurnkeySigner`
tests assert the `invalid_input` error when the signing key is missing.

Integration tests (`tk/tests`):

- `ssh public-key` and `ssh git-sign` succeed against wiremock using a
  registry fixture with `ssh_signing_key_id`, and using the env bundle.
- `ssh public-key` with a profile lacking a signing key returns
  `code: invalid_input` and the message names `profile set`.
- `tk -Y` passthrough picks the profile named by `TK_PROFILE`.
- `ssh agent start` forwards `--profile`; `status` reports the new default
  socket path; a start with no identity fails before creating the socket.
- `login --ssh-signing-key-id` and `profile set` persist the field with
  the registry still mode 0600; `profile set` with no flags is a usage error.
- `tk config` exits 2 with a usage error.
- Existing `config_command.rs` tests are deleted with the command.

All four gates pass: `cargo fmt --check`, `cargo clippy --all-targets -- -D
warnings`, `cargo build --workspace`, `cargo test --workspace`.

## Implementation order

1. Move identity code to `auth/src/identity.rs`; re-export from `tk`.
2. Add `ssh_signing_key_id` to `Identity`; switch `TurnkeySigner` to it.
3. Port `public_key`, `git_sign`, and the agent to `identity::resolve`; move
   the socket directory; forward the profile to the daemon.
4. Add `login --ssh-signing-key-id` and `profile set`.
5. Delete `auth/src/config.rs`, `tk config`, and their tests.
6. Rewrite README and the two SSH docs; update `docs/unified-cli.md`.
7. Restore the Async I/O Policy in `AGENTS.md`.

## Open questions

None. Decisions taken with the repository owner on 2026-09-09: remove
`tk config` outright; set the signing key through both `login` and
`profile set`; keep the environment bundle working for SSH commands; move the
agent socket next to the registry.
