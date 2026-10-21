# Authentication

`tk` authenticates with a Turnkey API key stored in a named profile.

```bash
# Create a profile with a fresh credential, then register the printed public
# key with Turnkey.
tk profile create --profile-name admin --organization-id ORG_UUID

# Verify the credential with Turnkey and select the profile.
tk login --profile-name admin

# Check the selection.
tk auth status
tk whoami
```

Several profiles can share one machine:

```bash
tk profile list
tk profile show --profile-name agent
tk profile use --profile-name agent
tk --profile agent whoami
export TK_PROFILE=agent

# Change a profile's organization, API endpoint, or credential file.
tk profile set --profile-name agent --organization-id OTHER_ORG_UUID
tk profile set --profile-name agent --api-key-file ~/.config/turnkey/tk/api-keys/02….json

# Forget a profile. Credential files are kept.
tk profile delete --profile-name agent
tk auth logout
```

The registry lives at `~/.config/turnkey/tk.config.toml` and generated
credentials under `~/.config/turnkey/tk/api-keys/`.

## YubiKey

A profile can sign with a P256 key that never leaves a YubiKey, so every
Turnkey request waits for a touch:

```bash
# Generate the key on the YubiKey in any signing slot. tk refuses a key that
# needs the PIN, signs without a touch, or was imported.
ykman piv keys generate --algorithm eccp256 --pin-policy never --touch-policy cached 9a -

# Save the profile. Reading the public key from the slot needs no touch.
tk profile create --profile-name admin --organization-id ORG_UUID --yubikey-slot 9a

# Register the printed public key with Turnkey, then touch the YubiKey to log in.
tk login --profile-name admin
```

With touch policy `cached`, one touch covers the requests of the next 15
seconds, so a command that polls, such as `activity wait`, needs a touch about
every 15 seconds; with `always`, every request needs its own touch. `tk` never
asks for the PIV PIN, writes to the YubiKey, or uses its management key, so
anyone holding the YubiKey can touch it. `auth status` and `profile use` fail
when the YubiKey is unplugged or the slot holds a different key, and
`session request` refuses a YubiKey profile because a session key would
replace the YubiKey key with one stored on disk. The macOS release includes
YubiKey support; on Linux, install `libpcsclite-dev` and run
`cargo install turnkey_tk --features yubikey`.

## CI

Skip the registry and pass the credential through the environment:

```bash
export TURNKEY_ORGANIZATION_ID=ORG_UUID
export TURNKEY_API_PUBLIC_KEY=API_PUBLIC_KEY
export TURNKEY_API_PRIVATE_KEY=API_PRIVATE_KEY
export TURNKEY_API_BASE_URL="https://api.turnkey.com" # optional
tk whoami
```

`--profile` or `TK_PROFILE` wins over the environment bundle, which wins over
the active profile. Credential secrets are never accepted as arguments.

## Skills

- [bootstrapping-organization](../skills/bootstrapping-organization/SKILL.md): the root profile and tags an organization needs before its first agent.
- [managing-identities](../skills/managing-identities/SKILL.md): creating users and rotating the credentials profiles hold.
- [provisioning-agent-identity](../skills/provisioning-agent-identity/SKILL.md): generating the agent's credential with `profile create` on its own host and proving the identity with `whoami`.
- [revoking-agent-keys](../skills/revoking-agent-keys/SKILL.md): the revoker host's own credential and the `whoami` failure that proves a deleted key is dead.
- [provisioning-session-agent](../skills/provisioning-session-agent/SKILL.md): the agent profile that session keys are activated into and the `whoami` check after each renewal.
- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): confirming a renewed key with `whoami` as the agent and pinning `HOME` and `TK_PROFILE` for every process that runs `tk`.
