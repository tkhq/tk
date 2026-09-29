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
- [provisioning-agent-identity](../skills/provisioning-agent-identity/SKILL.md): generating the agent's credential with `profile create` on its own host and proving acceptance with `whoami`.
- [provisioning-session-agent](../skills/provisioning-session-agent/SKILL.md): the agent profile that session keys are activated into and the `whoami` check after each renewal.
- [sidecar-patterns](../skills/sidecar-patterns/SKILL.md): confirming a renewed key with `whoami` as the agent and pinning `HOME` and `TK_PROFILE` for every process that runs `tk`.
