---
name: configuring-agent-permissions
description: Propose the agent harness permission settings, for example for Claude Code or Codex, that let an agent run tk without a prompt on every call, for the human to review and apply. Use right after installing tk and this package, or when an agent harness keeps prompting for tk commands; not for Turnkey policies, which bound what the agent's credential can do.
---

# Configuring agent permissions

Result: the agent's harness runs `tk` without prompting, under settings the
human read and applied, with `TK_PROFILE` pinned to the agent's profile.

## Reference

- [authentication](../../docs/authentication.md): profiles, `TK_PROFILE`, and the `whoami` record.
- [skills](../../docs/skills.md): installing this package.

## Rules

- Opt-in only. The agent prints the proposed settings and the file they go
  in, then stops. The human applies them. The agent never writes harness
  permission config itself, even when a harness would let it.
- Turnkey policy, not the harness, bounds what the agent's credential can do.
  Allowing `tk` for a profile whose user is a policy-scoped agent is
  reasonable for that reason.
- A prefix rule cannot exclude a flag: an allow for `tk` also allows
  `tk --profile admin whoami`. Propose the blanket `tk` allow only when this
  machine holds no root credential, or the root quorum needs more approvers
  than the credentials here. Otherwise allow only the subcommands the
  workflow repeats, with the subcommand first and flags after it, so each
  call matches its rule; anything else still prompts.
- Set `TK_PROFILE` to the agent's profile in the harness environment, so
  calls need no `--profile` and never fall through to the active profile.
- Prefer one plain `tk` command per call. A pipe, redirection, or `$(...)`
  can make the harness judge the whole line instead of the `tk` part.

## Instructions

Inputs: the harness, for example Claude Code or Codex, and the agent's profile name
(`agent`).

1. **List the profiles on this machine.**

   <!-- example: permissions.profile-list -->
   ```sh
   tk profile list
   ```

   Ask the human whether any listed profile is root. If one is, and the
   root quorum can act on that credential alone, use the narrow form in
   steps 2 and 3.

2. **Claude Code example: propose the settings.** The target is the user settings
   file, `~/.claude/settings.json`; `autoMode` is read only from user or
   managed settings or `--settings`, never from a project's
   `.claude/settings.json`. Merge into existing keys; do not replace them.

   ```json
   {
     "env": { "TK_PROFILE": "agent" },
     "permissions": { "allow": ["Bash(tk:*)"] },
     "autoMode": {
       "environment": [
         "$defaults",
         "**Primary use**: agent tooling for git signing, ssh, and credential management with Turnkey",
         "**Org-specific CLIs**: tk — routine in this workflow"
       ]
     }
   }
   ```

   Allow rules resolve before the auto mode classifier, so a matched `tk`
   call skips it; `autoMode.environment` gives the classifier context for
   the rest, and `"$defaults"` keeps its built-in entries. The narrow form
   replaces `Bash(tk:*)` with one rule per subcommand, such as
   `Bash(tk whoami:*)` and `Bash(tk gpg:*)`. Print the path and the merged
   JSON, and stop for the human.

3. **Codex example: propose the rules.** The target is `~/.codex/rules/default.rules`
   (a repository's `.codex/rules/*.rules` load only when the project is
   trusted):

   ```
   prefix_rule(
       pattern = ["tk"],
       decision = "allow",
       justification = "Turnkey policy bounds the agent profile",
   )
   ```

   And in `~/.codex/config.toml`:

   ```
   [shell_environment_policy]
   set = { TK_PROFILE = "agent" }
   ```

   The most restrictive matching rule wins, `forbidden` over `prompt` over
   `allow`. The narrow form lists subcommands, such as
   `pattern = ["tk", ["whoami", "gpg"]]`. Print both paths and snippets, and
   stop for the human.

4. **Verify after the human applies them.** Start a new session so the
   harness reloads its settings, then run:

   <!-- example: permissions.whoami -->
   ```sh
   tk whoami --message-format json
   ```

   It runs without a prompt and `data.userId` is the agent's user. In the
   Codex example, the human can also check the rule offline with
   `codex execpolicy check --pretty --rules ~/.codex/rules/default.rules -- tk whoami`.

5. **Hand off.** Report the harness, the files the human changed, whether
   the blanket or narrow form was chosen and why, and the `whoami` result.
   Stop.

## Verified by

| Examples | Test |
|---|---|
| permissions.profile-list, permissions.whoami | identity::profile_selection_beats_ambient_and_active_profile |

The human applies the harness settings; the suite runs no harness.

## Troubleshooting

- `tk` still prompts in the Claude Code example: the session predates the
  change, the call starts with something other than `tk` (an env
  assignment, a pipe), the narrow rules omit that subcommand or put a flag
  before it, or `autoMode.classifyAllShell` is `true`, which suspends every
  shell allow rule. Inspect the effective rules in `/permissions`;
  `claude auto-mode config` prints the merged `autoMode`.
- The classifier ignores `autoMode.environment`: it sits in a project
  `.claude/settings.json`. Move it to `~/.claude/settings.json`.
- `tk` prompts in the Codex example: the line has a redirection or
  `$(...)` and is matched as a whole. Split it into plain commands.
- `whoami` reports the wrong user: `TK_PROFILE` is not set in the harness
  environment, or names another profile. Fix the setting, not the call.
- The agent was asked to edit `~/.claude/settings.json` or `.codex/` itself:
  decline, print the snippet, and let the human apply it.

## Related Skills

- [provisioning-agent-identity](../provisioning-agent-identity/SKILL.md): the agent user and profile that `TK_PROFILE` names.
- [managing-policies](../managing-policies/SKILL.md): the Turnkey policies that bound what the allowed `tk` calls can do.
- [sidecar-patterns](../sidecar-patterns/SKILL.md): pinning `HOME` and `TK_PROFILE` for every process that runs `tk`.
