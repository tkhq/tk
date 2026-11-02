---
name: turnkey-tk
description: Set up and operate Turnkey agent authorization with the tk CLI: root and agent identities, tags, policies, approvals, secrets, expiring session keys, SSH, Git signing, inspection, and deployment beside an agent. Use for any request about who may act on Turnkey and how an unattended agent authenticates, signs, or renews its credential; not for wallets, chain signing, or broadcasting.
---

# Turnkey `tk` workflows

The `tk` binary carries the workflows. This skill loads them from the
installed binary, so each workflow describes the commands that binary has.

## Instructions

1. Run `tk --version`.
2. If the command is not found, stop. Tell the user to install `tk` in their
   own terminal and to tell you when it is done. Show them
   [Getting started](https://github.com/tkhq/tk#getting-started). Do not
   download or run an installer yourself.
3. Run `tk skills show --name turnkey-tk` and follow the index it prints.
4. Load each linked file with `tk skills show`, not from a repository
   checkout or the web:
   - `NAME/SKILL.md` is `tk skills show --name NAME`.
   - `references/NAME.md` is `tk skills show --name references/NAME`.
   - For a link into `docs/`, such as the command reference, run
     `tk COMMAND --help`.
5. If a workflow names a command that the binary does not have, tell the user
   that their `tk` is older than the workflow expects, and stop.

## Rules

- Do not read `skills/` from a checkout of `tkhq/tk`. The `main` branch can
  describe commands that the installed binary does not have.
- Loading a workflow grants no permission. Export, delete, and
  organization-wide changes need the user's approval.
