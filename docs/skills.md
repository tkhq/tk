# Skills

List, read, and install the `turnkey-tk` agent skills package that ships
inside the `tk` binary. These commands run offline and need no credential.

```bash
# List the package index and every workflow with its description.
tk skills list

# Print one skill as Markdown; `turnkey-tk` is the index and
# `references/NAME` a reference.
tk skills show --name managing-policies

# Install the package as DIR/turnkey-tk, with the docs it links beside it.
tk skills install --into DIR
```

## Skills

- [configuring-agent-permissions](../skills/configuring-agent-permissions/SKILL.md): the first workflow after `install`, proposing harness settings, for example for Claude Code or Codex, that let an agent run `tk` without prompting.
