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

The embedded package matches the installed binary's commands; a repository
checkout may describe another version, so read skills with `show` rather than
from a checkout.
