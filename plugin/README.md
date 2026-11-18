# tk plugin for Claude Code

This plugin adds the `turnkey-tk` skill to Claude Code. The skill does not
contain the workflows. It reads them from the installed `tk` binary with
`tk skills show`, so each workflow matches the commands that binary has.

Install `tk` first. See
[Getting started](https://github.com/tkhq/tk#getting-started).

```
/plugin marketplace add tkhq/tk
/plugin install tk@tkhq
```
