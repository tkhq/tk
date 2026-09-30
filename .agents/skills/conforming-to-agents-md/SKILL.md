---
name: conforming-to-agents-md
description: Use when a tk branch is about to be marked ready for review, or when asked to check a PR against AGENTS.md, remove dead code, de-slop, or clean up a branch before merge. Also use after finishing any feature work in this repo, before opening or un-drafting the PR.
---

# Conforming to AGENTS.md

## Overview

Drive a branch to zero violations of `AGENTS.md`, zero dead code, and zero slop by
looping: sweep with parallel reviewers, fix findings with serial fixers, re-sweep.
The loop ends only when a fresh sweep returns nothing.

A finding is a definite violation of a written rule. Hedged observations are not
findings and are dropped at sweep time.

## Scope

With no argument: the branch diff from the merge base with `main` through the
working tree, including uncommitted and untracked files:

```bash
git add --intent-to-add . && git diff origin/main
```

Findings are then limited to lines the branch touched and code the branch made
dead. Pre-existing violations in untouched code are out of scope. Say so if a
reviewer reports one, and drop it.

With an argument, for example `/conforming-to-agents-md tk/src/gpg` or
`/conforming-to-agents-md tk auth`: every file under those paths, not the diff.
Reviewers get the file list instead of the diff command, and every violation in
those files is in scope. The slop rule "Doc comment on untouched item" applies
only through its second sentence, since there is no diff to define "untouched".

## The loop

Track state in `<scratchpad>/conformance/`: `round-N.md` for the raw reviewer
output and `round-N-merged.md` for the merged list. Pass the merged file's path
to fixers rather than inlining the list. Every round:

**1. Mechanical pass.** Run directly, no agents:

```bash
cargo +nightly-2026-09-01 fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff origin/main | grep -n '^+.*#\[allow('     # diff mode
grep -rn '#\[allow(' <paths>                        # path mode
```

Fix anything reported before any reviewer runs. A new `#[allow(...)]` is a finding
unless it carries a `reason` naming the specific false positive.

**2. Sweep.** Spawn three reviewers in parallel, each read-only, each given the
scope (diff command or file list), the finding record format below, and the list
of findings skipped in earlier rounds under the heading "Already adjudicated, do
not report". Each reviewer's prompt starts with: "Read the entire `AGENTS.md` at
the repo root before reviewing and apply it throughout."

| Reviewer | Checklist |
|---|---|
| Rules | Every section of `AGENTS.md` except Reviews |
| Dead code | Items nothing uses: functions, fields, variants, derives, `pub` on module-local items, arms for inputs no caller produces, imports, features, tests of deleted code |
| Slop | [slop-rules.md](slop-rules.md) in this skill's directory |

**3. Merge.** Concatenate the three lists into one numbered list. Delete any
record whose `rule` field is empty or whose `summary` field, in the reviewer's own
words and not in quoted rule text, contains "consider", "borderline",
"acceptable", "minor", "not harmful", or "may". Two records with the same file
and line are duplicates regardless of rule; keep the one whose rule is an
`AGENTS.md` sentence. Records with the same file, same rule, and same fix
collapse into one record listing every line. Order by rule violations first,
then dead code, then slop.

**4. Fix.** Spawn fixers in parallel when their fixes touch disjoint files, and
combine findings that touch the same file into one fixer. A fixer receives its
findings, the files it owns, the merged file path for context, the rule text
each violates, and this instruction:

> Fix these findings completely. Make whatever refactor the fix genuinely needs,
> including changes outside the cited lines, editing only these files:
> <file list>. Do not add doc comments to items you did not create. Delete a
> unit test as covered by an e2e test only when, by reading the e2e test, every
> assertion of the unit test is provably covered; you cannot run the e2e suite.
> Then run `cargo +nightly-2026-09-01 fmt --all`, `cargo clippy --workspace --all-targets --locked
> -- -D warnings`, and `cargo test --workspace --locked`. Return one paragraph
> per finding saying what changed, including any change beyond the cited lines.
> Do not commit.

If a fixer reports a finding was wrong, record why in the round file and carry
it forward as adjudicated.

**5. Re-sweep.** Go to step 1 with fresh reviewers. Never reuse a reviewer from a
previous round. Stop when a sweep produces an empty merged list, or after round
4. After round 4, report every open finding verbatim instead of continuing.

**6. Final gate.** Run `cargo test --workspace --locked` once. Do not run the e2e
suite; it targets a live organization. Report: rounds run, findings fixed grouped
by rule, findings skipped with reasons, the test result, and the line
`Changes applied: N` where N counts fixes that landed.

## Finding record

Every reviewer returns findings only in this shape. Anything else is discarded.

```
file: tk/src/gpg/keys.rs
line: 236
rule: Coding style — "Default to inlining one-use helpers"
summary: `next_free_index` has one caller and adds no name the call site lacks.
fix: Inline the body into the `Create` arm and delete the function.
```

The `rule` field quotes the `AGENTS.md` sentence, or names the slop rule by its
heading, or reads `dead code`. No other values.

## Red flags

Stop and re-read this skill if you notice yourself:

- Reporting findings to the user instead of fixing them
- Fixing findings yourself inline instead of spawning a fixer
- Running two fixers on the same file at once
- Letting a fixer tell you the tree is clean instead of re-sweeping
- Keeping a hedged finding because "it's probably right"
- Overriding an `AGENTS.md` rule because the fix looks worse; the rule is the
  authority, and the place to argue is a PR against `AGENTS.md`
- Stopping because the list is short, rather than because it is empty
- Committing, amending, or pushing
