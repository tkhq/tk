---
name: refactoring-iteratively
description: Use when asked to find refactors, simplify, clean up, or improve code in the tk repo with no line-count target given, or when a branch already conforms to AGENTS.md and the question is whether it can be made simpler, more correct, or faster.
---

# Refactoring Iteratively

## Overview

Hunt for refactors above the rule floor and apply them one at a time until a
fresh scan finds none worth doing. This is not conformance: a candidate is not a
violation of a written rule, it is an improvement with a payoff a reader can
name. Run `conforming-to-agents-md` first; this skill assumes a clean tree.

## Scope

With no argument: the branch diff from the merge base with `main` through the
working tree, including untracked files:

```bash
git add --intent-to-add . && git diff origin/main
```

With an argument, for example `/refactoring-iteratively tk/src/gpg`: every file
under that path, not the diff. On `main` with no argument, stop and ask for a
path.

## What qualifies

A candidate must state its payoff in one sentence using one of these verbs and a
concrete object: **removes** (a clone, an allocation, a lock, a branch, a type, a
lifetime, a duplicate), **collapses** (N arms, N helpers, N call sites into one),
**tightens** (a type so a state cannot be represented, a visibility, a contract),
**moves** (a fallible step to the boundary, a check to parse time). Anything
whose payoff needs a different verb is not a candidate.

A candidate is rejected at scan time if it:

- Changes a public function signature, a serialized shape, a CLI flag, or an error message text
- Restates a style preference with no payoff object
- Touches only tests, unless it collapses duplicated setup

## The loop

Track state in `<scratchpad>/refactor/`: `round-N.md` for raw reviewer output
and `round-N-merged.md` for the ranked list. Pass the merged file's path to
fixers rather than inlining the list. Every round:

**1. Scan.** Spawn three reviewers in parallel, read-only. Each prompt starts with:
"Read the entire `AGENTS.md` at the repo root before reviewing and apply it
throughout." Each also receives the candidates rejected or reverted in earlier
rounds under the heading "Already adjudicated, do not report". Each returns
candidate records in the shape below.

| Reviewer | Looks for |
|---|---|
| Simplicity | Duplication, one-use helpers, nested conditionals, impossible-state handling, defensive checks callers cannot trigger, wrapper types with one field and no invariant |
| Correctness | States a type allows but the code assumes away, checks repeated at several depths, fallible steps below the boundary, `String` where a domain type exists, silent defaults on malformed data |
| Performance | Clones of owned values on their last use, `.to_string()` in loops, repeated file or network reads for the same resource in one command, allocations a borrow would avoid |

**2. Rank.** Merge into one list. Drop any record failing the qualification test.
Order by payoff over blast radius: a one-file change that removes a duplicate
outranks a five-file change that tightens a type.

**3. Apply.** Spawn fixers in parallel when their changes touch disjoint files,
and combine candidates that touch the same file into one fixer, in rank order.
A fixer receives its candidates, the files it owns, the merged file path for
context, and:

> Apply these refactors completely, including every call site they touch,
> editing only these files: <file list>. Preserve behavior, public signatures,
> serialized shapes, and error text. Do not add doc comments to items you did
> not create. Then run `cargo +nightly-2026-09-01 fmt --all`, `cargo clippy --workspace
> --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`.
> If a test fails, revert your change with `git checkout -- <files>` and report
> why. Return one paragraph per candidate. Do not commit.

**4. Re-scan.** Go to step 1 with fresh reviewers. Stop when the ranked list is
empty, or after round 4. After round 4, report the open candidates instead of
continuing.

**5. Report.** Rounds run, refactors applied with their payoff sentences,
candidates reverted with the failing test, and the line `Changes applied: N`.

## Candidate record

```
file: tk/src/gpg/signer.rs
line: 23
payoff: removes a String allocation per signature by holding org_id as Uuid
blast: 2 files, 1 type, 0 public signatures
change: Store `Uuid` in `TurnkeySigner`; call `.to_string()` once at the wire call.
```

## Red flags

- A payoff sentence with "cleaner", "clearer", "more idiomatic", or "better"
- Applying a candidate the reviewer rated as marginal to have something to do
- Running two fixers on the same file at once
- Skipping `cargo test` because clippy passed
- Stopping because the remaining candidates are small, rather than because there are none
- Committing, amending, or pushing
