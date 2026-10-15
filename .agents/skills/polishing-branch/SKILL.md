---
name: polishing-branch
description: Use when a tk branch is finished and should be brought to review quality end to end, or when asked to "polish", "finish", or "get this ready" with no narrower instruction. Runs the conformance and refactoring skills in alternation over Rust code, docs, skills, and help text.
---

# Polishing a Branch

## Overview

Alternate `conforming-to-agents-md` and `refactoring-iteratively` until one full
cycle of both reports no changes. Both cover the branch's Rust code, `docs/`,
`skills/`, `README.md`, and help text; a branch that changes only prose still
runs the full loop. Refactors can introduce rule violations, and
conformance fixes can expose refactors, so neither skill alone reaches a fixed
point.

## The loop

Track cycles in `<scratchpad>/polish/cycles.md`. Every cycle:

1. Invoke `conforming-to-agents-md` with the Skill tool and follow it to its
   final report. Record its `Changes applied: N` line.
2. Invoke `refactoring-iteratively` with the Skill tool, no argument, and follow
   it to its final report. Record its `Changes applied: N` line.
3. If both lines read `Changes applied: 0`, stop. Otherwise start the next cycle.
4. If cycle 3 still applied changes, run cycle 4. After cycle 4, stop regardless
   and report which skill was still making changes.

Each invocation runs the full skill, including fresh reviewer sweeps. Do not
skip a skill because the previous cycle's run of it was clean; that is what the
stop condition in step 3 checks.

## Report

Cycles run, a table of changes applied per skill per cycle, the final test
result from the last skill run including the skills and docs checks, and a `git diff --stat origin/main` of the tree.
Nothing is committed; say so.
