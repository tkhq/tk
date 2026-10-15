# Slop rules

Checklist for the slop reviewer. Each heading is a rule name; cite it in the
`rule` field of a finding. A finding must match one rule exactly. If it does not,
it is not slop.

## Comment restates code

A comment that says what the next line does in English. `// increment the counter`
above `count += 1`. Delete it. A comment earns its place by saying why.

## Change narration

`// Added to support X`, `// Previously ...`, `// Now we ...`, `// Refactored to ...`.
This belongs in the commit message. Delete it.

## Doc comment on untouched item

A `///` or `//!` added to or expanded on an item the branch did not create. Also a
doc comment on a private item that only restates its signature. Delete it.

## Section banner

`// ---- Helpers ----`, `// Step 3:`, `// Setup`, `// Act`, `// Assert`, or any
comment that labels a block instead of explaining it. Delete it.

## Hedging comment

`Note:`, `Important:`, a `TODO` with no owner or issue link, or "should",
"probably", "for now", "hopefully", "in theory" inside a comment. Either resolve
the uncertainty in code or delete the comment.

## Impossible-state handling

`unwrap_or_default` on a value that is always present, `if let Some` on an
infallible path, a match arm that errors on a variant callers cannot produce, a
check the type system already guarantees. Remove the handling. If the state is
reachable, that is a correctness bug, not slop; report it under the AGENTS.md
rule it violates.

## Name-only helper

A function with one caller whose body is shorter than its signature plus call
site, and whose name adds nothing the call site does not already say. Inline it.

## Test name says nothing

`test_works`, `test_basic`, `test_happy_path`, `it_works`, or a name that repeats
the function under test with no behavior stated. Rename to the behavior asserted.

## Weak assertion

`assert!(value.is_some())` or `assert!(value.is_none())` where the inner value is
available and could be compared. Replace with an equality on the value.

## Duplicated test setup

The same three or more lines of arrangement in three or more tests. Move to a
shared fixture or the existing `Run` helpers.

## Error message slop

A message that repeats the error type's name, ends with "please try again",
contains an exclamation mark, or apologizes. Rewrite to state what failed and
what the user can change.

## Leftover scaffolding

Commented-out code. Delete it.

## Prose filler

A sentence in a doc, skill, or help text that announces, summarizes, or
transitions instead of stating a fact or directing an action: "This section
explains", "In summary", "Note that", "As mentioned above".

## Prose hedging

"May", "might", "should generally", or "in most cases" in a doc or skill where
the code gives one behavior. State the behavior.

## Negative parallelism

"Not just X, but Y", "It's not X. It's Y.", or "not merely X" in a doc or skill.
State Y directly.

## Stale reference

A command, flag, path, record field, error code, or skill name in a touched doc
or skill that the tree no longer has, or that a later change on the branch
renamed.
