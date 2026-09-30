# AGENTS.md

Default guidance for coding-agent runs in this repository.

## Reviews

- Before starting any code review, read this entire `AGENTS.md` and apply its
  guidance to the review.
- When delegating a review to a sub-agent, explicitly instruct the sub-agent to
  read this entire `AGENTS.md` before reviewing and to follow it throughout the
  review.

## Coding style

- Lints live in `[lints]` in the root `Cargo.toml`. Add a lint there, not as a
  crate-level `#![deny(...)]`. An `#![allow(...)]` belongs only in the one file
  that needs the exception, with a comment saying why.
- Prefer raw string literals (`r#"..."#`) over escaped quotation marks (`\"`) or
  escaped newlines (`\n`) for any nontrivial string or multi-line output (e.g.
  `human_message` bodies, help text, JSON fixtures, test goldens). Lay the text
  out on real lines so it reads as it renders. If a line ends in significant
  trailing whitespace, still use a raw literal but add a comment noting the
  trailing whitespace so editors/formatters don't silently strip it.
- Prefer moving owned values over cloning them. If you already own a value and
  this is its last use (e.g. building the return value at the end of a
  function), move it out — use `.into_iter()` or partial field moves instead of
  `.clone()`.
- Don't hide clones inside functions. A function or `From`/`TryFrom` impl should
  take an owned value (`T`, not `&T`) rather than clone internally; prefer
  `From<T>` over `From<&T>`. When a clone is genuinely needed, make it explicit
  at the call site — e.g. `value.clone().into()` or
  `items.iter().cloned().map(Into::into)`.
- Prefer short (imported) names over fully-qualified paths. Add a `use` and
  write `impl Display for Foo { fn fmt(&self, f: &mut Formatter<'_>) … }` rather
  than `impl std::fmt::Display for Foo { … std::fmt::Formatter … }`. Only keep a
  longer/module-qualified form when it disambiguates from another in-scope name —
  e.g. `fmt::Result` stays qualified (via `use std::fmt::{self, Display, Formatter}`)
  so it doesn't collide with `anyhow::Result`, and `std::fmt::Write` may need
  `as _` where `std::io::Write` is also in scope.
- Format with `cargo +nightly-2026-09-01 fmt --all`, the toolchain the CI `fmt`
  job pins.
- A comment exists in exactly three cases. A `///` or `//!` that the
  `missing_docs` lint demands. A `///` on a Clap command, field, or variant,
  which renders as `--help` text. A `//` stating an invariant a reader cannot
  recover from the code in front of them: an ordering the types do not
  enforce, a constraint imposed by an external protocol or API, or a platform
  quirk the code works around. Every other comment is deleted: one that
  restates the code, narrates the change, labels a block, hedges, or explains
  a *why* the code could carry. Reaching for that last kind means reshaping
  the code so the reason is the code. The `//` above an `#[allow(...)]` is an
  invariant of the third kind and names the specific false positive.
- A module's doc is a `//!` in its own root file, never a `///` on the `mod`.
  Public docs are one line and state the contract, not the mechanism.
- In doc comments and module docs, describe responsibilities, contracts, and
  relationships without naming specific source files or inventorying current
  consumers. File paths and call-site lists go stale when code moves. When a
  relationship matters, prefer Rustdoc intra-doc links to stable items (for
  example, [`ErrorCode`] or [`crate::errors::classify`]) and describe other
  participants by their role, such as "the CLI output layer" or "callers."
  Reference an exact path only when the path itself is part of an operational
  or compatibility contract (for example, a user-facing config location or
  migration input), or when no stable symbol exists.
- When converting from an external/generated API type into one of our own
  structs, destructure it
  exhaustively — `let Foo { a, b, c: _ } = value;` with no trailing `..` —
  rather than reading fields with `value.a`. Bind the fields you use and
  `_`-bind the ones you don't. This way, when the upstream type gains a field, the destructure
  fails to compile and forces a deliberate decision about whether the new field
  belongs in our output — instead of it being silently dropped. Skip this only
  where it adds noise for no value, e.g. reading one or two fields off a large
  API response result.
- In `tracing` calls, use field shorthand when the variable name matches the
  field name — `%value` for `Display`, `?value` for `Debug` — rather than
  `value = %value`. Use `#[instrument(skip(arg))]` for noisy or sensitive
  arguments and `#[instrument(level = "debug", ret, err)]` when return or
  error logging helps.

## CLI boundaries

- Use Clap field types, defaults, value parsers, argument groups, and conflicts
  to enforce CLI invariants during parsing instead of recreating the same
  validation in command execution.
- Keep fields on Clap `Args` structs private unless another construction path is
  intentional. Downstream functions should accept validated domain inputs, not
  a publicly constructible bag of CLI options.
- Reject incompatibilities that can be determined from parsed CLI arguments
  immediately after parsing, before loading configuration or credentials,
  authenticating, signing, or making network requests. If validation requires
  configuration, load only the configuration needed for that validation first.

## Types and data flow

- Prefer types that cannot represent invalid state combinations. Use enums,
  domain wrappers, and private constructors to encode mutually exclusive
  choices and required relationships.
- Keep each identity or decision in one authoritative place. Do not duplicate
  values across related structs when they could diverge.
- Parse identifiers whose domain contract guarantees a specific format into the
  corresponding domain type, such as `Uuid`, at CLI, config, and API boundaries.
  Do not assume that every field named `*_id` is a UUID; preserve opaque or
  forward-compatible identifiers as strings or dedicated domain wrappers.
  Compare typed values internally and convert them to strings only when an
  external wire type requires it.
- Parse, don't validate: run the fallible check once, at the boundary, and
  return a narrow domain type that carries the proof. Downstream code takes
  that type and transforms it infallibly instead of repeating the check deeper
  in the call stack. Watch for validation disguised as parsing: before writing
  a function named `is_*`/`check_*`/`verify_*`/`validate_*`, or one that
  inspects data and returns `bool` or `Result<(), E>`, ask where the proof
  goes — if callers continue with the same type they passed in, that is
  validation; return the parsed type instead. `Result<(), E>` is the usual
  disguise: it reads as parsing because it is fallible, but the unit return
  discards the evidence.
- Prefer infallible constructors. A constructor assembles an already-valid
  value; it does not acquire what it needs. Do fallible acquisition — loading
  config, resolving addresses, opening handles, fetching credentials — before
  construction and pass the finished dependencies in, concentrating failure
  handling at the wiring layer. Reserve a fallible constructor for a type
  that exists to hold a live, long-lived resource, where constructing and
  connecting are genuinely the same operation.
- Keep call stacks flat. Default to inlining one-use helpers — a let-bound
  block (`let approved = { … };`) names the result without adding a
  signature. A helper must earn its boundary: actual repeated callers
  (extract on the third occurrence, not in anticipation of reuse), a
  genuinely generic unit, an intentional `pub` surface, or a name that states
  intent the body only shows as mechanism. Keep a one-use helper when inlining
  it would push the caller past about 60 lines, add a level of nesting inside
  a loop or match arm, or need a labeled block. A `.clone()` added only to
  satisfy an extracted signature means the boundary is wrong — dissolve the
  helper rather than pay the clone.
- Match enums exhaustively when variants require distinct behavior. Use a
  wildcard only when all current and future non-target variants are
  intentionally handled alike.

## I/O, errors, and compatibility

- Perform config loading, authentication, and network work only on paths that
  require them. Explicit or offline inputs must not depend on unrelated config
  being present or well-formed.
- Treat serialized TOML and JSON shapes as compatibility boundaries. Keep
  runtime types distinct from persisted schemas when a migration needs
  different fields, and make migration timing and write-back behavior explicit.
- Keep missing data distinct from malformed data. Default only for intentional
  absence; surface malformed persisted or API values with the field, path, and
  operation needed to diagnose them.
- Prefer typed errors when callers need to make recovery decisions. Add
  user-facing remediation at the command layer instead of embedding a specific
  CLI command in reusable helpers.
- Preserve typed errors through `anyhow` chains so machine classification can
  downcast them. Add operation and identifier context with `.context()` or
  `.with_context()`; do not stringify an error with `anyhow!("{error}")` or
  `bail!("{error}")`, because that discards its type and source chain.
  Classify new upstream error variants explicitly rather than adding a
  wildcard fallback.
- Use `MissingResource::new` only when a lookup request succeeded but its
  decoded response omitted the expected resource, such as an optional payload
  being `None`. This means callers should verify or re-resolve the identifier
  or prerequisite state; it does not imply that blindly retrying the same
  lookup will help. Pass a stable resource noun and the most actionable
  identifier, for example `MissingResource::new("deployment", deployment_id)`.
  Do not use `MissingResource` for unsuccessful HTTP responses; propagate the
  typed `TurnkeyClientError` so its status and response body remain available.
- Do not render runtime errors at call sites. Pass the `anyhow::Error` to the
  output boundary so human and JSON modes use the same chain rendering,
  truncation, classification, and HTTP-status behavior.
- Prefer `thiserror` derives for error types whose `Display` is a straightforward
  field-formatting template. Reserve manual `Display` and `Error`
  implementations for behavior the derive cannot express clearly.
- Implement `Display` for domain values used in user-facing errors rather than
  hard-coding their variants at call sites.

## Tests and verification

- Prefer end-to-end tests over unit tests. Cover a behavior in the real-binary
  `tests/e2e/` suite first; add a unit or mock-server test only for a failure
  mode the live API cannot produce on demand (transport timeouts, malformed
  responses, rejected or failed activities) or for local parsing that needs no
  server. Delete a unit test once an e2e test covers the same behavior.
- Prefer complete structural equality when the complete value or serialized
  shape is the contract. Use focused field or predicate assertions when a test
  deliberately covers only one property and unrelated fields are outside its
  scope; avoid substring assertions when an exact structured representation is
  available. Use test-only `Debug` and `PartialEq` derives when those traits
  should not expand the release API.
- Avoid `unreachable!()` in tests; use exact equality, pattern assertions, or a
  descriptive failure.
- Test CLI parsing for the defaults, conflicts, and typed values that form part
  of our interface. Avoid duplicating Clap's validation as deeper command
  validation tests.
- Test migrations and serialized compatibility by parsing the complete output
  into the target schema and comparing it with a complete expected value.

## End-to-end tests

- When adding a new `tk` command or feature, or changing the JSON record shape
  of an existing one, add or update the matching test in the `tests/e2e/`
  module (one file per command area; the runner lives in `run.rs`) so the
  real-binary suite keeps covering it. Keep every file under 1000 lines. Run
  it with `cargo test --test e2e -- --ignored`; the suite runs in parallel and
  must stay correct that way.
- Every e2e test starts with `Run::new()`, which creates a sub-organization
  named with the run marker, rooted by the admin key from `.env.test`, and
  deletes it, with everything inside, when the `Run` drops. Run every command
  through the runner's bundles (`admin()` for the root, `as_user()` for users
  the test created) so it targets that sub-organization; never address the
  parent organization or another test's resources. Do not add per-resource
  cleanup: the sub-organization deletion is the cleanup. A test that needs a
  non-root actor creates the user with `run.create_user()` and a policy that
  allows it, as the consensus test does.
- Submissions may legitimately return `pending` while the API is busy. Use
  `run.submit(cmd, "<command>")`, which asserts the command on the initial
  response and returns the completed record, instead of asserting completion
  on the first response.
- The runner retries transient outcomes with exponential backoff: transport
  errors and HTTP 429/5xx at every call, and server-side `FAILED` activities
  by re-submitting the command. A 429 waits longer than other transient
  failures because the API blocks the whole organization family for a minute
  once its shared request bucket empties; CI also caps the suite at four
  threads for the same reason. Tests must not add their own sleeps or retry
  loops, and must not retry to make an assertion pass; if a test is flaky,
  fix the runner's policy or the test's assumption.

## Skills and docs

- A pull request that adds or changes a command touches, in the same PR: the
  command, its `--help`, the description in `docs/<area>.md`, any step in
  `skills/` that invokes it, and the e2e test that executes that step. The
  structural checks in `tests/skills.rs` and `src/skills/` catch missing
  links, unparseable examples, unmapped `## Verified by` tests, and diverged
  shared blocks; they cannot prove prose was updated, so review remains part
  of the rule.
- Command behavior, records, and errors live in `docs/<area>.md`. Multi-step
  operator procedures, policy patterns, the approval matrix, and workflow
  recovery live in `skills/`. A doc links to the skills that use its commands
  in a `## Skills` footer; a skill lists the docs it depends on in a
  `## Reference` section and does not restate flag inventories.
- Every fenced `sh` block in `skills/` that invokes `tk` carries an
  `<!-- example: <id> -->` line directly above it; `## Verified by` maps those
  ids to `module::test` names in the e2e suite. A block that must stay
  identical across files carries `<!-- shared: <id> -->`.

## Docs

- An area doc, `docs/<area>.md`, addresses someone running `tk`. It opens with
  a title naming the area, one or two sentences saying what the commands do,
  the line `Follow [authentication](./authentication.md) first.` when they need
  a credential, and then its first fence or diagram. Repository process, such
  as releasing, CI jobs, and the test suite, lives in `docs/releasing.md` or
  this file, never in an area doc.
- A section that shows commands opens with its fence, or with one sentence
  ending in a colon that introduces the fence. Explain a command with a `#`
  comment on the line above it inside the fence, written as a sentence. Prose
  after the fence is one paragraph and covers only what the command line
  cannot show: exit status and error code, what a record field means, what is
  written or deleted and where, and what never happens. A paragraph that
  sequences commands is a procedure and belongs in `skills/`.
- State each fact once across `docs/`. Do not repeat in prose what a fence
  comment already says. A behavior another doc owns, such as the pending
  activity flow, gets one sentence and a relative link, `see
  [activities](./activities.md)`, not a restatement.
- Do not inventory flags or record fields. `docs/commands.md` is generated for
  flags; a doc shows a flag only inside a command that demonstrates its
  behavior, and names a record field only where the reader acts on it. Show
  one command per behavior; when several subcommands take the same flags, show
  one and say so in its comment rather than listing each.
- Name statuses and error codes by their machine value in backticks, such as
  `pending` and `api_error`, and subcommands by their bare name in backticks,
  such as `wait` and `create`.
- Placeholders the reader substitutes are `UPPER_SNAKE`, such as `WALLET_ID`,
  `ACTIVITY_ID`, and `ORG_UUID`. A value whose shape matters keeps a literal
  example instead, such as `you@example.com`, `0x…`, and `7d`. Profile names in
  examples are `admin`, `agent`, `approver`, and `provisioner`. Shell fences in
  an area doc are `bash`.
- The `## Skills` footer is the last section of a doc at least one skill uses,
  with one line per skill in the form
  `- [name](../skills/name/SKILL.md): what that skill does with this doc's commands.`
  Two docs never carry the same footer sentence.
- `docs/commands.md` is generated; never edit it by hand. Change the command
  and regenerate with `TK_UPDATE_COMMANDS_MD=1 cargo test commands_reference`.

## Help text

- Every visible command, positional, and flag has help. Its first line is one
  sentence stating what the command or value does. A second paragraph exists
  only for behavior the flags cannot show and that matters before running:
  what never happens, a security consequence, a precondition. Procedures and
  mechanism belong in `skills/` and `docs/`.
- Help never inventories other flags, subcommands, or record fields, and never
  says a flag is repeatable or lists its possible values; clap and the
  generated reference render those. State each fact once: on the flag it
  describes, not again on the command.
- Statuses, error codes, record fields, and other commands appear in
  backticks; literal examples stay literal. Value names are `UPPER_SNAKE`.
- The root help states prompting, JSON output, and exit codes, and points at
  the `cli-convention` reference for record shapes and error codes. A test
  binds the error-code table in that reference to the `ErrorCode` enum.
