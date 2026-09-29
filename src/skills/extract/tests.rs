// Test fixtures and assertions may panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::cli::Cli;
use crate::errors::{ActivityError, ActivityErrorKind, UnexpectedHttpStatus};
use crate::operations::OperationOutput;
use crate::output::ErrorMessage;
use anyhow::Error;
use clap::Parser;
use clap::error::ErrorKind;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::LazyLock;
use strum::IntoEnumIterator;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

static PUBLIC_KEY: LazyLock<String> =
    LazyLock::new(|| hex::encode(TurnkeyP256ApiKey::generate().compressed_public_key()));

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "plans") {
                continue;
            }
            markdown_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
}

static DOCUMENTED_MARKDOWN: LazyLock<Vec<(PathBuf, String)>> = LazyLock::new(|| {
    let repo = repo_root();
    let mut paths = Vec::new();
    for root in ["skills", "docs"] {
        let before = paths.len();
        markdown_files(&repo.join(root), &mut paths);
        assert!(
            paths.len() - before >= 5,
            "{root} documentation tree looks empty: {paths:?}"
        );
    }
    paths.push(repo.join("README.md"));
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            (path, text)
        })
        .collect()
});

fn parse(argv: &[String]) -> Result<(), clap::Error> {
    match Cli::try_parse_from(argv) {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[test]
fn every_documented_tk_invocation_parses_against_clap() {
    let mut failures = Vec::new();
    let mut checked = 0usize;
    for (path, text) in DOCUMENTED_MARKDOWN.iter() {
        let Document { fences, spans } = document(text);
        let mut blocks = Vec::new();
        for fence in fences {
            match fence.lang {
                Lang::Shell => blocks.push((fence.start_line, fence.body)),
                Lang::Unknown(text) => failures.push(format!(
                    "{}:{}: unknown fence language `{text}`",
                    path.display(),
                    fence.start_line
                )),
                Lang::Json | Lang::Yaml | Lang::Mermaid | Lang::Plain => {}
            }
        }
        for (line, body) in blocks
            .into_iter()
            .chain(spans.into_iter().map(|s| (s.line, s.text)))
        {
            match script(path, line, &body, &PUBLIC_KEY) {
                Ok(script) => {
                    for argv in script.invocations {
                        checked += 1;
                        if let Err(error) = parse(&argv) {
                            failures.push(format!("{}:{line}: {argv:?}\n{error}", path.display()));
                        }
                    }
                }
                Err(unsupported) => failures.push(unsupported.to_string()),
            }
        }
    }
    assert!(checked > 50, "only {checked} tk invocations were found");
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

fn example_id_failures<'a>(
    files: impl IntoIterator<Item = &'a (PathBuf, String)>,
    public_key: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (path, text) in files {
        let mut seen = BTreeSet::new();
        for fence in document(text)
            .fences
            .into_iter()
            .filter(|f| f.lang == Lang::Shell)
        {
            let script = script(path, fence.start_line, &fence.body, public_key).unwrap();
            if script.invocations.is_empty() {
                continue;
            }
            let ids: Vec<&str> = fence
                .comments
                .iter()
                .filter_map(|comment| comment.strip_prefix("example:"))
                .map(str::trim)
                .collect();
            match ids.as_slice() {
                [id] if !seen.insert((*id).to_owned()) => {
                    failures.push(format!(
                        "{}:{}: duplicate example id {id}",
                        path.display(),
                        fence.start_line
                    ));
                }
                [_] => {}
                _ => failures.push(format!(
                    "{}:{}: tk example needs exactly one `<!-- example: <id> -->` line above it",
                    path.display(),
                    fence.start_line
                )),
            }
        }
    }
    failures
}

#[test]
fn skill_shell_blocks_that_invoke_tk_carry_unique_example_ids() {
    let skills = repo_root().join("skills");
    let failures = example_id_failures(
        DOCUMENTED_MARKDOWN
            .iter()
            .filter(|(path, _)| path.starts_with(&skills)),
        &PUBLIC_KEY,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn shared_block_failures<'a>(
    files: impl IntoIterator<Item = &'a (PathBuf, String)>,
) -> Vec<String> {
    let mut by_id: BTreeMap<String, Vec<(&Path, usize, String)>> = BTreeMap::new();
    for (path, text) in files {
        for Fence {
            body,
            start_line,
            comments,
            lang: _,
        } in document(text).fences
        {
            let mut ids: Vec<String> = comments
                .iter()
                .filter_map(|comment| comment.strip_prefix("shared:"))
                .map(|id| id.trim().to_owned())
                .collect();
            let Some(last) = ids.pop() else {
                continue;
            };
            for id in ids {
                by_id
                    .entry(id)
                    .or_default()
                    .push((path, start_line, body.clone()));
            }
            by_id
                .entry(last)
                .or_default()
                .push((path, start_line, body));
        }
    }
    let mut failures = Vec::new();
    if by_id.is_empty() {
        failures.push("no shared blocks were found".to_owned());
    }
    for (id, copies) in &by_id {
        let ((first_path, first_line, first), rest) = copies.split_first().unwrap();
        if rest.is_empty() {
            failures.push(format!("shared block {id} appears in only one file"));
        }
        for (path, line, body) in rest {
            if body != first {
                failures.push(format!(
                    r#"shared block {id} differs
--- {}:{first_line}
{first}
+++ {}:{line}
{body}"#,
                    first_path.display(),
                    path.display()
                ));
            }
        }
    }
    failures
}

#[test]
fn shared_blocks_are_identical_across_files() {
    let failures = shared_block_failures(DOCUMENTED_MARKDOWN.iter());
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn mutation_fixtures_fail_the_shared_block_and_example_id_checks() {
    let fresh = r#"<!-- shared: startup -->
```sh
tk whoami
```
"#;
    let stale = r#"<!-- shared: startup -->
```sh
tk --profile agent whoami
```
"#;
    assert_eq!(
        shared_block_failures(&[
            (PathBuf::from("a.md"), fresh.to_owned()),
            (PathBuf::from("b.md"), stale.to_owned()),
        ]),
        [r#"shared block startup differs
--- a.md:3
tk whoami
+++ b.md:3
tk --profile agent whoami"#]
    );
    assert_eq!(
        shared_block_failures(&[(PathBuf::from("a.md"), fresh.to_owned())]),
        ["shared block startup appears in only one file"]
    );

    let unlabelled = r#"```sh
tk whoami
```
"#
    .to_owned();
    let duplicate = r#"<!-- example: x.a -->
```sh
tk whoami
```
<!-- example: x.a -->
```sh
tk whoami
```
"#
    .to_owned();
    let prose_only = r#"```sh
git status
```
"#
    .to_owned();
    let failures = example_id_failures(
        &[
            (PathBuf::from("a.md"), unlabelled),
            (PathBuf::from("b.md"), duplicate),
            (PathBuf::from("c.md"), prose_only),
        ],
        &PUBLIC_KEY,
    );
    assert_eq!(
        failures,
        [
            "a.md:2: tk example needs exactly one `<!-- example: <id> -->` line above it",
            "b.md:7: duplicate example id x.a",
        ]
    );
}

const SIGNING_PATTERNS: [&str; 3] = [
    "activity.action == 'SIGN'",
    "ACTIVITY_TYPE_SIGN_",
    "ACTIVITY_TYPE_ETH_SEND",
];
const SCOPE_PATTERNS: [&str; 3] = ["wallet.id", "wallet_account.address", "private_key.id"];

fn unscoped_signing_allow(effect: &str, condition: &str) -> bool {
    let allow = matches!(effect, "EFFECT_ALLOW" | "allow");
    let signs = SIGNING_PATTERNS.iter().any(|p| condition.contains(p));
    let scoped = SCOPE_PATTERNS.iter().any(|p| condition.contains(p));
    allow && signs && !scoped
}

fn walk_policies(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(effect)) = fields.get("effect")
                && let Some(condition) = fields.get("condition").and_then(Value::as_str)
                && unscoped_signing_allow(effect, condition)
            {
                out.push(condition.to_owned());
            }
            fields.values().for_each(|v| walk_policies(v, out));
        }
        Value::Array(items) => items.iter().for_each(|v| walk_policies(v, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn policy_examples_use_compressed_keys_and_scoped_signing_allows() {
    let mut failures = Vec::new();
    for (path, text) in DOCUMENTED_MARKDOWN.iter() {
        for fence in document(text).fences {
            let (literals, invocations) = match fence.lang {
                Lang::Json => (vec![fence.body], Vec::new()),
                Lang::Shell => {
                    let script = script(path, fence.start_line, &fence.body, &PUBLIC_KEY).unwrap();
                    (script.literals, script.invocations)
                }
                Lang::Yaml | Lang::Mermaid | Lang::Plain | Lang::Unknown(_) => continue,
            };
            let negative = fence.comments.iter().any(|c| c == "negative-example");
            for literal in literals {
                if literal.contains(r#""publicKey": "04"#) || literal.contains(r#""publicKey":"04"#)
                {
                    failures.push(format!(
                        "{}:{}: publicKey starts with 04; Turnkey API keys are compressed (02/03)",
                        path.display(),
                        fence.start_line
                    ));
                }
                let value = match serde_json::from_str::<Value>(&literal) {
                    Ok(value) => value,
                    Err(error) => {
                        failures.push(format!(
                            "{}:{}: literal is not valid JSON: {error}",
                            path.display(),
                            fence.start_line
                        ));
                        continue;
                    }
                };
                let mut unscoped = Vec::new();
                walk_policies(&value, &mut unscoped);
                if !negative {
                    for condition in unscoped {
                        failures.push(format!(
                            "{}:{}: signing ALLOW lacks a key scope: {condition}",
                            path.display(),
                            fence.start_line
                        ));
                    }
                }
            }
            for argv in invocations {
                let flag = |name: &str| {
                    argv.iter()
                        .position(|arg| arg == name)
                        .and_then(|i| argv.get(i + 1))
                        .map(String::as_str)
                };
                if !negative
                    && let Some(effect) = flag("--effect")
                    && let Some(condition) = flag("--condition")
                    && unscoped_signing_allow(effect, condition)
                {
                    failures.push(format!(
                        "{}:{}: signing ALLOW lacks a key scope: {argv:?}",
                        path.display(),
                        fence.start_line
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn documentation_contains_no_secret_looking_literals() {
    const MARKERS: [&str; 5] = [
        "sk-ant-",
        "ghp_",
        "github_pat_",
        "-----BEGIN",
        "TURNKEY_API_PRIVATE_KEY=\"",
    ];
    let mut failures = Vec::new();
    for (path, text) in DOCUMENTED_MARKDOWN.iter() {
        for (index, line) in text.lines().enumerate() {
            for marker in MARKERS {
                let Some(position) = line.find(marker) else {
                    continue;
                };
                let rest = &line[position + marker.len()..];
                let literal_secret = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .count()
                    >= 8;
                if literal_secret {
                    failures.push(format!(
                        "{}:{}: looks like a secret literal: {line}",
                        path.display(),
                        index + 1
                    ));
                }
            }
            if let Some(position) = line
                .find(r#""privateKey""#)
                .or_else(|| line.find("private_key\""))
                && line[position..]
                    .split_once(':')
                    .is_some_and(|(_, v)| v.trim().trim_matches(['"', ',']).len() >= 32)
            {
                failures.push(format!(
                    "{}:{}: private key value in documentation: {line}",
                    path.display(),
                    index + 1
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn runtime_names_appear_only_as_labelled_examples() {
    const RUNTIMES: [&str; 5] = ["Hermes", "Claude Code", "Codex", "systemd", "Docker"];
    let mut failures = Vec::new();
    for (path, text) in DOCUMENTED_MARKDOWN.iter() {
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !RUNTIMES.iter().any(|runtime| line.contains(runtime)) {
                continue;
            }
            let previous = lines[..index]
                .iter()
                .rev()
                .find(|l| !l.trim().is_empty())
                .copied()
                .unwrap_or_default();
            let labelled = [*line, previous]
                .iter()
                .any(|l| l.to_ascii_lowercase().contains("example"));
            if !labelled {
                failures.push(format!(
                    "{}:{}: runtime named without an `example` label: {line}",
                    path.display(),
                    index + 1
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn documented_fields(text: &str, heading: &str) -> BTreeSet<String> {
    let section = text
        .split_once(heading)
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| panic!("cli-convention.md lacks section {heading}"));
    section
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .skip(2)
        .take_while(|line| line.starts_with('|'))
        .map(|line| {
            line.trim_start_matches('|')
                .split('|')
                .next()
                .unwrap()
                .trim()
                .trim_matches('`')
                .to_owned()
        })
        .collect()
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

#[test]
fn cli_convention_record_tables_name_the_serialized_fields() {
    let text = fs::read_to_string(repo_root().join("skills/references/cli-convention.md")).unwrap();

    let pending = OperationOutput::result(
        "user.create",
        json!({"activity": {"id": "a", "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED"}}),
    );
    let pending = serde_json::to_value(&pending).unwrap();
    assert_eq!(pending["status"], "pending");
    assert_eq!(
        keys(&pending),
        documented_fields(&text, "### `command_result`")
    );

    let http = Error::new(UnexpectedHttpStatus {
        status: 401,
        body: "denied".into(),
    });
    let activity = Error::new(
        ActivityError::new(ActivityErrorKind::WaitTimeout, "wait timed out")
            .with_activity(json!({"id": "a", "status": null})),
    );
    let mut serialized = BTreeSet::new();
    for error in [http, activity] {
        serialized.extend(keys(
            &serde_json::to_value(ErrorMessage::from_error(&error)).unwrap(),
        ));
    }
    assert_eq!(serialized, documented_fields(&text, "### Error records"));
}

// The reference table is checked against the enum, not assigned from it.
#[allow(clippy::disallowed_types)]
#[test]
fn cli_convention_error_code_table_names_every_error_code() {
    let text = fs::read_to_string(repo_root().join("skills/references/cli-convention.md")).unwrap();
    let declared: BTreeSet<String> = crate::errors::ErrorCode::iter()
        .map(|code| {
            serde_json::to_value(code)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(documented_fields(&text, "## Error codes"), declared);
}

fn invocations(body: &str) -> Vec<Vec<String>> {
    script(Path::new("test.md"), 1, body, &PUBLIC_KEY)
        .unwrap()
        .invocations
}

fn unsupported(start_line: usize, body: &str) -> Unsupported {
    script(Path::new("test.md"), start_line, body, &PUBLIC_KEY).unwrap_err()
}

#[test]
fn extractor_handles_quotes_json_heredocs_and_substitution() {
    let body = r#"# a comment line
tk --profile admin --message-format json policy create --name "spaced name" --effect allow \
  --consensus "approvers.any(user, user.id == 'USER_ID')" \
  --condition 'activity.type == "x"'   # trailing comment
tk user create --input-json '{
  "users": [{"userName": "agent"}]
}' | jq -r .data
FINGERPRINT=$(tk gpg keys create --wallet-id WALLET_ID --user-id "Name <n@example.com>" --message-format json | jq -r .fingerprint)
echo "$FINGERPRINT:6:" | gpg --import-ownertrust
tk policy create --input-file - <<'EOF'
{"policyName": "p", "effect": "EFFECT_DENY"}
EOF
tk secret export --name api-token --out ./file.txt 2>/dev/null >> log
tk --profile "$PROFILE_ID" --organization-id ORG_UUID user get --id USER_ID
tk activity wait --id ACTIVITY_ID --timeout 60; tk activity get --id ACTIVITY_ID
"#;
    let script = script(Path::new("test.md"), 1, body, &PUBLIC_KEY).unwrap();
    let argv: Vec<Vec<&str>> = script
        .invocations
        .iter()
        .map(|argv| argv.iter().map(String::as_str).collect())
        .collect();
    assert_eq!(
        argv,
        vec![
            vec![
                "tk",
                "--profile",
                "admin",
                "--message-format",
                "json",
                "policy",
                "create",
                "--name",
                "spaced name",
                "--effect",
                "allow",
                "--consensus",
                "approvers.any(user, user.id == 'USER_ID')",
                "--condition",
                r#"activity.type == "x""#,
            ],
            vec![
                "tk",
                "user",
                "create",
                "--input-json",
                r#"{
  "users": [{"userName": "agent"}]
}"#,
            ],
            vec![
                "tk",
                "gpg",
                "keys",
                "create",
                "--wallet-id",
                UUID_FIXTURE,
                "--user-id",
                "Name <n@example.com>",
                "--message-format",
                "json",
            ],
            vec!["tk", "policy", "create", "--input-file", "-"],
            vec![
                "tk",
                "secret",
                "export",
                "--name",
                "api-token",
                "--out",
                "./file.txt",
            ],
            vec![
                "tk",
                "--profile",
                UUID_FIXTURE,
                "--organization-id",
                UUID_FIXTURE,
                "user",
                "get",
                "--id",
                UUID_FIXTURE,
            ],
            vec![
                "tk",
                "activity",
                "wait",
                "--id",
                UUID_FIXTURE,
                "--timeout",
                "60"
            ],
            vec!["tk", "activity", "get", "--id", UUID_FIXTURE],
        ]
    );
    assert_eq!(
        script.literals,
        vec![
            r#"{
  "users": [{"userName": "agent"}]
}"#
            .to_owned(),
            r#"{"policyName": "p", "effect": "EFFECT_DENY"}"#.to_owned(),
        ]
    );
    for argv in &script.invocations {
        parse(argv).unwrap();
    }
}

#[test]
fn extractor_keeps_words_after_inline_redirect_targets_and_comments() {
    assert_eq!(
        invocations("tk whoami 2>&1; tk auth status"),
        vec![vec!["tk", "whoami"], vec!["tk", "auth", "status"]]
    );
    assert_eq!(
        invocations("tk whoami >&2 --message-format json"),
        vec![vec!["tk", "whoami", "--message-format", "json"]]
    );
    assert_eq!(
        invocations("tk whoami >&10 --x"),
        vec![vec!["tk", "whoami", "--x"]]
    );
    assert_eq!(
        invocations("tk whoami >| out --x"),
        vec![vec!["tk", "whoami", "--x"]]
    );
    assert_eq!(
        invocations("tk whoami >2fa.txt --x"),
        vec![vec!["tk", "whoami", "--x"]]
    );
    assert_eq!(
        invocations("tk whoami 2>1.log --x"),
        vec![vec!["tk", "whoami", "--x"]]
    );
    assert_eq!(
        invocations("tk policy create --input-file - <<-EOF\n{}\n\tEOF\ntk whoami"),
        vec![
            vec!["tk", "policy", "create", "--input-file", "-"],
            vec!["tk", "whoami"],
        ]
    );
    assert_eq!(
        invocations("tk whoami 2>/dev/null; tk auth status"),
        vec![vec!["tk", "whoami"], vec!["tk", "auth", "status"]]
    );
    assert_eq!(
        invocations(
            r#"tk whoami # the agent's key
tk auth status
tk secret env --name api-token
"#
        ),
        vec![
            vec!["tk", "whoami"],
            vec!["tk", "auth", "status"],
            vec!["tk", "secret", "env", "--name", "api-token"],
        ]
    );
    assert_eq!(
        invocations("tk user get --name 'a<<b'"),
        vec![vec!["tk", "user", "get", "--name", "a<<b"]]
    );
    assert_eq!(
        invocations("tk whoami < in > out --x"),
        vec![vec!["tk", "whoami", "--x"]]
    );
}

#[test]
fn extractor_sees_through_control_flow_head_words() {
    assert_eq!(
        invocations("if tk whoami >/dev/null; then echo ok; fi"),
        vec![vec!["tk", "whoami"]]
    );
    assert_eq!(invocations("time tk whoami"), vec![vec!["tk", "whoami"]]);
    assert_eq!(
        invocations("if ! tk whoami; then echo ok; fi"),
        vec![vec!["tk", "whoami"]]
    );
    assert_eq!(
        invocations("while ! tk activity wait --id ACTIVITY_ID; do :; done"),
        vec![vec!["tk", "activity", "wait", "--id", UUID_FIXTURE]]
    );
    assert_eq!(
        invocations("nohup tk ssh agent start &"),
        vec![vec!["tk", "ssh", "agent", "start"]]
    );
    assert_eq!(
        invocations("exec tk ssh agent start"),
        vec![vec!["tk", "ssh", "agent", "start"]]
    );
    assert_eq!(invocations("sudo tk whoami"), vec![vec!["tk", "whoami"]]);
    assert_eq!(
        invocations("env FOO=bar tk whoami"),
        vec![vec!["tk", "whoami"]]
    );
}

#[test]
fn extractor_collects_only_json_looking_heredocs() {
    let script = script(
        Path::new("test.md"),
        1,
        r#"cat <<EOF > greeting.txt
Hello
EOF
tk policy create --input-file - <<'EOF'
{"policyName": "p"}
EOF
"#,
        &PUBLIC_KEY,
    )
    .unwrap();
    assert_eq!(script.literals, [r#"{"policyName": "p"}"#]);
    assert_eq!(
        script.invocations,
        [["tk", "policy", "create", "--input-file", "-"]]
    );
}

#[test]
fn extractor_deletes_unquoted_line_continuations_like_the_shell() {
    assert_eq!(
        invocations(
            r#"tk user get --name=a\
b"#
        ),
        vec![vec!["tk", "user", "get", "--name=ab"]]
    );
    assert_eq!(
        invocations(
            r#"tk whoami\
--x"#
        ),
        vec![vec!["tk", "whoami--x"]]
    );
    assert_eq!(
        invocations(
            r#"tk whoami \
  --x"#
        ),
        vec![vec!["tk", "whoami", "--x"]]
    );
}

#[test]
fn extractor_substitutes_placeholders_in_flag_equals_values() {
    assert_eq!(
        invocations("tk user get --organization-id=ORG_UUID"),
        vec![vec![
            "tk".to_owned(),
            "user".to_owned(),
            "get".to_owned(),
            format!("--organization-id={UUID_FIXTURE}"),
        ]]
    );
    assert_eq!(
        unsupported(1, "tk user get --x=MYSTERY_VALUE").message,
        "unknown placeholder MYSTERY_VALUE"
    );
}

#[test]
fn extractor_joins_quoted_line_continuations_like_the_shell() {
    assert_eq!(
        invocations(
            r#"tk user get --name "a\
b""#
        ),
        vec![vec!["tk", "user", "get", "--name", "ab"]]
    );
    assert_eq!(
        invocations(
            r#"tk user get --name 'a\
b'"#
        ),
        vec![vec!["tk", "user", "get", "--name", "a\\\nb"]]
    );
}

#[test]
fn extractor_rejects_unsupported_constructs_and_unknown_placeholders() {
    let here_string = unsupported(
        3,
        r#"tk whoami
tk policy create --input-json "$BODY" <<< x
"#,
    );
    assert_eq!(here_string.line, 4);
    assert_eq!(here_string.message, "here-string <<< is not supported");

    let activity_type = unsupported(1, "tk user get --id ACTIVITY_TYPE_CREATE_USER_TAG");
    assert_eq!(
        activity_type.message,
        "unknown placeholder ACTIVITY_TYPE_CREATE_USER_TAG"
    );

    let backtick = unsupported(
        10,
        r#"tk whoami
FOO=`tk whoami`
"#,
    );
    assert_eq!(backtick.path, Path::new("test.md"));
    assert_eq!(backtick.line, 11);
    assert_eq!(
        backtick.message,
        "backtick substitution at column 4 is not supported; use $(...)"
    );

    let quoted_backtick = unsupported(1, r#"tk user get --name "`whoami`""#);
    assert_eq!(
        quoted_backtick.message,
        "backtick substitution at column 20 is not supported; use $(...)"
    );

    let heredoc = unsupported(7, "tk policy create --input-file - <<");
    assert_eq!(heredoc.path, Path::new("test.md"));
    assert_eq!(heredoc.line, 7);
    assert_eq!(heredoc.message, "heredoc has no terminator");

    let unterminated_heredoc = unsupported(
        2,
        r#"tk whoami
tk policy create --input-file - <<EOF
{"policyName": "p"}
"#,
    );
    assert_eq!(unterminated_heredoc.line, 3);
    assert_eq!(
        unterminated_heredoc.message,
        "heredoc terminator EOF not found"
    );

    let process_substitution = unsupported(1, "tk whoami <(cat x)");
    assert_eq!(
        process_substitution.message,
        "process substitution is not supported"
    );

    let comment_continuation = unsupported(
        5,
        r#"# comment \
tk whoami
"#,
    );
    assert_eq!(comment_continuation.line, 5);
    assert_eq!(
        comment_continuation.message,
        "line continuation inside a comment"
    );

    let commented_continuation = unsupported(
        5,
        r#"tk whoami \
# c
--x
"#,
    );
    assert_eq!(commented_continuation.line, 5);
    assert_eq!(
        commented_continuation.message,
        "line continuation followed by a comment"
    );

    let unknown = unsupported(1, "tk user get --id MYSTERY_VALUE");
    assert_eq!(unknown.message, "unknown placeholder MYSTERY_VALUE");

    let unknown_var = unsupported(1, r#"tk user get --id "$WHO""#);
    assert_eq!(unknown_var.message, "unknown shell variable $WHO");

    let braced_var = unsupported(1, "tk user get --id ${WHO}");
    assert_eq!(braced_var.message, "bare $ is not a supported construct");

    let subshell = unsupported(1, "(cd dir && tk whoami)");
    assert_eq!(subshell.message, "bare `(` at column 0 is not supported");

    let group = unsupported(1, "{ tk whoami; }");
    assert_eq!(group.message, "bare `{` at column 0 is not supported");

    let positional_placeholder = unsupported(1, "tk user get <id> --x");
    assert_eq!(
        positional_placeholder.message,
        "angle-bracket placeholder <id> is not supported"
    );

    let flag_placeholder = unsupported(1, "tk user get --name <name>");
    assert_eq!(
        flag_placeholder.message,
        "angle-bracket placeholder <name> is not supported"
    );

    let spaced_placeholder = unsupported(1, "tk user get --org <org id> --x");
    assert_eq!(
        spaced_placeholder.message,
        "angle-bracket placeholder <org id> is not supported"
    );

    let path_placeholder = unsupported(1, "tk user get --path <path to file>");
    assert_eq!(
        path_placeholder.message,
        "angle-bracket placeholder <path to file> is not supported"
    );

    assert_eq!(
        invocations("tk user get --id UNKNOWN_THING_ID"),
        vec![vec!["tk", "user", "get", "--id", UUID_FIXTURE]]
    );
}

#[test]
fn extractor_output_is_checked_by_the_real_parser() {
    let bad = invocations("tk user get --id USER_ID --no-such-flag");
    assert_eq!(
        parse(&bad[0]).unwrap_err().kind(),
        ErrorKind::UnknownArgument
    );
    let ok = invocations("tk user create --user-name agent --tag-name a --tag-name b");
    parse(&ok[0]).unwrap();
    let help = invocations("tk secret --help");
    parse(&help[0]).unwrap();
}

#[test]
fn inline_spans_select_full_invocations_only() {
    let spans = document(
        r#"Use `tk secret env` at startup, or `tk activity wait --id ACTIVITY_ID --timeout 60`.
```sh
`tk --fenced`
```
"#,
    )
    .spans;
    let texts: Vec<&str> = spans.iter().map(|span| span.text.as_str()).collect();
    assert_eq!(texts, ["tk activity wait --id ACTIVITY_ID --timeout 60"]);
    assert_eq!(spans[0].line, 1);
}

#[test]
fn fence_info_strings_parse_into_closed_languages() {
    let langs: Vec<Lang> = document(
        r#"```shell
tk whoami
```
```sh title=example
tk whoami
```
```
plain text
```
```bash
tk whoami
```
```yml
key: value
```
```mermaid
flowchart LR
    a --> b
```
"#,
    )
    .fences
    .into_iter()
    .map(|fence| fence.lang)
    .collect();
    assert_eq!(
        langs,
        [
            Lang::Unknown("shell".to_owned()),
            Lang::Unknown("sh title=example".to_owned()),
            Lang::Plain,
            Lang::Shell,
            Lang::Yaml,
            Lang::Mermaid,
        ]
    );
}
