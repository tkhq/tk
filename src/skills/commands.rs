// Test fixtures and assertions may panic.
#![allow(clippy::unwrap_used, clippy::panic)]
use std::{env, fmt::Write, fs, path::Path};

use clap::{Arg, ArgAction, Command, CommandFactory};

use crate::cli::Cli;

const UPDATE_ENV: &str = "TK_UPDATE_COMMANDS_MD";

fn cell(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', r"\|")
}

fn value_names(arg: &Arg) -> String {
    let names: Vec<String> = match arg.get_value_names() {
        Some(names) => names.iter().map(|n| format!("<{n}>")).collect(),
        None => vec![format!("<{}>", arg.get_id().as_str().to_uppercase())],
    };
    names.join(" ")
}

fn takes_value(arg: &Arg) -> bool {
    !matches!(
        arg.get_action(),
        ArgAction::SetTrue
            | ArgAction::SetFalse
            | ArgAction::Count
            | ArgAction::Help
            | ArgAction::HelpShort
            | ArgAction::HelpLong
            | ArgAction::Version
    )
}

fn flag(arg: &Arg) -> String {
    let mut parts = Vec::new();
    if let Some(short) = arg.get_short() {
        parts.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        parts.push(format!("--{long}"));
    }
    let mut text = parts.join(", ");
    if takes_value(arg) {
        text.push(' ');
        text.push_str(&value_names(arg));
    }
    if matches!(arg.get_action(), ArgAction::Append) {
        text.push_str(" (repeatable)");
    }
    text
}

fn notes(arg: &Arg) -> String {
    let mut notes = Vec::new();
    if arg.is_required_set() {
        notes.push("required".to_owned());
    }
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    if takes_value(arg) && !defaults.is_empty() {
        notes.push(format!("default `{}`", defaults.join(" ")));
    }
    let possible: Vec<String> = arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| format!("`{}`", v.get_name()))
        .collect();
    if !possible.is_empty() {
        notes.push(format!("one of {}", possible.join(", ")));
    }
    if let Some(env) = arg.get_env() {
        notes.push(format!("env `{}`", env.to_string_lossy()));
    }
    notes.join("; ")
}

fn visible(sub: &Command) -> bool {
    !sub.is_hide_set() && sub.get_name() != "help"
}

fn arguments(command: &Command, global: bool) -> Vec<&Arg> {
    command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set() && arg.is_global_set() == global)
        .filter(|arg| !matches!(arg.get_id().as_str(), "help" | "version"))
        .collect()
}

fn arguments_table(out: &mut String, arguments: &[&Arg]) {
    out.push_str(
        r#"| Argument | Notes | Description |
|---|---|---|
"#,
    );
    for arg in arguments {
        let name = if arg.is_positional() {
            let mut name = value_names(arg);
            if matches!(arg.get_action(), ArgAction::Append)
                || arg.get_num_args().is_some_and(|n| n.max_values() > 1)
            {
                name.push_str("...");
            }
            name
        } else {
            flag(arg)
        };
        let help = arg
            .get_help()
            .map(|h| cell(&h.to_string()))
            .unwrap_or_default();
        writeln!(out, "| `{name}` | {} | {help} |", notes(arg)).unwrap();
    }
    out.push('\n');
}

fn groups(out: &mut String, command: &Command) {
    let mut lines = Vec::new();
    for group in command.get_groups() {
        let mut group = group.clone();
        let members: Vec<String> = group
            .get_args()
            .filter_map(|id| command.get_arguments().find(|arg| arg.get_id() == id))
            .filter(|arg| !arg.is_hide_set())
            .map(|arg| match arg.get_long() {
                Some(long) => format!("`--{long}`"),
                None => format!("`{}`", value_names(arg)),
            })
            .collect();
        if members.len() < 2 {
            continue;
        }
        let rule = match (group.is_required_set(), group.is_multiple()) {
            (true, false) => "exactly one of",
            (true, true) => "at least one of",
            (false, false) => "at most one of",
            (false, true) => continue,
        };
        lines.push(format!("- {rule} {}", members.join(", ")));
    }
    for arg in arguments(command, false) {
        let conflicts: Vec<String> = command
            .get_arg_conflicts_with(arg)
            .into_iter()
            .filter(|other| !other.is_hide_set())
            .filter_map(|other| other.get_long().map(|long| format!("`--{long}`")))
            .collect();
        if let (Some(long), false) = (arg.get_long(), conflicts.is_empty()) {
            lines.push(format!(
                "- `--{long}` conflicts with {}",
                conflicts.join(", ")
            ));
        }
    }
    if !lines.is_empty() {
        lines.sort();
        lines.dedup();
        out.push_str(
            r#"Constraints:

"#,
        );
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
        out.push('\n');
    }
}

fn fence(out: &mut String, text: &str) {
    write!(
        out,
        r#"```
{text}
```

"#
    )
    .unwrap();
}

fn section(out: &mut String, command: &mut Command, path: &[&str]) {
    let depth = path.len().min(5);
    writeln!(out, "{} `{}`\n", "#".repeat(depth + 1), path.join(" ")).unwrap();
    if let Some(about) = command.get_about() {
        writeln!(out, "{}\n", cell(&about.to_string())).unwrap();
    }
    if path.len() == 1
        && let Some(long) = command.get_long_about()
    {
        fence(out, &long.to_string());
    }
    let usage = command.render_usage().to_string();
    fence(out, usage.trim_start_matches("Usage:").trim());
    let own = arguments(command, false);
    if !own.is_empty() {
        arguments_table(out, &own);
    }
    groups(out, command);
    let subcommands: Vec<&Command> = command
        .get_subcommands()
        .filter(|sub| visible(sub))
        .collect();
    if !subcommands.is_empty() {
        out.push_str(
            r#"Subcommands:

"#,
        );
        for sub in subcommands {
            let mut sub_path = path.to_vec();
            sub_path.push(sub.get_name());
            let about = sub
                .get_about()
                .map(|a| cell(&a.to_string()))
                .unwrap_or_default();
            writeln!(
                out,
                "- [`{}`](#{}){}",
                sub_path.join(" "),
                sub_path.join("-"),
                if about.is_empty() {
                    String::new()
                } else {
                    format!(": {about}")
                }
            )
            .unwrap();
        }
        out.push('\n');
    }
    if path.len() == 1 {
        out.push_str(
            r#"### Global options

Every command accepts these.

"#,
        );
        arguments_table(out, &arguments(command, true));
        if let Some(after) = command.get_after_help() {
            fence(out, after.to_string().trim_end());
        }
    }
    for sub in command.get_subcommands_mut().filter(|sub| visible(sub)) {
        let name = sub.get_name().to_owned();
        let mut sub_path = path.to_vec();
        sub_path.push(&name);
        section(out, sub, &sub_path);
    }
}

fn render() -> String {
    let mut command = Cli::command();
    command.build();
    let mut out = String::from(
        r#"# Command reference

Do not edit by hand: this file is autogenerated with

```
TK_UPDATE_COMMANDS_MD=1 cargo test commands_reference
```

This lists what the parser accepts. Validation that happens after parsing,
such as identity resolution or JSON shape checks, and the Git and GPG shim
modes that bypass this parser are described in the area docs.

"#,
    );
    section(&mut out, &mut command, &["tk"]);
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

fn first_difference(expected: &str, actual: &str) -> String {
    let expected: Vec<&str> = expected.lines().collect();
    let actual: Vec<&str> = actual.lines().collect();
    let index = expected
        .iter()
        .zip(actual.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(expected.len().min(actual.len()));
    format!(
        r#"first difference at line {}
--- checked in
{}
+++ rendered
{}"#,
        index + 1,
        expected.get(index).copied().unwrap_or("<end>"),
        actual.get(index).copied().unwrap_or("<end>")
    )
}

#[test]
fn commands_reference_matches_clap() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/commands.md");
    let rendered = render();
    if env::var_os(UPDATE_ENV).is_some() {
        fs::write(&path, &rendered).unwrap();
        return;
    }
    let checked_in = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        checked_in == rendered,
        r#"{} is stale; regenerate with {UPDATE_ENV}=1 cargo test commands_reference
{}"#,
        path.display(),
        first_difference(&checked_in, &rendered)
    );
}

#[test]
fn commands_reference_covers_every_visible_subcommand() {
    let rendered = render();
    let mut command = Cli::command();
    command.build();
    fn visit(command: &Command, path: &mut Vec<String>, rendered: &str) {
        for sub in command.get_subcommands().filter(|sub| visible(sub)) {
            path.push(sub.get_name().to_owned());
            let heading = format!(" `{}`\n", path.join(" "));
            assert!(
                rendered.contains(&heading),
                "missing section for {}",
                path.join(" ")
            );
            visit(sub, path, rendered);
            path.pop();
        }
    }
    visit(&command, &mut vec!["tk".to_owned()], &rendered);
    assert!(
        !rendered.contains("internal-run"),
        "hidden subcommand rendered"
    );
}
