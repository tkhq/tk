//! Structure, link, and eval checks for the `skills/` package.

// Test fixtures and assertions may panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const WORKFLOW_SECTIONS: [&str; 6] = [
    "## Reference",
    "## Rules",
    "## Instructions",
    "## Verified by",
    "## Troubleshooting",
    "## Related Skills",
];
const MAX_WORKFLOW_LINES: usize = 220;
const MAX_DESCRIPTION_CHARS: usize = 1024;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn skills_root() -> PathBuf {
    repo_root().join("skills")
}

struct Workflow {
    name: String,
    path: PathBuf,
    text: String,
}

fn workflows() -> Vec<Workflow> {
    let mut workflows: Vec<Workflow> = fs::read_dir(skills_root())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir() && path.file_name().is_some_and(|n| n != "references"))
        .map(|dir| {
            let path = dir.join("SKILL.md");
            Workflow {
                name: dir.file_name().unwrap().to_str().unwrap().to_owned(),
                text: fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display())),
                path,
            }
        })
        .collect();
    workflows.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(!workflows.is_empty(), "no workflow skills under skills/");
    workflows
}

fn references() -> Vec<(PathBuf, String)> {
    let mut references: Vec<(PathBuf, String)> = fs::read_dir(skills_root().join("references"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "md"))
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            (path, text)
        })
        .collect();
    references.sort();
    assert!(
        !references.is_empty(),
        "no references under skills/references/"
    );
    references
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "plans") {
                continue;
            }
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn frontmatter(text: &str, path: &Path) -> BTreeMap<String, String> {
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("---"),
        "{}: missing frontmatter",
        path.display()
    );
    let mut fields = BTreeMap::new();
    for line in lines {
        if line == "---" {
            return fields;
        }
        let (key, value) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("{}: frontmatter line `{line}`", path.display()));
        fields.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    panic!("{}: unterminated frontmatter", path.display())
}

fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("missing section {heading}"));
    let body = &text[start + heading.len() + 2..];
    let end = body.find("\n## ").unwrap_or(body.len());
    &body[..end]
}

fn slug(heading: &str) -> String {
    heading
        .trim()
        .trim_start_matches('#')
        .trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase()
        .replace(' ', "-")
}

fn anchors(text: &str) -> BTreeSet<String> {
    let mut in_fence = false;
    text.lines()
        .filter(|line| {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                return false;
            }
            !in_fence && line.starts_with('#')
        })
        .map(slug)
        .collect()
}

fn links(text: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut rest = text;
    while let Some(position) = rest.find("](") {
        let after = &rest[position + 2..];
        let Some(end) = after.find(')') else { break };
        links.push(&after[..end]);
        rest = &after[end + 1..];
    }
    links
}

fn example_ids(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("<!-- example:")
                .and_then(|rest| rest.strip_suffix("-->"))
        })
        .map(|id| id.trim().to_owned())
        .collect()
}

#[test]
fn workflows_have_frontmatter_sections_and_line_budget() {
    let mut names = BTreeSet::new();
    for Workflow { name, path, text } in workflows() {
        let fields = frontmatter(&text, &path);
        assert_eq!(fields.get("name"), Some(&name), "{}", path.display());
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{name} is not kebab-case"
        );
        let duplicate = format!("duplicate skill name {name}");
        assert!(names.insert(name), "{duplicate}");
        let description = fields
            .get("description")
            .unwrap_or_else(|| panic!("{}: no description", path.display()));
        assert!(
            !description.is_empty() && description.len() <= MAX_DESCRIPTION_CHARS,
            "{}: description length {}",
            path.display(),
            description.len()
        );
        assert!(
            description.contains("Use "),
            "{}: description does not say when to use it",
            path.display()
        );

        let mut cursor = 0;
        for heading in WORKFLOW_SECTIONS {
            let position = text[cursor..]
                .find(&format!("\n{heading}\n"))
                .unwrap_or_else(|| {
                    panic!(
                        "{}: missing or out-of-order section {heading}",
                        path.display()
                    )
                });
            cursor += position + heading.len();
        }
        assert!(
            section(&text, "## Instructions")
                .lines()
                .any(|line| line.trim_start().starts_with("1. ")),
            "{}: instructions are not numbered",
            path.display()
        );
        let lines = text.lines().count();
        assert!(
            lines <= MAX_WORKFLOW_LINES,
            "{}: {lines} lines exceeds {MAX_WORKFLOW_LINES}",
            path.display()
        );
    }
}

#[test]
fn index_routes_to_every_workflow_and_reference() {
    let path = skills_root().join("SKILL.md");
    let text = fs::read_to_string(&path).unwrap();
    let fields = frontmatter(&text, &path);
    assert_eq!(fields.get("name").map(String::as_str), Some("turnkey-tk"));
    assert!(fields.get("description").is_some_and(|d| !d.is_empty()));
    let linked: BTreeSet<&str> = links(&text).into_iter().collect();
    for workflow in workflows() {
        let target = format!("{}/SKILL.md", workflow.name);
        assert!(
            linked.contains(target.as_str()),
            "index does not link {target}"
        );
    }
    for (reference, _) in references() {
        let target = format!(
            "references/{}",
            reference.file_name().unwrap().to_str().unwrap()
        );
        assert!(
            linked.contains(target.as_str()),
            "index does not link {target}"
        );
    }
}

#[test]
fn references_have_no_frontmatter_and_a_contents_section() {
    for (path, text) in references() {
        assert!(
            text.starts_with("# "),
            "{}: must start with a title",
            path.display()
        );
        assert!(
            text.contains("\n## Contents\n"),
            "{}: no contents section",
            path.display()
        );
    }
}

#[test]
fn relative_links_and_anchors_resolve_in_skills_and_docs() {
    let root = repo_root();
    let mut files: Vec<PathBuf> = Vec::new();
    files_under(&root.join("skills"), &mut files);
    files_under(&root.join("docs"), &mut files);
    files.retain(|path| path.extension().is_some_and(|e| e == "md"));
    let texts: BTreeMap<PathBuf, String> = files
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            (path.canonicalize().unwrap(), text)
        })
        .collect();
    let mut anchors_by_path: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let mut failures = Vec::new();
    for (path, text) in &texts {
        for link in links(text) {
            if link.starts_with("http://") || link.starts_with("https://") {
                continue;
            }
            let (target, anchor) = link.split_once('#').unwrap_or((link, ""));
            let Ok(resolved) = path.parent().unwrap().join(target).canonicalize() else {
                failures.push(format!("{}: broken link {link}", path.display()));
                continue;
            };
            if !anchor.is_empty() && resolved.extension().is_some_and(|e| e == "md") {
                let target_anchors =
                    anchors_by_path
                        .entry(resolved)
                        .or_insert_with_key(|resolved| match texts.get(resolved) {
                            Some(text) => anchors(text),
                            None => anchors(&fs::read_to_string(resolved).unwrap()),
                        });
                if !target_anchors.contains(anchor) {
                    failures.push(format!("{}: missing anchor in {link}", path.display()));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn related_skills_name_existing_workflows_and_docs_link_back() {
    let workflows = workflows();
    let all: BTreeSet<&str> = workflows.iter().map(|w| w.name.as_str()).collect();
    let docs = repo_root().join("docs");
    let mut doc_texts: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut failures = Vec::new();
    for Workflow { name, path, text } in &workflows {
        let related = links(section(text, "## Related Skills"));
        assert!(!related.is_empty(), "{}: no related skills", path.display());
        for link in related {
            let target = link
                .strip_prefix("../")
                .and_then(|rest| rest.strip_suffix("/SKILL.md"))
                .unwrap_or_else(|| panic!("{}: related link {link}", path.display()));
            if !all.contains(target) {
                failures.push(format!(
                    "{}: unknown related skill {target}",
                    path.display()
                ));
            }
        }
        let referenced = links(section(text, "## Reference"));
        assert!(
            !referenced.is_empty(),
            "{}: no reference docs",
            path.display()
        );
        for link in referenced {
            let doc = link
                .strip_prefix("../../docs/")
                .unwrap_or_else(|| panic!("{}: reference link {link}", path.display()));
            let doc_path = docs.join(doc);
            let doc_text = doc_texts.entry(doc_path.clone()).or_insert_with(|| {
                fs::read_to_string(&doc_path)
                    .unwrap_or_else(|e| panic!("{}: {e}", doc_path.display()))
            });
            let back = format!("../skills/{name}/SKILL.md");
            if !links(section(doc_text, "## Skills")).contains(&back.as_str()) {
                failures.push(format!(
                    "{}: does not link back to {name}",
                    doc_path.display()
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn verified_by_failures(name: &str, text: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let ids = example_ids(text);
    if ids.is_empty() {
        failures.push("no examples".to_owned());
    }
    let verified = section(text, "## Verified by");
    let rows: Vec<(&str, &str)> = verified
        .lines()
        .filter(|line| line.starts_with("| ") && !line.starts_with("| Examples"))
        .map(|line| {
            let mut cells = line.trim_matches('|').split('|').map(str::trim);
            (cells.next().unwrap(), cells.next().unwrap())
        })
        .collect();
    if rows.is_empty() {
        failures.push("empty verified-by table".to_owned());
    }
    for (examples, test) in &rows {
        let well_formed = test.split_once("::").is_some_and(|(module, function)| {
            !module.is_empty()
                && !function.is_empty()
                && test
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == ':')
        });
        if !well_formed {
            failures.push(format!("test name {test} is not module::function"));
        }
        for id in examples.split(',').map(str::trim) {
            if !ids.contains(id) {
                failures.push(format!("verified-by names undeclared example {id}"));
            }
        }
    }
    let mentioned: BTreeSet<&str> = rows
        .iter()
        .flat_map(|(examples, _)| examples.split(',').map(str::trim))
        .chain(
            verified
                .lines()
                .filter(|line| !line.starts_with('|'))
                .flat_map(|line| line.split('`').skip(1).step_by(2)),
        )
        .collect();
    for id in &ids {
        if !mentioned.contains(id.as_str()) {
            failures.push(format!("example {id} is not covered or excused"));
        }
        let prefix = id.split('.').next().unwrap();
        if !name.contains(prefix) {
            failures.push(format!(
                "example id {id} should start with a word of the skill name"
            ));
        }
    }
    failures
}

#[test]
fn verified_by_tables_map_declared_examples_to_e2e_tests() {
    for Workflow { name, path, text } in workflows() {
        let failures = verified_by_failures(&name, &text);
        assert!(
            failures.is_empty(),
            "{}: {}",
            path.display(),
            failures.join("; ")
        );
    }
}

#[test]
fn verified_by_mutations_are_reported() {
    let text = r#"<!-- example: policies.create -->
<!-- example: policies.orphan -->
<!-- example: policies.crea -->
<!-- example: other.thing -->
## Verified by

| Examples | Test |
|---|---|
| policies.create, policies.missing | policies::crud |
| policies.create | not_a_path |

## Troubleshooting
"#;
    assert_eq!(
        verified_by_failures("managing-policies", text),
        [
            "verified-by names undeclared example policies.missing",
            "test name not_a_path is not module::function",
            "example other.thing is not covered or excused",
            "example id other.thing should start with a word of the skill name",
            "example policies.crea is not covered or excused",
            "example policies.orphan is not covered or excused",
        ]
    );
}

#[test]
fn every_package_file_is_reachable_from_the_index_or_a_workflow() {
    let root = skills_root();
    let index = root.join("SKILL.md");
    let mut sources: Vec<(PathBuf, String)> =
        vec![(index.clone(), fs::read_to_string(&index).unwrap())];
    sources.extend(workflows().into_iter().map(|w| (w.path, w.text)));
    sources.extend(references());
    let mut linked: BTreeSet<PathBuf> = BTreeSet::new();
    for (source, text) in &sources {
        for link in links(text) {
            let target = link.split('#').next().unwrap();
            if target.is_empty() || target.starts_with("http") {
                continue;
            }
            if let Ok(resolved) = source.parent().unwrap().join(target).canonicalize() {
                linked.insert(resolved);
            }
        }
    }
    let mut files = Vec::new();
    files_under(&root, &mut files);
    let index = index.canonicalize().unwrap();
    let unreachable: Vec<PathBuf> = files
        .into_iter()
        .map(|path| path.canonicalize().unwrap())
        .filter(|file| *file != index && !linked.contains(file))
        .collect();
    assert!(unreachable.is_empty(), "unreachable: {unreachable:?}");
}
